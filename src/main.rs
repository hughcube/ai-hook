// GUI subsystem (no console): hosts that spawn the hook without an inherited
// console skip the conhost/console-allocation cost entirely (~9 ms per process
// measured on Windows). Decision output goes to stdout/stderr pipes that the
// host redirects; interactive use still works because shells hand their
// handles over and `attach_parent_console()` below backfills real handles when
// only the parent console is missing.
#![cfg_attr(windows, windows_subsystem = "windows")]

use ai_hook::cli::{Cli, Commands, localized_command};
use ai_hook::engine::debug::{
    DebugCollector, InteractionTrace, RuleTrace, decision_to_value, is_debug_enabled,
};
use ai_hook::engine::{ErrorPolicy, RuleLoader, RuleRunner};
use ai_hook::fast_path::check_fast_path;
use ai_hook::i18n::{Msg, t};
use ai_hook::protocol::input::env_flag_true;
use ai_hook::protocol::{ConfirmPath, HookContext, HookDecision, confirm_path};
use ai_hook::ui::GuiDialog;
use ai_hook::{errln, outln};
use clap::FromArgMatches;
use serde_json::json;
use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Instant;

/// On Windows, a GUI-subsystem process has no console and, unless the caller
/// redirected them, no standard handles. When stdout/stderr are missing,
/// attach to the parent's console (interactive shells) so ordinary CLI use
/// (`list`, `test`, `install`, help) stays visible. Must run before the first
/// `println!`/`eprintln!` because Rust caches the std handles on first use.
#[cfg(windows)]
fn attach_parent_console() {
    use std::os::windows::io::RawHandle;

    const STD_INPUT_HANDLE: u32 = -10i32 as u32;
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    const INVALID_HANDLE_VALUE: RawHandle = -1isize as RawHandle;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_READ: u32 = 0x1;
    const OPEN_EXISTING: u32 = 0x3;

    unsafe extern "system" {
        fn GetStdHandle(n: u32) -> RawHandle;
        fn AttachConsole(dw_process_id: u32) -> i32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            security: *mut core::ffi::c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            template: RawHandle,
        ) -> RawHandle;
        fn SetStdHandle(n: u32, h: RawHandle) -> i32;
    }

    unsafe {
        // A handle is "missing" when GetStdHandle reports NULL (the process
        // was created without a standard handle) or INVALID_HANDLE_VALUE.
        // Shells like Git Bash spawn GUI-subsystem children with NULL std
        // handles, so only checking for INVALID would skip the attach below
        // and silently swallow all console output / mis-detect a terminal.
        let missing = |h: RawHandle| h.is_null() || h == INVALID_HANDLE_VALUE;
        let need_input = missing(GetStdHandle(STD_INPUT_HANDLE));
        let need_output = missing(GetStdHandle(STD_OUTPUT_HANDLE));
        let need_error = missing(GetStdHandle(STD_ERROR_HANDLE));
        if !need_input && !need_output && !need_error {
            return;
        }
        // Only attach when there is a real interactive parent to talk to.
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        // AttachConsole does not rewrite the standard-handle table; fetch the
        // console devices explicitly and backfill the handles Rust will read.
        // Only overridden handles are touched, so a redirected pipe (the hook
        // decision channel) is never replaced.
        if need_output || need_error {
            let mut con = [0u16; 8];
            for (i, c) in "CONOUT$\0".encode_utf16().enumerate() {
                con[i] = c;
            }
            let hout = CreateFileW(
                con.as_ptr(),
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                INVALID_HANDLE_VALUE,
            );
            if hout != INVALID_HANDLE_VALUE {
                if need_output {
                    SetStdHandle(STD_OUTPUT_HANDLE, hout);
                }
                if need_error {
                    SetStdHandle(STD_ERROR_HANDLE, hout);
                }
            }
        }
        if need_input {
            let mut conin = [0u16; 7];
            for (i, c) in "CONIN$\0".encode_utf16().enumerate() {
                conin[i] = c;
            }
            let hin = CreateFileW(
                conin.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                INVALID_HANDLE_VALUE,
            );
            if hin != INVALID_HANDLE_VALUE {
                SetStdHandle(STD_INPUT_HANDLE, hin);
            }
        }
    }
}

/// Timestamped stderr log line: `[YYYY-MM-DD HH:MM:SS] message…`.
/// All diagnostics carry a human-readable local time.
macro_rules! eprint_ts {
    ($($arg:tt)*) => {
        errln!("[{}] {}", ai_hook::engine::local_now_str(), format_args!($($arg)*))
    };
}

// --- Startup profiler (AI_HOOK_PROFILE=1): stage timings to stderr. ---
thread_local! {
    static PROF_T0: std::cell::Cell<Option<Instant>> = const { std::cell::Cell::new(None) };
    static PROF_MARKS: std::cell::RefCell<Vec<(String, f64)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn profile_enabled() -> bool {
    std::env::var("AI_HOOK_PROFILE")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "on"
        })
        .unwrap_or(false)
}

/// Wall-clock instant at which the OS created this process.
///
/// `Instant::now()` inside `main` cannot see anything that happened before
/// `main`: PE image mapping, DLL loading, relocations, C/Rust runtime init.
/// On Windows that invisible prefix dominates hook latency, so the profiler
/// anchors its origin at process creation instead. `GetProcessTimes` reports
/// the creation FILETIME the kernel recorded at CreateProcess time; the only
/// conversion needed is the offset to `Instant`'s monotonic clock, obtained
/// by sampling both clocks back to back.
#[cfg(windows)]
fn process_creation_instant() -> Option<Instant> {
    #[repr(C)]
    struct FileTime {
        lo: u32,
        hi: u32,
    }
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn GetProcessTimes(
            h: *mut core::ffi::c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn GetSystemTimeAsFileTime(t: *mut FileTime);
    }
    unsafe {
        let mut creation = FileTime { lo: 0, hi: 0 };
        let mut exit = FileTime { lo: 0, hi: 0 };
        let mut kernel = FileTime { lo: 0, hi: 0 };
        let mut user = FileTime { lo: 0, hi: 0 };
        if GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        ) == 0
        {
            return None;
        }
        // Sample both clocks as close together as possible.
        let mut now_ft = FileTime { lo: 0, hi: 0 };
        GetSystemTimeAsFileTime(&mut now_ft);
        let now = Instant::now();

        let ticks = |f: &FileTime| ((f.hi as u64) << 32) | f.lo as u64;
        let age_ticks = ticks(&now_ft).saturating_sub(ticks(&creation));
        Some(now - std::time::Duration::from_nanos(age_ticks.saturating_mul(100)))
    }
}

#[cfg(not(windows))]
fn process_creation_instant() -> Option<Instant> {
    None
}

/// Profiler origin: process creation when the platform can report it,
/// `main` entry otherwise (Unix has no cheap equivalent).
fn prof_origin() -> Instant {
    process_creation_instant().unwrap_or_else(Instant::now)
}

macro_rules! prof_init {
    () => {
        if profile_enabled() {
            PROF_T0.with(|c| c.set(Some(prof_origin())));
        }
    };
}

macro_rules! prof_mark {
    ($label:expr) => {
        if profile_enabled() {
            PROF_T0.with(|c| {
                if let Some(t0) = c.get() {
                    PROF_MARKS.with(|m| {
                        m.borrow_mut()
                            .push(($label.to_string(), t0.elapsed().as_secs_f64() * 1000.0))
                    });
                }
            });
        }
    };
}

macro_rules! prof_flush {
    () => {
        if profile_enabled() {
            PROF_MARKS.with(|m| {
                let marks = std::mem::take(&mut *m.borrow_mut());
                if marks.is_empty() {
                    return;
                }
                errln!("[ai-hook-profile] 进程全生命周期(原点=进程创建,含 main 之前的加载开销)");
                let mut prev = 0.0f64;
                for (label, t) in &marks {
                    errln!(
                        "  {:<38} 累计 {:7.3} ms   本段 {:7.3} ms",
                        label,
                        t,
                        (t - prev).max(0.0)
                    );
                    prev = *t;
                }
            });
        }
    };
}

fn get_binary_info_help() -> String {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("ai-hook"));
    let exe_dir = current_exe
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());

    format!(
        "{}\n  {}: {}\n  {}: {}",
        t(Msg::M051),
        t(Msg::M052),
        current_exe.display(),
        t(Msg::M053),
        exe_dir
    )
}

/// Subcommand names defined by the derive macro. When the first positional
/// argument is one of these, argument handling belongs to clap.
const SUBCOMMANDS: [&str; 9] = [
    "list", "test", "bench", "install", "update", "tutorial", "guide", "clean", "prune",
];

/// Hand-rolled parse of the argument shapes a hook configuration produces.
///
/// Constructing clap's `Command` — every subcommand plus every localized help
/// string — measures ~0.2 ms, i.e. as much as a whole rule evaluation. Hosts
/// only ever pass global flags and rule paths, so those are parsed here in
/// nanoseconds. Anything not recognized returns `None` and the caller falls
/// back to clap, which keeps the derive definitions authoritative; there is
/// no second, divergent grammar to keep in sync.
///
/// Mirrors clap's `trailing_var_arg` on `scripts`: the first positional and
/// everything after it is a script path, even when it looks like a flag.
fn parse_simple_args(args: &[OsString]) -> Option<Cli> {
    let mut cli = Cli::default();
    let mut i = 0usize;

    while i < args.len() {
        // Non-UTF-8 is legal on Unix; let clap report it properly.
        let arg = args[i].to_str()?;

        // 1. Explicit end of options: everything after is a script path.
        if arg == "--" {
            cli.scripts.extend(args[i + 1..].iter().map(PathBuf::from));
            return Some(cli);
        }

        // 2. Long flag: --name or --name=value
        if let Some(long) = arg.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            // Inline values on boolean flags are not valid clap syntax;
            // letting them reach clap keeps the error message consistent.
            match name {
                "no-gui" if inline.is_none() => cli.no_gui = true,
                "force-gui" | "force-popup" if inline.is_none() => cli.force_gui = true,
                "dry-run" if inline.is_none() => cli.dry_run = true,
                "allow-on-error" if inline.is_none() => cli.allow_on_error = true,
                "no-fast-path" if inline.is_none() => cli.no_fast_path = true,
                "debug" if inline.is_none() => cli.debug = true,
                "rule" => {
                    let value = match inline {
                        Some(v) => v.to_string(),
                        None => args.get(i + 1)?.to_str()?.to_string(),
                    };
                    cli.rule.push(PathBuf::from(value));
                    if inline.is_none() {
                        i += 1;
                    }
                }
                "timeout" => {
                    let value = match inline {
                        Some(v) => v,
                        None => args.get(i + 1)?.to_str()?,
                    };
                    cli.timeout = Some(value.parse::<u32>().ok()?);
                    if inline.is_none() {
                        i += 1;
                    }
                }
                _ => return None,
            }
            i += 1;
            continue;
        }

        // 3. Short flag. Only `-r` takes a value and every other global flag
        //    is long-only, so no clustering needs to be supported.
        if arg.len() > 1 && arg.starts_with('-') {
            let (name, inline) = match arg[1..].split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (&arg[1..], None),
            };
            if name != "r" {
                return None;
            }
            let value = match inline {
                Some(v) => v.to_string(),
                None => args.get(i + 1)?.to_str()?.to_string(),
            };
            cli.rule.push(PathBuf::from(value));
            i += if inline.is_none() { 2 } else { 1 };
            continue;
        }

        // 4. First positional. A subcommand belongs to clap; anything else is
        //    a script path, and so is everything after it (trailing var-arg).
        if SUBCOMMANDS.contains(&arg) {
            return None;
        }
        cli.scripts.extend(args[i..].iter().map(PathBuf::from));
        return Some(cli);
    }

    Some(cli)
}

fn parse_args() -> Cli {
    let mut raw_args = std::env::args_os();
    let bin = raw_args.next();
    let first = raw_args.next();

    match first {
        None => {
            // 没有任何参数 (最常见的 Agent Hook 调用场景)，零 Clap 构建，零帮助文本堆分配
            Cli::default()
        }
        Some(first_arg) => {
            let mut rest: Vec<OsString> = vec![first_arg];
            rest.extend(raw_args);

            // 检查是否需要帮助或版本信息
            let wants_help_or_version = rest.iter().any(|a| {
                let s = a.to_string_lossy();
                s == "-h" || s == "--help" || s == "-V" || s == "--version"
            });

            if wants_help_or_version {
                let help_info = get_binary_info_help();
                let cmd = localized_command()
                    .after_help(help_info.clone())
                    .after_long_help(help_info);
                let all: Vec<OsString> = std::iter::once(bin.unwrap_or_default())
                    .chain(rest.iter().cloned())
                    .collect();
                let matches = cmd.get_matches_from(&all);
                return Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
            }

            // 快速路径：宿主实际会产生的参数形态，不构造 clap
            if let Some(cli) = parse_simple_args(&rest) {
                return cli;
            }

            // 回退 clap：子命令、未知 flag、解析错误
            let all_args: Vec<OsString> = std::iter::once(bin.unwrap_or_default())
                .chain(rest)
                .collect();
            use clap::Parser;
            match Cli::try_parse_from(&all_args) {
                Ok(parsed) => parsed,
                Err(e) => {
                    let help_info = get_binary_info_help();
                    let cmd = localized_command()
                        .after_help(help_info.clone())
                        .after_long_help(help_info);
                    let _ = cmd.get_matches_from(&all_args);
                    e.exit();
                }
            }
        }
    }
}

fn main() {
    // Must precede every stdout/stderr write: Rust caches the standard handles
    // on first use, so attach to a parent console (interactive shells) before
    // any output happens when the GUI-subsystem binary lacks handles.
    #[cfg(windows)]
    attach_parent_console();
    prof_init!();
    // First mark = the invisible prefix: PE mapping, DLL loading, relocations,
    // C + Rust runtime init. On Windows this is most of the hook's latency.
    prof_mark!("① main 入口前(加载器/DLL/Rust 初始化)");
    let args = parse_args();
    prof_mark!("② 参数解析完成");

    match args.command {
        Some(Commands::List { ref scripts }) => handle_list(&args, scripts),
        Some(Commands::Test {
            ref command,
            ref tool,
            ref file,
            ref platform,
            ref scripts,
        }) => handle_test(&args, command, tool, file, platform, scripts),
        Some(Commands::Bench {
            iterations,
            ref command,
            ref platform,
            ref scripts,
        }) => handle_bench(&args, iterations, command, platform, scripts),
        Some(Commands::Install { ref target_dir }) => handle_install(target_dir.clone()),
        Some(Commands::Update { force, ref repo }) => {
            if let Err(e) = ai_hook::update::handle_update(force, repo) {
                eprint_ts!("[ai-hook update] {}: {}", t(Msg::M054), e);
                std::process::exit(1);
            }
        }
        Some(Commands::Tutorial { ref lang }) => {
            // Explicit --lang wins; otherwise follow the system language.
            let resolved = match lang.as_deref() {
                Some(l) => l.to_string(),
                None => {
                    if ai_hook::i18n::lang().is_zh() {
                        "zh".to_string()
                    } else {
                        "en".to_string()
                    }
                }
            };
            ai_hook::tutorial::print_tutorial(&resolved);
        }
        Some(Commands::Clean { max_files, dry_run }) => handle_clean(max_files, dry_run),
        None => handle_dispatch(&args),
    }
}

/// Gathers explicit script paths passed via positional arguments or --rule flags.
fn collect_target_rules(args: &Cli, extra_scripts: Option<&[PathBuf]>) -> Vec<PathBuf> {
    let mut targets = args.scripts.clone();
    if let Some(extra) = extra_scripts {
        targets.extend(extra.iter().cloned());
    }
    targets.extend(args.rule.iter().cloned());
    targets
}

/// Prints hook output only when non-empty (empty output = allow / no decision
/// in every host protocol, so we must never print whitespace-only noise).
fn print_output(output: &str) {
    if !output.is_empty() {
        outln!("{}", output);
    }
    use std::io::Write;
    let flush = std::io::stdout().flush();
    // Final mark is taken after flushing the decision, so it reflects the
    // whole lifecycle; everything after it is `exit()` teardown.
    prof_mark!("⑦ 输出已写出");
    prof_flush!();
    let _ = std::io::stderr().flush();
    if flush.is_err() && !output.is_empty() {
        // The decision could not be delivered: the host will read empty
        // stdout and treat it as "allow". Exit 2 so blocking hosts (Claude
        // Code / Codex) still stop the action — the one outcome code no JSON
        // can override. Non-blocking hosts lose nothing: they were going to
        // read nothing anyway.
        errln!(
            "[ai-hook] decision output could not be flushed to stdout (host pipe closed?); exiting 2 so blocking hosts still deny"
        );
        std::process::exit(2);
    }
    std::process::exit(0);
}

/// Fail-closed policy can be relaxed explicitly via CLI flag or environment.
fn allow_on_error_requested(args: &Cli) -> bool {
    args.allow_on_error || env_flag_true("AI_HOOK_ALLOW_ON_ERROR")
}

/// The fast-path bypass can be disabled via CLI flag or environment so that
/// whitelisted read-only commands still reach the rule engine. Off values
/// follow the same convention as AI_HOOK_GUI / AI_HOOK_LOG.
fn fast_path_disabled(args: &Cli) -> bool {
    if args.no_fast_path {
        return true;
    }
    std::env::var("AI_HOOK_FAST_PATH")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "0" || v == "false" || v == "no" || v == "off"
        })
        .unwrap_or(false)
}

/// True when the operator configured rule paths (CLI or env), used to decide
/// whether a fast-path bypass is worth warning about.
fn rules_configured(explicit_paths: &[PathBuf]) -> bool {
    !explicit_paths.is_empty() || std::env::var("AI_HOOK_RULES").is_ok()
}

/// Main entry point for agent hook dispatching via stdin
fn handle_dispatch(args: &Cli) {
    if std::io::stdin().is_terminal() {
        // Invoked directly from terminal without piped input -> print help and exit
        let help_info = get_binary_info_help();
        let _ = localized_command()
            .after_help(help_info.clone())
            .after_long_help(help_info)
            .print_help();
        outln!();
        return;
    }

    let is_debug = is_debug_enabled(args.debug);
    let mut debug_collector = if is_debug {
        Some(DebugCollector::new())
    } else {
        None
    };

    let mut buffer = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buffer) {
        // Unreadable stdin (broken pipe / invalid UTF-8) yields no reliable
        // payload. Empty output means "allow" to every host protocol, so an
        // unreadable payload must deny rather than return silently.
        eprint_ts!("[ai-hook] {}: {}", t(Msg::M055), e);
        let ctx = HookContext::parse("");
        let reason = t(Msg::M135).to_string();
        let dec = HookDecision::Deny { reason };
        let out = dec.to_json_output(&ctx, None);
        if let Some(mut col) = debug_collector {
            col.parse_failed = true;
            col.record("generic", Some(&ctx), &dec, &out, 0);
        }
        print_output(&out);
        return;
    }

    // Strip a leading UTF-8 BOM if present. Several hosts / redirection
    // wrappers (notably PowerShell 5.1's Process.StandardInput and some file
    // save dialogs) prepend U+FEFF to the piped bytes; serde_json rejects it,
    // which would route a perfectly valid payload into the "unparseable" ask
    // path and pop a confirmation dialog on every hook call.
    if buffer.starts_with('\u{feff}') {
        buffer.drain(..'\u{feff}'.len_utf8());
    }

    if let Some(ref mut col) = debug_collector {
        col.t_read_done = Some(Instant::now());
        col.raw_input = buffer.clone();
    }

    if buffer.trim().is_empty() {
        // Same reasoning: an empty hook payload is not a verified allow.
        let ctx = HookContext::parse("");
        let reason = t(Msg::M136).to_string();
        let dec = HookDecision::Deny { reason };
        let out = dec.to_json_output(&ctx, None);
        if let Some(col) = debug_collector {
            col.record("generic", Some(&ctx), &dec, &out, 0);
        }
        print_output(&out);
        return;
    }

    prof_mark!("③ stdin 读取完成");
    // Debug aid (AI_HOOK_LOG_EXTERNAL=1): persist the raw payload BEFORE
    // parsing so shape / platform-detection problems stay diagnosable even
    // when parse itself fails. Never fails the hook.
    ai_hook::engine::log_inbound_payload(&buffer);

    let ctx = HookContext::parse(&buffer);
    prof_mark!("④ payload 解析完成");

    if let Some(ref mut col) = debug_collector {
        col.t_parse_done = Some(Instant::now());
        col.parse_failed = ctx.parse_failed;
    }

    // A payload that is not valid JSON carries no tool semantics at all.
    // Failing silently (empty output would read as "allow") or running rules
    // against an empty view would almost always end in an accidental Allow,
    // so ask the operator instead: a GUI dialog when one is available, a
    // terminal "ask" otherwise.
    if ctx.parse_failed {
        let reason = t(Msg::M148).to_string();
        let gui_enabled = GuiDialog::is_enabled(args.no_gui) && !args.dry_run;
        if gui_enabled {
            let prompt_agent = ctx.platform.to_string();
            let t_dlg = Instant::now();
            let approved = GuiDialog::confirm(
                t(Msg::M058),
                &reason,
                "",
                &prompt_agent,
                GuiDialog::resolve_timeout(args.timeout),
            );
            let dlg_dur = t_dlg.elapsed().as_secs_f64() * 1000.0;
            let (dec, out) = if approved {
                let d = HookDecision::Allow;
                let o = d.to_json_output(&ctx, None);
                (d, o)
            } else {
                let d = HookDecision::Deny { reason };
                let o = d.to_json_output(&ctx, None);
                (d, o)
            };
            if let Some(mut col) = debug_collector {
                col.interaction = Some(InteractionTrace {
                    confirm_path: "Popup".to_string(),
                    gui_approved: Some(approved),
                    dialog_duration_ms: Some(dlg_dur),
                });
                col.record(&prompt_agent, Some(&ctx), &dec, &out, 0);
            }
            print_output(&out);
        } else {
            // No dialog: hand the decision to the renderer as a Confirm.
            // An unparseable payload has no host identity at all
            // (`Platform::Generic` + `HookEvent::Other`), which the capability
            // matrix scores as NONE, so this degrades to `Op::Deny` rather
            // than emitting a protocol `ask`. That is the intended direction:
            // an unreadable payload is not a verified allow. Ask-capable hosts
            // would only see an `ask` here if the payload named a platform the
            // matrix actually grants `ask` to — it cannot, by construction.
            let dec = HookDecision::Confirm {
                reason,
                title: None,
                gui: None,
                timeout: None,
                force_gui: None,
            };
            let out = dec.to_json_output(&ctx, None);
            if let Some(mut col) = debug_collector {
                col.interaction = Some(InteractionTrace {
                    confirm_path: "Ask".to_string(),
                    gui_approved: None,
                    dialog_duration_ms: None,
                });
                col.record(&ctx.platform.to_string(), Some(&ctx), &dec, &out, 0);
            }
            print_output(&out);
        }
        return;
    }

    // 2. Collect explicit rule paths first: the fast path needs to know
    //    whether any rules were configured at all (cheap, no file I/O).
    let explicit_paths = collect_target_rules(args, None);

    // 1. Fast path check (< 0.01ms)
    if !fast_path_disabled(args)
        && let Some(decision) = check_fast_path(&ctx)
    {
        // Rules exist but were skipped: say so, otherwise the bypass is
        // invisible and rules appear to "not work" for these commands.
        if rules_configured(&explicit_paths) {
            eprint_ts!("[ai-hook] {}", t(Msg::M138));
        }
        let out = decision.to_json_output(&ctx, None);
        if let Some(mut col) = debug_collector {
            col.fast_path_hit = true;
            col.fast_path_prefix = ctx
                .cmd
                .as_deref()
                .and_then(|c| c.split_whitespace().next().map(str::to_string));
            col.record(&ctx.platform.to_string(), Some(&ctx), &decision, &out, 0);
        }
        print_output(&out);
        return;
    }

    // 3. Load explicit rules (no full-disk auto traversal)
    let rules = RuleLoader::load_rules(&explicit_paths);
    prof_mark!("⑤ 规则文件加载");

    if rules.is_empty() {
        // No gate at all. If rules were configured (explicit CLI paths or
        // AI_HOOK_RULES) but nothing loaded (typo, wrong extension, filtered
        // directory rules), this is a silent full bypass - warn loudly so the
        // operator hears it even when the host only surfaces stderr in its
        // debug log.
        if rules_configured(&explicit_paths) {
            eprint_ts!("[ai-hook] {}", t(Msg::M160));
        }
        let dec = HookDecision::Allow;
        let out = dec.to_json_output(&ctx, None);
        if let Some(col) = debug_collector {
            col.record(&ctx.platform.to_string(), Some(&ctx), &dec, &out, 0);
        }
        print_output(&out);
        return;
    }

    let agent_str = ctx.platform.to_string();
    let debug_col_cell = std::rc::Rc::new(std::cell::RefCell::new(debug_collector));
    let debug_col_panic = debug_col_cell.clone();
    let ctx_panic = ctx.clone();

    // 3. Evaluate rules + optional GUI inside catch_unwind: an internal panic
    //    (e.g. embedded JS runtime fault) must still yield a deny decision —
    //    empty output is interpreted as "allow" by every host protocol.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let policy = ErrorPolicy::from_flag(allow_on_error_requested(args));
        let runner = match RuleRunner::new() {
            Ok(r) => r,
            Err(e) => {
                // Gate is broken: rules cannot run, so do NOT silently allow.
                eprint_ts!("[ai-hook] {}: {}", t(Msg::M056), e);
                let reason = t(Msg::M057).to_string();
                let dec = HookDecision::Deny { reason };
                let out = dec.to_json_output(&ctx, None);
                if let Some(col) = debug_col_cell.borrow_mut().take() {
                    col.record(&agent_str, Some(&ctx), &dec, &out, 0);
                }
                print_output(&out);
                return;
            }
        };

        let (decision, results) = runner.evaluate_all(&rules, &ctx, policy);
        prof_mark!("⑥ 规则执行完成");

        if let Some(ref mut col) = *debug_col_cell.borrow_mut() {
            col.t_rules_done = Some(Instant::now());
            for r in &results {
                col.rules_evaluated.push(RuleTrace {
                    id: r.rule_id.clone(),
                    path: r.rule_path.to_string_lossy().to_string(),
                    duration_ms: r.duration.as_secs_f64() * 1000.0,
                    decision: r.decision.as_ref().map(decision_to_value),
                    error: r.error.clone(),
                });
            }
            col.hit_rule = results
                .iter()
                .find(|r| r.decision.is_some() || r.error.is_some())
                .map(|r| r.rule_id.clone());
        }

        // 4. Handle confirmation & GUI prompt (gui 三态语义):
        //    gui:true / force_gui → 强制弹窗(穿透 --no-gui,仅 dry-run 演练除外);
        //    缺省(不配置)→ 宿主能 ask 走协议 ask;不能 ask 时 GUI 兜底(不可用则自动拒绝);
        //    gui:false → 能 ask 走 ask;不能 ask 自动拒绝(规则禁弹窗 → fail-closed)。
        let mut gui_approved = None;
        let mut auto_deny = false;
        if let HookDecision::Confirm {
            reason,
            title,
            gui,
            timeout: rule_timeout,
            force_gui: rule_force_gui,
        } = &decision
        {
            let gui_enabled = GuiDialog::is_enabled(args.no_gui);
            // Rule-provided timeout of 0 is treated as "use the default".
            let timeout = rule_timeout
                .filter(|t| *t > 0)
                .unwrap_or_else(|| GuiDialog::resolve_timeout(args.timeout));
            let forced = args.force_gui
                || env_flag_true("AI_HOOK_FORCE_GUI")
                || rule_force_gui.unwrap_or(false);

            // The protocol-ask channel needs BOTH gates: the platform still
            // prompts in this mode (`can_ask`) AND the (platform, event) pair
            // has an ask slot (`caps.ask`). Using only `can_ask` here used to
            // pick `ConfirmPath::Ask` on events whose capability row has no
            // ask (UserPromptSubmit / PermissionRequest / PreCompact), so the
            // dialog fallback never ran and the confirm degraded to a hard
            // deny with no way to authorize. The renderer applies the same
            // conjunction, so both layers now agree.
            let ask_ok = ctx.can_ask() && ctx.capabilities().ask;
            let c_path = confirm_path(*gui, forced, ask_ok, gui_enabled, args.dry_run);

            let mut dialog_dur = None;
            match c_path {
                ConfirmPath::Popup => {
                    let prompt_target = ctx
                        .cmd
                        .as_deref()
                        .filter(|c| !c.is_empty())
                        .or_else(|| ctx.file.as_ref().and_then(|f| f.path.as_deref()))
                        .unwrap_or("");
                    let prompt_title = title.as_deref().unwrap_or_else(|| t(Msg::M058));
                    let prompt_agent = ctx.platform.to_string();
                    let t_gui = Instant::now();
                    let approved = GuiDialog::confirm(
                        prompt_title,
                        reason,
                        prompt_target,
                        &prompt_agent,
                        timeout,
                    );
                    dialog_dur = Some(t_gui.elapsed().as_secs_f64() * 1000.0);
                    gui_approved = Some(approved);
                }
                ConfirmPath::Ask => {
                    // 不弹窗:gui_approved 保持 None → 输出层按宿主协议输出
                    // ask(CC/CB)、force_ask(AGY 交互)。Codex 不支持 ask（由能力矩阵和 auto_deny 兜底）
                }
                ConfirmPath::AutoDeny => auto_deny = true,
            }

            if let Some(ref mut col) = *debug_col_cell.borrow_mut() {
                col.interaction = Some(InteractionTrace {
                    confirm_path: match c_path {
                        ConfirmPath::Popup => "Popup".to_string(),
                        ConfirmPath::Ask => "Ask".to_string(),
                        ConfirmPath::AutoDeny => "AutoDeny".to_string(),
                    },
                    gui_approved,
                    dialog_duration_ms: dialog_dur,
                });
            }
        }

        // Auto-deny: turn the confirm into a hard deny with an explanation —
        // the host cannot ask and no dialog was shown, so an "ask" decision
        // would be silently ignored or unsupported by the host protocol.
        let decision = if auto_deny {
            match &decision {
                HookDecision::Confirm { reason, .. } => HookDecision::Deny {
                    reason: format!("{}\n({})", reason, t(Msg::M149)),
                },
                _ => HookDecision::Deny {
                    reason: t(Msg::M149).to_string(),
                },
            }
        } else {
            decision
        };

        let out = decision.to_json_output(&ctx, gui_approved);
        if let Some(col) = debug_col_cell.borrow_mut().take() {
            col.record(&agent_str, Some(&ctx), &decision, &out, 0);
        }
        print_output(&out);
    }));

    if outcome.is_err() {
        eprint_ts!("[ai-hook] {}", t(Msg::M059));
        let reason = t(Msg::M060).to_string();
        let dec = HookDecision::Deny { reason };
        let out = dec.to_json_output(&ctx_panic, None);
        if let Some(col) = debug_col_panic.borrow_mut().take() {
            col.record(&agent_str, Some(&ctx_panic), &dec, &out, 0);
        }
        print_output(&out);
    }
}

fn handle_list(args: &Cli, scripts: &[PathBuf]) {
    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    outln!("============================================================");
    outln!("  {} ({}: {})", t(Msg::M061), t(Msg::M062), rules.len());
    outln!("============================================================");

    if rules.is_empty() {
        outln!("  {}", t(Msg::M063));
        outln!(
            "  {}: ai-hook [选项] <script1.js> <script2.js>...",
            t(Msg::M064)
        );
        outln!(
            "  {}: ./.ai-hook/rules.js 或 ./.ai-hook/rules/",
            t(Msg::M065)
        );
        return;
    }

    for (idx, r) in rules.iter().enumerate() {
        outln!("  [{:02}] {:<30} -> {}", idx + 1, r.id, r.path.display());
    }
}

/// Hosts whose envelope `test` / `bench` knows how to synthesize.
const TEST_PLATFORMS: &[&str] = &[
    "claude_code",
    "codex",
    "codebuddy",
    "workbuddy",
    "gemini",
    "antigravity",
    "opencode",
];

/// Builds the envelope a host would really deliver for a command tool call.
///
/// `test` / `bench` used to hard-code one Antigravity shape, so the simulated
/// `ctx.platform` was always `antigravity` and no other host's rendering could
/// be inspected — a rule could pass `test` and still emit the wrong JSON in
/// production. The shape is host-specific in ways that matter: only
/// Antigravity nests the tool under `toolCall`, only Gemini spells the event
/// `BeforeTool`, and `transcript_path` is what carries the product name.
fn synthetic_payload(platform: &str, command: &str, tool: &str, file: &str, cwd: &str) -> String {
    match platform {
        "antigravity" => {
            let mut args = serde_json::Map::new();
            args.insert("CommandLine".into(), json!(command));
            args.insert("Cwd".into(), json!(cwd));
            if !file.is_empty() {
                args.insert("TargetFile".into(), json!(file));
            }
            // `name` lives inside toolCall for the Antigravity envelope;
            // omitting it made `ctx.cmd` always null and silently disabled
            // every command rule.
            json!({ "toolCall": { "name": tool, "args": args }, "conversationId": "test-session" })
                .to_string()
        }
        "gemini" => {
            let mut input = serde_json::Map::new();
            input.insert("command".into(), json!(command));
            if !file.is_empty() {
                input.insert("file_path".into(), json!(file));
            }
            json!({
                "hook_event_name": "BeforeTool",
                "tool_name": tool,
                "tool_input": input,
                "session_id": "test-session",
                "transcript_path": format!("{cwd}/.gemini/tmp/test-session.json"),
                "cwd": cwd,
            })
            .to_string()
        }
        // Claude-Code-shaped envelope: Claude Code, Codex, CodeBuddy,
        // WorkBuddy and the OpenCode bridge. `transcript_path` carries the
        // product directory, which is what lets the simulated platform resolve.
        _ => {
            let dir = match platform {
                "codex" => ".codex",
                "codebuddy" => ".codebuddy",
                "workbuddy" => ".workbuddy",
                _ => ".claude",
            };
            let mut input = serde_json::Map::new();
            input.insert("command".into(), json!(command));
            if !file.is_empty() {
                input.insert("file_path".into(), json!(file));
            }
            let mut obj = json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": input,
                "session_id": "test-session",
                "transcript_path": format!("{cwd}/{dir}/projects/test-session.jsonl"),
                "cwd": cwd,
            });
            if platform == "codex" {
                obj["turn_id"] = json!("test-turn");
            }
            obj.to_string()
        }
    }
}

/// Prints the JSON the host would really receive. Empty output means "allow"
/// in every host protocol, so an empty render is named rather than left blank.
fn print_rendered(decision: &HookDecision, ctx: &HookContext) {
    let rendered = decision.to_json_output(ctx, None);
    if rendered.is_empty() {
        outln!("{}: {}", t(Msg::M156), t(Msg::M077));
    } else {
        outln!("{}: {}", t(Msg::M156), rendered);
    }
}

fn handle_test(
    args: &Cli,
    command: &str,
    tool: &str,
    file: &str,
    platform: &str,
    scripts: &[PathBuf],
) {
    outln!("{}...", t(Msg::M066));
    outln!("{}: {}", t(Msg::M067), command);
    outln!("{}: {}", t(Msg::M068), tool);
    if !file.is_empty() {
        outln!("{}: {}", t(Msg::M069), file);
    }
    if !TEST_PLATFORMS.contains(&platform) {
        outln!("⚠️  {}: {}", t(Msg::M155), platform);
    }
    outln!("------------------------------------------------------------");

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // The OpenCode bridge marks its envelopes with OPENCODE_COMPAT=1; without
    // the marker the synthesized payload would be classified as claude_code
    // and `test --platform opencode` could never exercise the OpenCode
    // renderer. The env is process-local and this process exits right after,
    // so nothing leaks.
    if platform == "opencode" {
        unsafe { std::env::set_var("OPENCODE_COMPAT", "1") };
    }

    let raw_payload = synthetic_payload(platform, command, tool, file, &cwd);
    let ctx = HookContext::parse(&raw_payload);
    outln!("{}: {}", t(Msg::M157), ctx.platform);
    outln!("------------------------------------------------------------");

    // Fast path check. Skipped when the bypass is disabled so whitelisted
    // commands can still be traced through the rules with `test`.
    if !fast_path_disabled(args) {
        let start_fast = Instant::now();
        if let Some(decision) = check_fast_path(&ctx) {
            outln!("⚡ {} {:?}", t(Msg::M070), start_fast.elapsed());
            outln!("{}: {:?}", t(Msg::M071), decision);
            print_rendered(&decision, &ctx);
            outln!("ℹ️  {}", t(Msg::M138));
            return;
        }
    }

    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    if rules.is_empty() {
        outln!("⚠️ {}", t(Msg::M072));
        outln!(
            "{}: ai-hook test <command> <script1.js> <script2.js>...",
            t(Msg::M073)
        );
        return;
    }

    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprint_ts!("{}: {}", t(Msg::M074), e);
            return;
        }
    };

    let start_eval = Instant::now();
    let policy = ErrorPolicy::from_flag(allow_on_error_requested(args));
    let (final_decision, results) = runner.evaluate_all(&rules, &ctx, policy);
    let total_elapsed = start_eval.elapsed();

    for res in results {
        let status = match res.decision {
            Some(HookDecision::Confirm { ref reason, .. }) => {
                format!("{} ({})", t(Msg::M075), reason)
            }
            Some(HookDecision::Deny { ref reason }) => {
                format!("{} ({})", t(Msg::M076), reason)
            }
            Some(HookDecision::Modify(ref m)) => {
                if let Some(text) = &m.inject {
                    format!("{} ({})", t(Msg::M151), text)
                } else if m.mutate_input.is_some() {
                    format!("{} (mutateInput)", t(Msg::M153))
                } else if let Some(out) = &m.replace_output {
                    match out {
                        serde_json::Value::String(s) => {
                            format!("{} ({})", t(Msg::M152), s)
                        }
                        other => format!("{} ({})", t(Msg::M152), other),
                    }
                } else {
                    t(Msg::M151).to_string()
                }
            }
            Some(HookDecision::KeepGoing { ref reason }) => {
                format!("KEEP_GOING ({})", reason)
            }
            Some(HookDecision::Allow) => t(Msg::M077).to_string(),
            None => t(Msg::M078).to_string(),
        };

        if let Some(err) = res.error {
            outln!(
                "  [{:<25}] ❌ {}: {} (in {:?})",
                res.rule_id,
                t(Msg::M079),
                err,
                res.duration
            );
            outln!("      {}", res.rule_path.display());
        } else {
            outln!(
                "  [{:<25}] {:<30} (in {:?})",
                res.rule_id,
                status,
                res.duration
            );
        }
    }

    outln!("------------------------------------------------------------");
    outln!("{}: {:?}", t(Msg::M071), final_decision);
    // The Debug form above is the rule's intent; this is what the host parses.
    print_rendered(&final_decision, &ctx);
    outln!("{}: {:?}", t(Msg::M080), total_elapsed);
}

fn handle_bench(args: &Cli, iterations: usize, command: &str, platform: &str, scripts: &[PathBuf]) {
    outln!(
        "{}: {} {} '{}'",
        t(Msg::M081),
        t(Msg::M082),
        iterations,
        t(Msg::M083),
    );

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    if !TEST_PLATFORMS.contains(&platform) {
        outln!("⚠️  {}: {}", t(Msg::M155), platform);
    }

    // Same OpenCode marker as `test` (see handle_test): the synthesized
    // envelope only classifies as opencode when OPENCODE_COMPAT is set.
    if platform == "opencode" {
        unsafe { std::env::set_var("OPENCODE_COMPAT", "1") };
    }

    let raw_payload = synthetic_payload(platform, command, "Bash", "", &cwd);
    let ctx = HookContext::parse(&raw_payload);
    outln!("{}: {}", t(Msg::M157), ctx.platform);
    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    if rules.is_empty() {
        outln!("⚠️ {}", t(Msg::M084));
        return;
    }

    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprint_ts!("{}: {}", t(Msg::M085), e);
            return;
        }
    };

    let policy = ErrorPolicy::from_flag(allow_on_error_requested(args));
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = runner.evaluate_all(&rules, &ctx, policy);
    }
    let elapsed = start.elapsed();

    let avg_us = elapsed.as_micros() as f64 / iterations as f64;
    outln!("============================================================");
    outln!("  {} : {} {}", t(Msg::M086), rules.len(), t(Msg::M087));
    outln!("  {} : {:?}", t(Msg::M088), elapsed);
    outln!("  {} : {}", t(Msg::M089), iterations);
    outln!(
        "  {} : {:.2} µs ({:.4} ms) {}",
        t(Msg::M090),
        avg_us,
        avg_us / 1000.0,
        t(Msg::M091)
    );
    outln!("============================================================");
}

/// Checks whether a directory is writable by attempting a quick probe file
fn is_dir_writable(dir: &std::path::Path) -> bool {
    if !dir.exists() {
        return false;
    }
    let test_file = dir.join(format!(".ai_hook_perm_test_{}", std::process::id()));
    if std::fs::write(&test_file, b"").is_ok() {
        let _ = std::fs::remove_file(&test_file);
        true
    } else {
        false
    }
}

/// Parses $PATH into entries, tolerating the MSYS/Git-Bash shape that is
/// injected into native Windows children: ':'-separated entries with '/c/…'
/// drive-mount prefixes. std::env::split_paths() alone mis-parses that shape
/// on Windows (it splits on ';'), so this parser is what keeps automatic
/// install placement working when the hook is driven from Git Bash.
fn path_entries_from_env() -> Vec<PathBuf> {
    let Some(raw) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    let raw = raw.to_string_lossy();

    #[cfg(windows)]
    if !raw.contains(';') && raw.contains(':') {
        return raw
            .split(':')
            .filter(|p| !p.is_empty())
            .map(|p| {
                // '/c/Users/…' -> 'C:\Users\…'; non-drive entries (e.g. /usr/bin)
                // stay as-is and are skipped later by exists()/writability probes.
                let b = p.as_bytes();
                if p.starts_with('/') && b.len() >= 3 && b[1].is_ascii_alphabetic() && b[2] == b'/'
                {
                    let drive = (b[1] as char).to_ascii_uppercase();
                    PathBuf::from(format!("{}:\\{}", drive, &p[3..]).replace('/', "\\"))
                } else {
                    PathBuf::from(p)
                }
            })
            .collect();
    }

    std::env::split_paths(raw.as_ref()).collect()
}

/// Automatically detects an existing directory already in PATH to avoid adding any new environment variables.
fn resolve_global_install_dir(target_dir: Option<PathBuf>) -> PathBuf {
    if let Some(explicit) = target_dir {
        return explicit;
    }

    let existing_paths = path_entries_from_env();

    // PATH entries keep their declared order; on Windows the %PATH% entries
    // live in the registry and split_paths reproduces that order.
    let is_windows_apps = |p: &std::path::Path| -> bool {
        let s = p.to_string_lossy().replace('\\', "/").to_lowercase();
        s.contains("microsoft") && s.contains("windowsapps")
    };

    // 1. Unix: standard system-wide /usr/local/bin first when writable
    #[cfg(not(windows))]
    {
        let usr_local_bin = PathBuf::from("/usr/local/bin");
        if existing_paths.contains(&usr_local_bin) && is_dir_writable(&usr_local_bin) {
            return usr_local_bin;
        }
    }

    // 2. Walk PATH left-to-right and take the first writable directory (ignoring WindowsApps)
    for path in &existing_paths {
        if path.as_os_str().is_empty() {
            continue;
        }
        if cfg!(windows) && is_windows_apps(path) {
            continue;
        }
        if path.exists() && is_dir_writable(path) {
            return path.clone();
        }
    }

    // 3. Fallback default: ~/.local/bin (Standard cross-platform convention)
    if let Some(home) = ai_hook::paths::home_dir() {
        home.join(".local").join("bin")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

fn handle_install(target_dir: Option<PathBuf>) {
    let current_exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprint_ts!("{}: {}", t(Msg::M092), e);
            return;
        }
    };

    let dest_dir = resolve_global_install_dir(target_dir);

    if !dest_dir.exists() {
        let _ = std::fs::create_dir_all(&dest_dir);
    }

    let exe_name = if cfg!(windows) {
        "ai-hook.exe"
    } else {
        "ai-hook"
    };

    let dest_file = dest_dir.join(exe_name);
    let norm = |p: &std::path::Path| {
        p.canonicalize()
            .unwrap_or_else(|_| p.to_path_buf())
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .to_lowercase()
    };
    let already_there = norm(&current_exe) == norm(&dest_file);

    if !already_there {
        if let Err(e) = std::fs::copy(&current_exe, &dest_file) {
            eprint_ts!("{} {}: {}", t(Msg::M093), dest_file.display(), e);
            #[cfg(windows)]
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprint_ts!("   {}", t(Msg::M094));
            }
            return;
        }
        // Verify the copy actually landed (size matches the source).
        let src_len = std::fs::metadata(&current_exe).map(|m| m.len()).ok();
        let dest_len = std::fs::metadata(&dest_file).map(|m| m.len()).ok();
        if src_len.is_some() && src_len != dest_len {
            eprint_ts!(
                "{} {} ({}).",
                t(Msg::M095),
                dest_file.display(),
                t(Msg::M096)
            );
            let _ = std::fs::remove_file(&dest_file);
            return;
        }
        outln!("{}:", t(Msg::M097));
        outln!("   {}", dest_file.display());
    } else {
        outln!("{}:", t(Msg::M098));
        outln!("   {}", dest_file.display());
    }
    outln!();

    // Check if the destination is already in PATH (no environment variables modified)
    let norm_dest = dest_dir
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_lowercase();
    let in_path = path_entries_from_env().iter().any(|p| {
        p.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_lowercase()
            == norm_dest
    });

    if in_path {
        outln!("✓ {}", t(Msg::M099));
        outln!("  '{}' {}.", dest_dir.display(), t(Msg::M100));
        outln!("  {}", t(Msg::M101));
    } else {
        outln!(
            "ℹ️  {} '{}' {}.",
            t(Msg::M102),
            dest_dir.display(),
            t(Msg::M103)
        );
        outln!("   {}:", t(Msg::M104));
        outln!("     {}", dest_file.display());
    }
}

fn handle_clean(max_files: Option<usize>, dry_run: bool) {
    let limit = max_files.unwrap_or_else(ai_hook::engine::debug::resolve_max_log_files);

    let Some(home) = ai_hook::paths::home_dir() else {
        eprintln!("[ai-hook] Could not determine user home directory.");
        std::process::exit(1);
    };
    let logs_dir = home.join(".ai-hook").join("logs");
    let lang = ai_hook::i18n::lang();

    if !logs_dir.is_dir() {
        match lang {
            ai_hook::i18n::Lang::Zh => {
                outln!("日志目录不存在或为空: {} (无需清理)", logs_dir.display());
            }
            ai_hook::i18n::Lang::En => {
                outln!(
                    "Log directory does not exist or is empty: {} (nothing to clean)",
                    logs_dir.display()
                );
            }
        }
        return;
    }

    let report = ai_hook::engine::debug::clean_all_logs(&logs_dir, limit, dry_run);
    let mb_freed = report.bytes_freed as f64 / (1024.0 * 1024.0);

    if dry_run {
        match lang {
            ai_hook::i18n::Lang::Zh => {
                outln!("[dry-run] 扫描日志目录: {}", logs_dir.display());
                outln!(
                    "共扫描到 {} 个日志文件 (涉及 {} 个分类)",
                    report.total_scanned,
                    report.categories.len()
                );
                outln!(
                    "拟清理超期文件: {} 个 (释放空间约 {:.2} MB)",
                    report.files_deleted,
                    mb_freed
                );
                outln!(
                    "拟保留活跃文件: {} 个 (每类上限保留最后 {} 个)",
                    report.files_retained,
                    limit
                );
                if !report.deleted_files.is_empty() {
                    outln!("\n拟删除的文件列表:");
                    for f in &report.deleted_files {
                        outln!("  - {}", f);
                    }
                }
            }
            ai_hook::i18n::Lang::En => {
                outln!("[dry-run] Scanned log directory: {}", logs_dir.display());
                outln!(
                    "Found {} log files across {} categories",
                    report.total_scanned,
                    report.categories.len()
                );
                outln!(
                    "Would delete: {} old log files (~{:.2} MB freed)",
                    report.files_deleted,
                    mb_freed
                );
                outln!(
                    "Would retain: {} active files (limit: {} per category)",
                    report.files_retained,
                    limit
                );
                if !report.deleted_files.is_empty() {
                    outln!("\nFiles that would be deleted:");
                    for f in &report.deleted_files {
                        outln!("  - {}", f);
                    }
                }
            }
        }
    } else {
        match lang {
            ai_hook::i18n::Lang::Zh => {
                outln!("✅ 日志清理完成: {}", logs_dir.display());
                outln!(
                    "共扫描到 {} 个日志文件 (涉及 {} 个分类)",
                    report.total_scanned,
                    report.categories.len()
                );
                outln!(
                    "已清理超期文件: {} 个 (共释放 {:.2} MB)",
                    report.files_deleted,
                    mb_freed
                );
                outln!(
                    "保留活跃文件: {} 个 (每类上限保留最后 {} 个)",
                    report.files_retained,
                    limit
                );
                if !report.deleted_files.is_empty() {
                    outln!("\n已清理的文件列表:");
                    for f in &report.deleted_files {
                        outln!("  - {}", f);
                    }
                }
            }
            ai_hook::i18n::Lang::En => {
                outln!("✅ Log cleanup complete: {}", logs_dir.display());
                outln!(
                    "Scanned {} log files across {} categories",
                    report.total_scanned,
                    report.categories.len()
                );
                outln!(
                    "Deleted: {} old log files ({:.2} MB freed)",
                    report.files_deleted,
                    mb_freed
                );
                outln!(
                    "Retained: {} active log files (up to {} per category)",
                    report.files_retained,
                    limit
                );
                if !report.deleted_files.is_empty() {
                    outln!("\nDeleted files:");
                    for f in &report.deleted_files {
                        outln!("  - {}", f);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    /// The hand-rolled fast path must agree with clap on every shape it
    /// claims to handle. If the two ever drift, this fails rather than
    /// silently changing how a host's hook command line is interpreted.
    #[test]
    fn fast_arg_parser_matches_clap() {
        let cases: &[&[&str]] = &[
            &[],
            &["rules/a.js"],
            &["rules/a.js", "rules/b.js"],
            &["--no-gui"],
            &["--force-gui"],
            &["--dry-run"],
            &["--allow-on-error"],
            &["--no-fast-path"],
            &["--debug"],
            &["--rule", "rules/a.js"],
            &["--rule=rules/a.js"],
            &["-r", "rules/a.js"],
            &["-r=rules/a.js"],
            &["--timeout", "30"],
            &["--timeout=30"],
            &["--no-gui", "--rule", "rules/a.js", "extra.js"],
            &["--", "weird --name.js"],
            // trailing_var_arg: once a positional is seen, flags are scripts
            &["a.js", "--no-gui"],
        ];

        for case in cases {
            let mut with_bin = vec![OsString::from("ai-hook")];
            with_bin.extend(os(case));
            let expected = Cli::try_parse_from(&with_bin)
                .unwrap_or_else(|e| panic!("clap 拒绝了用例 {case:?}: {e}"));
            let got = parse_simple_args(&os(case))
                .unwrap_or_else(|| panic!("快速路径未覆盖应当覆盖的用例: {case:?}"));
            assert_eq!(
                format!("{got:?}"),
                format!("{expected:?}"),
                "快速路径与 clap 结果不一致: {case:?}"
            );
        }
    }

    /// Anything the fast path does not fully understand must be handed back
    /// to clap, which owns the error messages and the subcommand grammar.
    #[test]
    fn fast_arg_parser_defers_everything_else_to_clap() {
        for sub in SUBCOMMANDS {
            assert!(
                parse_simple_args(&os(&[sub])).is_none(),
                "子命令 {sub} 应交回 clap 处理"
            );
        }
        assert!(parse_simple_args(&os(&["--nope"])).is_none());
        assert!(parse_simple_args(&os(&["--rule"])).is_none());
        assert!(parse_simple_args(&os(&["--timeout", "abc"])).is_none());
        assert!(parse_simple_args(&os(&["--timeout"])).is_none());
        assert!(parse_simple_args(&os(&["-x"])).is_none());
    }
}
