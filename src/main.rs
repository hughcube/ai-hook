// GUI subsystem (no console): hosts that spawn the hook without an inherited
// console skip the conhost/console-allocation cost entirely (~9 ms per process
// measured on Windows). Decision output goes to stdout/stderr pipes that the
// host redirects; interactive use still works because shells hand their
// handles over and `attach_parent_console()` below backfills real handles when
// only the parent console is missing.
#![cfg_attr(windows, windows_subsystem = "windows")]

use ai_hook::cli::{Cli, Commands, localized_command};
use ai_hook::engine::{ErrorPolicy, RuleLoader, RuleRunner};
use ai_hook::fast_path::check_fast_path;
use ai_hook::i18n::{Msg, t, tf};
use ai_hook::protocol::input::env_flag_true;
use ai_hook::protocol::{ConfirmPath, HookContext, HookDecision, confirm_path};
use ai_hook::ui::GuiDialog;
use ai_hook::{errln, outln};
use clap::FromArgMatches;
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

/// Timestamped stderr log line: `[2026-09-05 02:46:12] message…`.
/// All diagnostics carry a human-readable local time (2026-09-05 需求).
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
const SUBCOMMANDS: [&str; 7] = [
    "list", "test", "bench", "install", "update", "tutorial", "guide",
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
            ref scripts,
        }) => handle_test(&args, command, tool, file, scripts),
        Some(Commands::Bench {
            iterations,
            ref command,
            ref scripts,
        }) => handle_bench(&args, iterations, command, scripts),
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
    let _ = std::io::stdout().flush();
    // Final mark is taken after flushing the decision, so it reflects the
    // whole lifecycle; everything after it is `exit()` teardown.
    prof_mark!("⑦ 输出已写出");
    prof_flush!();
    let _ = std::io::stderr().flush();
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

    let mut buffer = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buffer) {
        // Unreadable stdin (broken pipe / invalid UTF-8) yields no reliable
        // payload. Empty output means "allow" to every host protocol, so an
        // unreadable payload must deny rather than return silently.
        eprint_ts!("[ai-hook] {}: {}", t(Msg::M055), e);
        let ctx = HookContext::parse("");
        let reason = t(Msg::M135).to_string();
        print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
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

    if buffer.trim().is_empty() {
        // Same reasoning: an empty hook payload is not a verified allow.
        let ctx = HookContext::parse("");
        let reason = t(Msg::M136).to_string();
        print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
        return;
    }

    prof_mark!("③ stdin 读取完成");
    // Debug aid (AI_HOOK_LOG_EXTERNAL=1): persist the raw payload BEFORE
    // parsing so shape / platform-detection problems stay diagnosable even
    // when parse itself fails. Never fails the hook.
    ai_hook::engine::log_inbound_payload(&buffer);

    let ctx = HookContext::parse(&buffer);
    prof_mark!("④ payload 解析完成");

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
            let approved = GuiDialog::confirm(
                t(Msg::M058),
                &reason,
                "",
                &prompt_agent,
                GuiDialog::resolve_timeout(args.timeout),
            );
            if approved {
                print_output(&HookDecision::Allow.to_json_output(&ctx, None));
            } else {
                print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
            }
        } else {
            // No dialog: emit a terminal "ask" so ask-capable hosts let the
            // user decide. The plain Deny path would silently block a host
            // that may simply use an envelope shape we have not seen yet.
            print_output(
                &HookDecision::Confirm {
                    reason,
                    title: None,
                    gui: None,
                    timeout: None,
                    force_gui: None,
                }
                .to_json_output(&ctx, None),
            );
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
        print_output(&decision.to_json_output(&ctx, None));
        return;
    }

    // 3. Load explicit rules (no full-disk auto traversal)
    let rules = RuleLoader::load_rules(&explicit_paths);
    prof_mark!("⑤ 规则文件加载");

    if rules.is_empty() {
        // No gate at all. If the operator pointed at paths that loaded nothing
        // (typo, wrong extension), this is a silent full bypass - warn loudly.
        if !explicit_paths.is_empty() {
            eprint_ts!("[ai-hook] {}", tf(Msg::M137, &[&explicit_paths.len()]));
        }
        print_output(&HookDecision::Allow.to_json_output(&ctx, None));
        return;
    }

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
                print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
                return;
            }
        };

        let (decision, _) = runner.evaluate_all(&rules, &ctx, policy);
        prof_mark!("⑥ 规则执行完成");

        // 4. Handle confirmation & GUI prompt (gui 三态语义,2026-09-05 约定):
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

            match confirm_path(*gui, forced, ctx.can_ask(), gui_enabled, args.dry_run) {
                ConfirmPath::Popup => {
                    let prompt_target = ctx
                        .cmd
                        .as_deref()
                        .filter(|c| !c.is_empty())
                        .or_else(|| ctx.file.as_ref().and_then(|f| f.path.as_deref()))
                        .unwrap_or("");
                    let prompt_title = title.as_deref().unwrap_or_else(|| t(Msg::M058));
                    let prompt_agent = ctx.platform.to_string();
                    let approved = GuiDialog::confirm(
                        prompt_title,
                        reason,
                        prompt_target,
                        &prompt_agent,
                        timeout,
                    );
                    gui_approved = Some(approved);
                }
                ConfirmPath::Ask => {
                    // 不弹窗:gui_approved 保持 None → 输出层按宿主协议输出
                    // ask(CC/CB)、ask(Codex 0.152+ 普通)、force_ask(AGY 交互)
                }
                ConfirmPath::AutoDeny => auto_deny = true,
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

        print_output(&decision.to_json_output(&ctx, gui_approved));
    }));

    if outcome.is_err() {
        eprint_ts!("[ai-hook] {}", t(Msg::M059));
        let reason = t(Msg::M060).to_string();
        print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
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

fn handle_test(args: &Cli, command: &str, tool: &str, file: &str, scripts: &[PathBuf]) {
    outln!("{}...", t(Msg::M066));
    outln!("{}: {}", t(Msg::M067), command);
    outln!("{}: {}", t(Msg::M068), tool);
    if !file.is_empty() {
        outln!("{}: {}", t(Msg::M069), file);
    }
    outln!("------------------------------------------------------------");

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // `name` lives inside toolCall for the Antigravity envelope; omitting it
    // made `ctx.cmd` always null and silently disabled every command rule.
    let raw_payload = serde_json::json!({
        "toolCall": {
            "name": tool,
            "args": {
                "CommandLine": command,
                "TargetFile": file,
                "Cwd": cwd,
            }
        },
        "conversationId": "test-session"
    })
    .to_string();

    let ctx = HookContext::parse(&raw_payload);

    // Fast path check. Skipped when the bypass is disabled so whitelisted
    // commands can still be traced through the rules with `test`.
    if !fast_path_disabled(args) {
        let start_fast = Instant::now();
        if let Some(decision) = check_fast_path(&ctx) {
            outln!("⚡ {} {:?}", t(Msg::M070), start_fast.elapsed());
            outln!("{}: {:?}", t(Msg::M071), decision);
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
            Some(HookDecision::Block { ref reason }) => {
                format!("BLOCK ({})", reason)
            }
            Some(HookDecision::PostContext {
                ref additional_context,
            }) => {
                format!("POST_CONTEXT ({})", additional_context)
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
    outln!("{}: {:?}", t(Msg::M080), total_elapsed);
}

fn handle_bench(args: &Cli, iterations: usize, command: &str, scripts: &[PathBuf]) {
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

    let raw_payload = serde_json::json!({
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": command,
                "Cwd": cwd,
            }
        },
        "conversationId": "bench-session"
    })
    .to_string();

    let ctx = HookContext::parse(&raw_payload);
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
/// on Windows (it splits on ';'), which used to silently defeat automatic
/// install placement (2026-09-05: an `install` from Git Bash fell back to
/// ~/bin instead of honoring the first writable PATH entry).
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
