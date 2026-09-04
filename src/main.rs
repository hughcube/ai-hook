use ai_hook::cli::{Cli, Commands};
use ai_hook::engine::{ErrorPolicy, RuleLoader, RuleRunner};
use ai_hook::fast_path::check_fast_path;
use ai_hook::i18n::{Msg, t};
use ai_hook::protocol::input::env_flag_true;
use ai_hook::protocol::{HookContext, HookDecision};
use ai_hook::ui::GuiDialog;
use clap::{CommandFactory, FromArgMatches};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Instant;

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

fn main() {
    let help_info = get_binary_info_help();
    let cmd = Cli::command()
        .after_help(help_info.clone())
        .after_long_help(help_info);
    let matches = cmd.get_matches();
    let args = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

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
                eprintln!("[ai-hook update] {}: {}", t(Msg::M054), e);
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
        println!("{}", output);
    }
}

/// Fail-closed policy can be relaxed explicitly via CLI flag or environment.
fn allow_on_error_requested(args: &Cli) -> bool {
    args.allow_on_error || env_flag_true("AI_HOOK_ALLOW_ON_ERROR")
}

/// Main entry point for agent hook dispatching via stdin
fn handle_dispatch(args: &Cli) {
    if std::io::stdin().is_terminal() {
        // Invoked directly from terminal without piped input -> print help and exit
        let help_info = get_binary_info_help();
        let _ = Cli::command()
            .after_help(help_info.clone())
            .after_long_help(help_info)
            .print_help();
        println!();
        return;
    }

    let mut buffer = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut buffer) {
        // Unreadable stdin (broken pipe / invalid UTF-8) yields no reliable
        // payload; log instead of failing silently.
        eprintln!("[ai-hook] {}: {}", t(Msg::M055), e);
        return;
    }

    if buffer.trim().is_empty() {
        return;
    }

    let ctx = HookContext::parse(&buffer);

    // 1. Fast path check (< 0.01ms)
    if let Some(decision) = check_fast_path(&ctx) {
        print_output(&decision.to_json_output(&ctx, None));
        return;
    }

    // 2. Load explicit rules (no full-disk auto traversal)
    let explicit_paths = collect_target_rules(args, None);
    let rules = RuleLoader::load_rules(&explicit_paths);

    if rules.is_empty() {
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
                eprintln!("[ai-hook] {}: {}", t(Msg::M056), e);
                let reason = t(Msg::M057).to_string();
                print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
                return;
            }
        };

        let (decision, _) = runner.evaluate_all(&rules, &ctx, policy);

        // 4. Handle confirmation & GUI prompt
        let mut gui_approved = None;
        if let HookDecision::Confirm {
            ref reason,
            ref title,
            gui,
            timeout: rule_timeout,
            force_gui: rule_force_gui,
        } = decision
        {
            let gui_enabled = GuiDialog::is_enabled(args.no_gui);
            // Rule-provided timeout of 0 is treated as "use the default".
            let timeout = rule_timeout
                .filter(|t| *t > 0)
                .unwrap_or_else(|| GuiDialog::resolve_timeout(args.timeout));

            let force_gui_flag = args.force_gui || env_flag_true("AI_HOOK_FORCE_GUI");

            let is_forced = force_gui_flag || rule_force_gui.unwrap_or(false);

            let should_popup = if is_forced {
                !args.dry_run
            } else if let Some(rule_gui) = gui {
                rule_gui && gui_enabled && !args.dry_run
            } else {
                // Default: popup if GUI is enabled and not dry-run
                gui_enabled && !args.dry_run
            };

            if should_popup {
                let prompt_target = ctx
                    .cmd
                    .as_deref()
                    .filter(|c| !c.is_empty())
                    .or_else(|| ctx.file.as_ref().and_then(|f| f.path.as_deref()))
                    .unwrap_or("");
                let prompt_title = title.as_deref().unwrap_or_else(|| t(Msg::M058));
                let prompt_agent = ctx.platform.to_string();
                let approved =
                    GuiDialog::confirm(prompt_title, reason, prompt_target, &prompt_agent, timeout);
                gui_approved = Some(approved);
            } else if ctx.is_yolo {
                // YOLO / bypass mode with no real dialog shown must fail
                // closed: hosts may silently ignore an "ask" decision.
                gui_approved = Some(false);
            }
        }

        print_output(&decision.to_json_output(&ctx, gui_approved));
    }));

    if outcome.is_err() {
        eprintln!("[ai-hook] {}", t(Msg::M059));
        let reason = t(Msg::M060).to_string();
        print_output(&HookDecision::Deny { reason }.to_json_output(&ctx, None));
    }
}

fn handle_list(args: &Cli, scripts: &[PathBuf]) {
    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    println!("============================================================");
    println!("  {} ({}: {})", t(Msg::M061), t(Msg::M062), rules.len());
    println!("============================================================");

    if rules.is_empty() {
        println!("  {}", t(Msg::M063));
        println!(
            "  {}: ai-hook [选项] <script1.js> <script2.js>...",
            t(Msg::M064)
        );
        println!(
            "  {}: ./.ai-hook/rules.js 或 ./.ai-hook/rules/",
            t(Msg::M065)
        );
        return;
    }

    for (idx, r) in rules.iter().enumerate() {
        println!("  [{:02}] {:<30} -> {}", idx + 1, r.id, r.path.display());
    }
}

fn handle_test(args: &Cli, command: &str, tool: &str, file: &str, scripts: &[PathBuf]) {
    println!("{}...", t(Msg::M066));
    println!("{}: {}", t(Msg::M067), command);
    println!("{}: {}", t(Msg::M068), tool);
    if !file.is_empty() {
        println!("{}: {}", t(Msg::M069), file);
    }
    println!("------------------------------------------------------------");

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let raw_payload = serde_json::json!({
        "toolName": tool,
        "toolCall": {
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

    // Fast path check
    let start_fast = Instant::now();
    if let Some(decision) = check_fast_path(&ctx) {
        println!("⚡ {} {:?}", t(Msg::M070), start_fast.elapsed());
        println!("{}: {:?}", t(Msg::M071), decision);
        return;
    }

    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    if rules.is_empty() {
        println!("⚠️ {}", t(Msg::M072));
        println!(
            "{}: ai-hook test <command> <script1.js> <script2.js>...",
            t(Msg::M073)
        );
        return;
    }

    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: {}", t(Msg::M074), e);
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
            Some(HookDecision::Allow) => t(Msg::M077).to_string(),
            None => t(Msg::M078).to_string(),
        };

        if let Some(err) = res.error {
            println!(
                "  [{:<25}] ❌ {}: {} (in {:?})",
                res.rule_id,
                t(Msg::M079),
                err,
                res.duration
            );
        } else {
            println!(
                "  [{:<25}] {:<30} (in {:?})",
                res.rule_id, status, res.duration
            );
        }
    }

    println!("------------------------------------------------------------");
    println!("{}: {:?}", t(Msg::M071), final_decision);
    println!("{}: {:?}", t(Msg::M080), total_elapsed);
}

fn handle_bench(args: &Cli, iterations: usize, command: &str, scripts: &[PathBuf]) {
    println!(
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
        "toolName": "run_command",
        "toolCall": {
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
        println!("⚠️ {}", t(Msg::M084));
        return;
    }

    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: {}", t(Msg::M085), e);
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
    println!("============================================================");
    println!("  {} : {} {}", t(Msg::M086), rules.len(), t(Msg::M087));
    println!("  {} : {:?}", t(Msg::M088), elapsed);
    println!("  {} : {}", t(Msg::M089), iterations);
    println!(
        "  {} : {:.2} µs ({:.4} ms) {}",
        t(Msg::M090),
        avg_us,
        avg_us / 1000.0,
        t(Msg::M091)
    );
    println!("============================================================");
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

/// Automatically detects an existing directory already in PATH to avoid adding any new environment variables.
fn resolve_global_install_dir(target_dir: Option<PathBuf>) -> PathBuf {
    if let Some(explicit) = target_dir {
        return explicit;
    }

    let existing_paths: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();

    // 1. Windows: Use official default app alias path which is already in user PATH by default
    #[cfg(windows)]
    {
        if let Some(local_app_data) = dirs::data_local_dir() {
            let win_apps = local_app_data.join("Microsoft").join("WindowsApps");
            if win_apps.exists() && is_dir_writable(&win_apps) {
                let norm_target = win_apps
                    .to_string_lossy()
                    .trim_end_matches('\\')
                    .to_lowercase();
                let in_path = existing_paths.iter().any(|p| {
                    p.to_string_lossy().trim_end_matches('\\').to_lowercase() == norm_target
                });
                if in_path {
                    return win_apps;
                }
            }
        }
    }

    // 2. Linux / macOS: Prefer standard system-wide /usr/local/bin if writable
    #[cfg(not(windows))]
    {
        let usr_local_bin = PathBuf::from("/usr/local/bin");
        if existing_paths.contains(&usr_local_bin) && is_dir_writable(&usr_local_bin) {
            return usr_local_bin;
        }
    }

    // 3. Search existing PATH entries for a directory under home with write permission
    if let Some(home) = dirs::home_dir() {
        for path in &existing_paths {
            if path.starts_with(&home) && path.exists() && is_dir_writable(path) {
                return path.clone();
            }
        }
    }

    // 4. Fallback default
    if let Some(home) = dirs::home_dir() {
        if cfg!(windows) {
            home.join("bin")
        } else {
            home.join(".local").join("bin")
        }
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

fn handle_install(target_dir: Option<PathBuf>) {
    let current_exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{}: {}", t(Msg::M092), e);
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
            eprintln!("{} {}: {}", t(Msg::M093), dest_file.display(), e);
            #[cfg(windows)]
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("   {}", t(Msg::M094));
            }
            return;
        }
        // Verify the copy actually landed (size matches the source).
        let src_len = std::fs::metadata(&current_exe).map(|m| m.len()).ok();
        let dest_len = std::fs::metadata(&dest_file).map(|m| m.len()).ok();
        if src_len.is_some() && src_len != dest_len {
            eprintln!(
                "{} {} ({}).",
                t(Msg::M095),
                dest_file.display(),
                t(Msg::M096)
            );
            let _ = std::fs::remove_file(&dest_file);
            return;
        }
        println!("{}:", t(Msg::M097));
        println!("   {}", dest_file.display());
    } else {
        println!("{}:", t(Msg::M098));
        println!("   {}", dest_file.display());
    }
    println!();

    // Check if the destination is already in PATH (no environment variables modified)
    let in_path = std::env::var_os("PATH")
        .map(|paths| {
            let norm_dest = dest_dir
                .to_string_lossy()
                .trim_end_matches(['\\', '/'])
                .to_lowercase();
            std::env::split_paths(&paths).any(|p| {
                p.to_string_lossy()
                    .trim_end_matches(['\\', '/'])
                    .to_lowercase()
                    == norm_dest
            })
        })
        .unwrap_or(false);

    if in_path {
        println!("✓ {}", t(Msg::M099));
        println!("  '{}' {}.", dest_dir.display(), t(Msg::M100));
        println!("  {}", t(Msg::M101));
    } else {
        println!(
            "ℹ️  {} '{}' {}.",
            t(Msg::M102),
            dest_dir.display(),
            t(Msg::M103)
        );
        println!("   {}:", t(Msg::M104));
        println!("     {}", dest_file.display());
    }
}
