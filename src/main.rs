use ai_hook::cli::{Cli, Commands};
use ai_hook::engine::{RuleLoader, RuleRunner};
use ai_hook::fast_path::check_fast_path;
use ai_hook::protocol::{HookContext, HookDecision};
use ai_hook::ui::GuiDialog;
use clap::{CommandFactory, Parser};
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args = Cli::parse();

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
                eprintln!("[ai-hook update] Error: {}", e);
                std::process::exit(1);
            }
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

/// Main entry point for agent hook dispatching via stdin
fn handle_dispatch(args: &Cli) {
    if std::io::stdin().is_terminal() {
        // Invoked directly from terminal without piped input -> print help and exit
        let _ = Cli::command().print_help();
        println!();
        return;
    }

    let mut buffer = String::new();
    let _ = std::io::stdin().read_to_string(&mut buffer);

    if buffer.trim().is_empty() {
        return;
    }

    let ctx = HookContext::parse(&buffer);

    // 1. Fast path check (< 0.01ms)
    if let Some(decision) = check_fast_path(&ctx) {
        let output = decision.to_json_output(&ctx, None);
        if !output.is_empty() {
            println!("{}", output);
        }
        return;
    }

    // 2. Load explicit rules (no full-disk auto traversal)
    let explicit_paths = collect_target_rules(args, None);
    let rules = RuleLoader::load_rules(&explicit_paths);

    if rules.is_empty() {
        let output = HookDecision::Allow.to_json_output(&ctx, None);
        if !output.is_empty() {
            println!("{}", output);
        }
        return;
    }

    // 3. Initialize runner & evaluate
    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ai-hook] Failed to initialize JS runtime: {}", e);
            let output = HookDecision::Allow.to_json_output(&ctx, None);
            if !output.is_empty() {
                println!("{}", output);
            }
            return;
        }
    };

    let (decision, _) = runner.evaluate_all(&rules, &ctx);

    // 4. Handle confirmation & GUI prompt
    let mut gui_approved = None;
    if let HookDecision::Confirm {
        ref reason,
        ref title,
        gui,
        timeout: rule_timeout,
    } = decision
    {
        let gui_enabled = GuiDialog::is_enabled(args.no_gui);
        let timeout = rule_timeout.unwrap_or_else(|| GuiDialog::resolve_timeout(args.timeout));

        let should_popup = if let Some(rule_gui) = gui {
            rule_gui && gui_enabled && !args.dry_run
        } else {
            // Default: popup if GUI is enabled and not dry-run
            gui_enabled && !args.dry_run
        };

        if should_popup {
            let prompt_target = if ctx.cmd.is_empty() {
                &ctx.target_file
            } else {
                &ctx.cmd
            };
            let prompt_title = title.as_deref().unwrap_or("操作安全授权确认");
            let prompt_agent = ctx.platform.to_string();
            let approved = GuiDialog::confirm(
                prompt_title,
                reason,
                prompt_target,
                &prompt_agent,
                timeout,
            );
            gui_approved = Some(approved);
        } else if ctx.is_yolo && !gui_enabled {
            // If GUI is explicitly disabled in YOLO mode, reject for safety
            gui_approved = Some(false);
        }
    }

    let output = decision.to_json_output(&ctx, gui_approved);
    if !output.is_empty() {
        println!("{}", output);
    }
}

fn handle_list(args: &Cli, scripts: &[PathBuf]) {
    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    println!("============================================================");
    println!("  ai-hook Target Rules (Total: {})", rules.len());
    println!("============================================================");

    if rules.is_empty() {
        println!("  No active rule scripts specified.");
        println!("  Pass script files explicitly: ai-hook [options] <script1.js> <script2.js>...");
        println!("  Or place in project directory: ./.ai-hook/rules.js or ./.ai-hook/rules/");
        return;
    }

    for (idx, r) in rules.iter().enumerate() {
        println!(
            "  [{:02}] {:<30} -> {}",
            idx + 1,
            r.id,
            r.path.display()
        );
    }
}

fn handle_test(args: &Cli, command: &str, tool: &str, file: &str, scripts: &[PathBuf]) {
    println!("Testing command against specified security rules...");
    println!("Target Command : {}", command);
    println!("Target Tool    : {}", tool);
    if !file.is_empty() {
        println!("Target File    : {}", file);
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
        println!("⚡ Fast Path Matched in {:?}", start_fast.elapsed());
        println!("Final Decision : {:?}", decision);
        return;
    }

    let explicit_paths = collect_target_rules(args, Some(scripts));
    let rules = RuleLoader::load_rules(&explicit_paths);

    if rules.is_empty() {
        println!("⚠️ No rule scripts provided to test against.");
        println!("Usage: ai-hook test <command> <script1.js> <script2.js>...");
        return;
    }

    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error initializing runner: {}", e);
            return;
        }
    };

    let start_eval = Instant::now();
    let (final_decision, results) = runner.evaluate_all(&rules, &ctx);
    let total_elapsed = start_eval.elapsed();

    for res in results {
        let status = match res.decision {
            Some(HookDecision::Confirm { ref reason, .. }) => format!("⚠️ CONFIRM ({})", reason),
            Some(HookDecision::Deny { ref reason }) => format!("🛑 DENY ({})", reason),
            Some(HookDecision::Allow) => "✅ ALLOW".to_string(),
            None => "◽ PASS".to_string(),
        };

        if let Some(err) = res.error {
            println!(
                "  [{:<25}] ❌ ERROR: {} (in {:?})",
                res.rule_id, err, res.duration
            );
        } else {
            println!(
                "  [{:<25}] {:<30} (in {:?})",
                res.rule_id, status, res.duration
            );
        }
    }

    println!("------------------------------------------------------------");
    println!("Final Decision : {:?}", final_decision);
    println!("Total Duration : {:?}", total_elapsed);
}

fn handle_bench(args: &Cli, iterations: usize, command: &str, scripts: &[PathBuf]) {
    println!("Running benchmark: {} iterations on '{}'", iterations, command);

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
        println!("⚠️ No rule scripts provided to benchmark.");
        return;
    }

    let runner = match RuleRunner::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Runner init error: {}", e);
            return;
        }
    };

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = runner.evaluate_all(&rules, &ctx);
    }
    let elapsed = start.elapsed();

    let avg_us = elapsed.as_micros() as f64 / iterations as f64;
    println!("============================================================");
    println!("  Target Rules : {} scripts", rules.len());
    println!("  Total Time   : {:?}", elapsed);
    println!("  Iterations   : {}", iterations);
    println!("  Average      : {:.2} µs ({:.4} ms) per execution", avg_us, avg_us / 1000.0);
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
                let norm_target = win_apps.to_string_lossy().trim_end_matches('\\').to_lowercase();
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
            eprintln!("Failed to get current executable path: {}", e);
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
            eprintln!("Failed to copy binary to {}: {}", dest_file.display(), e);
            return;
        }
        println!("✨ Successfully installed ai-hook to:");
        println!("   {}", dest_file.display());
    } else {
        println!("✨ ai-hook is already located at:");
        println!("   {}", dest_file.display());
    }
    println!();

    // Check if the destination is already in PATH (no environment variables modified)
    let in_path = std::env::var_os("PATH")
        .map(|paths| {
            let norm_dest = dest_dir.to_string_lossy().trim_end_matches(['\\', '/']).to_lowercase();
            std::env::split_paths(&paths).any(|p| {
                p.to_string_lossy().trim_end_matches(['\\', '/']).to_lowercase() == norm_dest
            })
        })
        .unwrap_or(false);

    if in_path {
        println!("✓ Global command ready!");
        println!("  '{}' is already in your PATH.", dest_dir.display());
        println!("  Zero extra environment variables added. You can run 'ai-hook' directly from any terminal.");
    } else {
        println!("ℹ️  Notice: '{}' is not currently present in your PATH.", dest_dir.display());
        println!("   To use without modifying PATH, you can run by absolute path:");
        println!("     {}", dest_file.display());
    }
}
