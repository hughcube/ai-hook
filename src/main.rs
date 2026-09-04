use ai_hook::cli::{Cli, Commands};
use ai_hook::engine::{RuleLoader, RuleRunner};
use ai_hook::fast_path::check_fast_path;
use ai_hook::protocol::{HookContext, HookDecision};
use ai_hook::ui::GuiDialog;
use clap::Parser;
use std::io::Read;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args = Cli::parse();

    match args.command {
        Some(Commands::List) => handle_list(&args),
        Some(Commands::Test {
            ref command,
            ref tool,
            ref file,
        }) => handle_test(&args, command, tool, file),
        Some(Commands::Bench {
            iterations,
            ref command,
        }) => handle_bench(&args, iterations, command),
        Some(Commands::Install { ref target_dir }) => handle_install(target_dir.clone()),
        None => handle_dispatch(&args),
    }
}

/// Main entry point for agent hook dispatching via stdin
fn handle_dispatch(args: &Cli) {
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

    // 2. Discover rules
    let custom_paths = if args.rule.is_empty() {
        None
    } else {
        Some(args.rule.as_slice())
    };
    let rules = RuleLoader::discover_rules(custom_paths);

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

    // 4. Handle GUI confirmation if in YOLO/skip-permissions mode
    let mut gui_approved = None;
    if let HookDecision::Confirm { ref reason } = decision {
        if ctx.is_yolo && !args.dry_run {
            let prompt_target = if ctx.cmd.is_empty() {
                &ctx.target_file
            } else {
                &ctx.cmd
            };
            let approved = GuiDialog::confirm(reason, prompt_target, 60);
            gui_approved = Some(approved);
        }
    }

    let output = decision.to_json_output(&ctx, gui_approved);
    if !output.is_empty() {
        println!("{}", output);
    }
}

fn handle_list(args: &Cli) {
    let custom_paths = if args.rule.is_empty() {
        None
    } else {
        Some(args.rule.as_slice())
    };
    let rules = RuleLoader::discover_rules(custom_paths);

    println!("============================================================");
    println!("  ai-hook Active Rules (Total: {})", rules.len());
    println!("============================================================");

    if rules.is_empty() {
        println!("  No active rule scripts found.");
        println!("  Rules are discovered from:");
        println!("    1. ./.ai-hook/rules/*.js (Project local)");
        println!("    2. ~/.ai-hook/rules/*.js (User global)");
        println!("    3. ~/.agents/plugins/*/hooks/*.js (Plugins)");
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

fn handle_test(args: &Cli, command: &str, tool: &str, file: &str) {
    println!("Testing command against all active security rules...");
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

    let custom_paths = if args.rule.is_empty() {
        None
    } else {
        Some(args.rule.as_slice())
    };
    let rules = RuleLoader::discover_rules(custom_paths);

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
            Some(HookDecision::Confirm { ref reason }) => format!("⚠️ CONFIRM ({})", reason),
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

fn handle_bench(args: &Cli, iterations: usize, command: &str) {
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
    let custom_paths = if args.rule.is_empty() {
        None
    } else {
        Some(args.rule.as_slice())
    };
    let rules = RuleLoader::discover_rules(custom_paths);

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
    println!("  Total Time : {:?}", elapsed);
    println!("  Iterations : {}", iterations);
    println!("  Average    : {:.2} µs ({:.4} ms) per execution", avg_us, avg_us / 1000.0);
    println!("============================================================");
}

fn handle_install(target_dir: Option<PathBuf>) {
    let current_exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to get current executable path: {}", e);
            return;
        }
    };

    let dest_dir = target_dir.unwrap_or_else(|| {
        if let Some(home) = dirs::home_dir() {
            let user_bin = home.join("bin");
            if user_bin.exists() {
                return user_bin;
            }
            let local_bin = home.join(".local").join("bin");
            if local_bin.exists() {
                return local_bin;
            }
            user_bin
        } else {
            PathBuf::from("/usr/local/bin")
        }
    });

    if !dest_dir.exists() {
        let _ = std::fs::create_dir_all(&dest_dir);
    }

    let exe_name = if cfg!(windows) {
        "ai-hook.exe"
    } else {
        "ai-hook"
    };

    let dest_file = dest_dir.join(exe_name);
    match std::fs::copy(&current_exe, &dest_file) {
        Ok(_) => {
            println!(" Successfully installed ai-hook to:");
            println!("  {}", dest_file.display());
            println!();
            println!("Quick Setup Recommendations:");
            println!("  1. Ensure '{}' is in your PATH environment variable.", dest_dir.display());
            println!("  2. Add the following alias to ~/.zshrc or ~/.bashrc:");
            println!("     alias ai:hook=\"ai-hook\"");
            println!("  3. Verify by running:");
            println!("     ai-hook --version");
        }
        Err(e) => {
            eprintln!("Failed to copy binary to {}: {}", dest_file.display(), e);
        }
    }
}
