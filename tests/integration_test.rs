use ai_hook::engine::{ErrorPolicy, RuleLoader, RuleRunner, RuleSource};
use ai_hook::fast_path::check_fast_path;
use ai_hook::protocol::{FileAction, FileContext, HookContext, HookDecision, Platform};
use std::path::PathBuf;
use std::time::Duration;

/// Builds a HookContext from a realistic Antigravity payload around `cmd`.
fn ctx_for(cmd: &str) -> HookContext {
    HookContext::parse(
        &serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": cmd }
            },
            "conversationId": "conv-test"
        })
        .to_string(),
    )
}

/// Builds a RuleSource with `id` and `code`.
fn rule(id: &str, code: &str) -> RuleSource {
    RuleSource {
        id: id.to_string(),
        path: PathBuf::from(format!("{id}.js")),
        code: code.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Fast path
// ---------------------------------------------------------------------------

#[test]
fn test_fast_path_filtering() {
    assert_eq!(
        check_fast_path(&ctx_for("git status")),
        Some(HookDecision::Allow)
    );
    assert_eq!(
        check_fast_path(&ctx_for("git status > dangerous.txt")),
        None
    );

    // Non-command contexts (no cmd) never hit the fast path.
    let file_ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/a.txt", "content": "x" }
        })
        .to_string(),
    );
    assert_eq!(check_fast_path(&file_ctx), None);
}

#[test]
fn test_fast_path_blocks_injection_and_boundary_abuse() {
    // These MUST NOT be fast-pathed: each would otherwise let a second,
    // non-read-only command ride on a benign prefix.
    let malicious = [
        "git status\ntouch pwned.txt", // newline injection
        "ls /\nreboot",                // newline injection
        "git status\nreboot",          // newline, no risky token
        "echo $(reboot)",              // command substitution
        "echo ${CMD}",                 // parameter expansion
        "cat `reboot`",                // backticks
        "git status && reboot",        // chaining
        "git status; reboot",          // chaining
        "git status | sh",             // pipe
        "git status > out.txt",        // redirect out
        "head -5 file < /etc/passwd",  // redirect in (never fast-path)
        "git statusX --help",          // glued suffix must not match prefix
        "cat/etc/passwd",              // no whitespace boundary after prefix
        "ls-reboot",                   // not an `ls` invocation at all
        "rm -rf /tmp/staging",         // dangerous token "rm "
        "pkill -f agent",              // substring kill/stop
        "shutdown -r now",             // destructive word
    ];
    for cmd in malicious {
        assert_eq!(
            check_fast_path(&ctx_for(cmd)),
            None,
            "command must NOT be fast-pathed: {cmd:?}"
        );
    }

    // Genuinely benign single commands still hit the fast path.
    let benign = [
        "git status",
        "git status --short",
        "git diff HEAD~1",
        "git branch --show-current",
        "ls",
        "ls -la /tmp",
        "pwd",
        "dir",
        "echo hello world",
        "which cargo",
        "where python",
        "cat package.json",
        "head -20 README.md",
        "tail -5 /var/log/syslog",
    ];
    for cmd in benign {
        assert_eq!(
            check_fast_path(&ctx_for(cmd)),
            Some(HookDecision::Allow),
            "command should be fast-pathed: {cmd:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Payload ingress parsing (v2: real host schemas, one semantic per property)
// ---------------------------------------------------------------------------

#[test]
fn test_protocol_ingress_antigravity() {
    // Realistic Antigravity payload: tool name lives in `toolCall.name`,
    // conversation/transcript/model at the top level.
    let agy_raw = serde_json::json!({
        "toolCall": {
            "name": "run_command",
            "args": { "CommandLine": "echo hello", "Cwd": "C:\\work" }
        },
        "stepIdx": 3,
        "conversationId": "conv-123",
        "transcriptPath": "/logs/t.jsonl",
        "modelName": "gemini-3.6-flash-medium"
    })
    .to_string();
    let ctx = HookContext::parse(&agy_raw);
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.tool_name, "run_command");
    assert_eq!(ctx.cmd.as_deref(), Some("echo hello"));
    assert_eq!(ctx.cwd, "C:\\work");
    assert_eq!(ctx.model.as_deref(), Some("gemini-3.6-flash-medium"));
    assert_eq!(
        ctx.conversation.as_ref().and_then(|c| c.id.as_deref()),
        Some("conv-123")
    );
    assert_eq!(
        ctx.conversation
            .as_ref()
            .and_then(|c| c.transcript_path.as_deref()),
        Some("/logs/t.jsonl")
    );
    assert!(ctx.file.is_none());
}

#[test]
fn test_protocol_ingress_claude_envelope_hosts() {
    // Claude Code shape.
    let cc_raw = serde_json::json!({
        "session_id": "sess-cc",
        "transcript_path": "/sessions/t.jsonl",
        "cwd": "/workspaces/app",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "toolu_1",
        "tool_input": { "command": "npm test", "description": "run tests" }
    })
    .to_string();
    let ctx_cc = HookContext::parse(&cc_raw);
    assert_eq!(ctx_cc.platform, Platform::ClaudeCode);
    assert_eq!(ctx_cc.tool_name, "Bash");
    assert_eq!(ctx_cc.cmd.as_deref(), Some("npm test"));
    assert_eq!(ctx_cc.cwd, "/workspaces/app");
    assert_eq!(ctx_cc.permission_mode.as_deref(), Some("default"));
    assert_eq!(
        ctx_cc.conversation.as_ref().and_then(|c| c.id.as_deref()),
        Some("sess-cc")
    );
    assert!(!ctx_cc.is_yolo);

    // Codex adds `turn_id` (documented Codex-only field).
    let codex_raw = serde_json::json!({
        "turn_id": "turn-abc",
        "session_id": "sess-cx",
        "cwd": "/workspaces/cx",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "cargo check" }
    })
    .to_string();
    let ctx_codex = HookContext::parse(&codex_raw);
    assert_eq!(ctx_codex.platform, Platform::Codex);
    assert_eq!(ctx_codex.cmd.as_deref(), Some("cargo check"));
}

#[test]
fn test_permission_mode_yolo_detection() {
    let parse = |mode: &str| {
        HookContext::parse(
            &serde_json::json!({
                "session_id": "s",
                "permission_mode": mode,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": "echo hi" }
            })
            .to_string(),
        )
    };
    assert!(!parse("default").is_yolo);
    assert!(!parse("plan").is_yolo);
    assert!(!parse("acceptEdits").is_yolo); // edits auto-approve, commands still ask
    assert!(parse("dontAsk").is_yolo);
    assert!(parse("bypassPermissions").is_yolo);
}

#[test]
fn test_file_action_normalization_across_hosts() {
    // Claude Code / CodeBuddy / Codex style file tools.
    let parse_cc = |tool: &str, input: serde_json::Value| {
        HookContext::parse(
            &serde_json::json!({
                "session_id": "s",
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": input
            })
            .to_string(),
        )
    };

    let w = parse_cc(
        "Write",
        serde_json::json!({ "file_path": "/tmp/a.txt", "content": "x" }),
    );
    assert_eq!(
        w.file,
        Some(FileContext {
            path: Some("/tmp/a.txt".into()),
            action: FileAction::Write
        })
    );
    assert!(w.cmd.is_none());

    let r = parse_cc("Read", serde_json::json!({ "file_path": "/tmp/a.txt" }));
    assert_eq!(r.file.as_ref().map(|f| f.action), Some(FileAction::Read));

    let e = parse_cc(
        "Edit",
        serde_json::json!({ "file_path": "/tmp/a.txt", "old_string": "a" }),
    );
    assert_eq!(e.file.as_ref().map(|f| f.action), Some(FileAction::Edit));

    let d = parse_cc("Delete", serde_json::json!({ "file_path": "/tmp/a.txt" }));
    assert_eq!(d.file.as_ref().map(|f| f.action), Some(FileAction::Delete));

    // Codex apply_patch is edit-shaped (no single path).
    let ap = parse_cc(
        "apply_patch",
        serde_json::json!({ "patch": "--- a\n+++ b" }),
    );
    assert_eq!(ap.file.as_ref().map(|f| f.action), Some(FileAction::Edit));
    assert_eq!(ap.file.as_ref().and_then(|f| f.path.as_deref()), None);

    // Antigravity tools.
    let parse_agy = |tool: &str, args: serde_json::Value| {
        HookContext::parse(
            &serde_json::json!({
                "toolCall": { "name": tool, "args": args },
                "conversationId": "c"
            })
            .to_string(),
        )
    };
    let vf = parse_agy("view_file", serde_json::json!({ "file_path": "/p/a.txt" }));
    assert_eq!(vf.file.as_ref().map(|f| f.action), Some(FileAction::Read));
    // Real Antigravity view_file carries its target as AbsolutePath
    // (captured payloads); it must normalize to action=read with the path.
    let vf_abs = parse_agy(
        "view_file",
        serde_json::json!({ "AbsolutePath": "/p/secret.txt" }),
    );
    assert_eq!(
        vf_abs.file,
        Some(FileContext {
            path: Some("/p/secret.txt".into()),
            action: FileAction::Read
        })
    );
    // Antigravity list_dir carries its target as DirectoryPath.
    let ld_dir = parse_agy("list_dir", serde_json::json!({ "DirectoryPath": "/p/dir" }));
    assert_eq!(
        ld_dir.file,
        Some(FileContext {
            path: Some("/p/dir".into()),
            action: FileAction::List
        })
    );
    let wtf = parse_agy(
        "write_to_file",
        serde_json::json!({ "file_path": "/p/b.txt", "content": "y" }),
    );
    assert_eq!(wtf.file.as_ref().map(|f| f.action), Some(FileAction::Write));
    let ld = parse_agy("list_dir", serde_json::json!({ "path": "/p" }));
    assert_eq!(ld.file.as_ref().map(|f| f.action), Some(FileAction::List));
    assert_eq!(ld.file.as_ref().and_then(|f| f.path.as_deref()), Some("/p"));

    // Non-file/non-command tools expose neither.
    let web = parse_cc("WebSearch", serde_json::json!({ "query": "x" }));
    assert!(web.cmd.is_none() && web.file.is_none());
}

// ---------------------------------------------------------------------------
// JS rule execution (v2 context injection)
// ---------------------------------------------------------------------------

#[test]
fn test_autonomous_js_rule_execution() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    let rule_code = r#"
        export default function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.includes("drop_database")) {
                return { action: "deny", reason: "Cannot drop database" };
            }
            if (ctx.cmd && ctx.cmd.includes("restart_service")) {
                return { action: "confirm", reason: "Needs restart approval" };
            }
            return null;
        }
    "#;

    let rule = rule("test-rule", rule_code);

    let deny_ctx = ctx_for("psql -c drop_database");
    let res_deny = runner.execute_rule(&rule, &deny_ctx);
    assert_eq!(
        res_deny.decision,
        Some(HookDecision::Deny {
            reason: "Cannot drop database".to_string()
        })
    );

    let confirm_ctx = ctx_for("systemctl restart_service");
    let res_confirm = runner.execute_rule(&rule, &confirm_ctx);
    assert_eq!(
        res_confirm.decision,
        Some(HookDecision::Confirm {
            reason: "Needs restart approval".to_string(),
            title: None,
            gui: None,
            timeout: None,
            force_gui: None,
        })
    );

    let pass_ctx = ctx_for("cargo check");
    let res_pass = runner.execute_rule(&rule, &pass_ctx);
    assert_eq!(res_pass.decision, None);
}

#[test]
fn test_v2_context_shapes_inside_js() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    // File tools get file{path,action} and cmd === null.
    let file_rule = rule(
        "file-shape",
        r#"export default function(ctx, sys) {
            if (ctx.cmd !== null) return { action: "deny", reason: "cmd must be null" };
            if (!ctx.file || ctx.file.action !== "write") return { action: "deny", reason: "file action wrong" };
            if (ctx.file.path !== "/tmp/a.txt") return { action: "deny", reason: "file path wrong" };
            if (ctx.tool !== "Write") return { action: "deny", reason: "tool wrong" };
            if (ctx.agent !== "claude_code") return { action: "deny", reason: "agent wrong" };
            if (ctx.mode !== "default") return { action: "deny", reason: "mode wrong" };
            if (!ctx.session || ctx.session.id !== "sess-1") return { action: "deny", reason: "session wrong" };
            if (ctx.session.transcriptPath !== "/s/t.jsonl") return { action: "deny", reason: "transcript wrong" };
            if (ctx.model !== null) return { action: "deny", reason: "model must be null for CC" };
            return { action: "deny", reason: "shape-ok" };
        }"#,
    );
    let file_ctx = HookContext::parse(
        &serde_json::json!({
            "session_id": "sess-1",
            "transcript_path": "/s/t.jsonl",
            "cwd": "/w",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/a.txt", "content": "x" }
        })
        .to_string(),
    );
    let res = runner.execute_rule(&file_rule, &file_ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "shape-ok".to_string()
        }),
        "unexpected: {:?} (error {:?})",
        res.decision,
        res.error
    );

    // Antigravity exposes model + agent identity from the toolCall envelope.
    let agy_rule = rule(
        "agy-shape",
        r#"export default function(ctx, sys) {
            if (ctx.agent !== "antigravity") return { action: "deny", reason: "agent" };
            if (ctx.model !== "gemini-x") return { action: "deny", reason: "model" };
            if (ctx.cmd !== "run deploy") return { action: "deny", reason: "cmd" };
            if (!ctx.session || ctx.session.id !== "conv-9") return { action: "deny", reason: "session" };
            if (ctx.session.transcriptPath !== "/t/x.jsonl") return { action: "deny", reason: "transcript" };
            if (ctx.isYolo !== false) return { action: "deny", reason: "yolo" };
            return { action: "deny", reason: "agy-ok" };
        }"#,
    );
    let agy_ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "run deploy", "Cwd": "/w" } },
            "conversationId": "conv-9",
            "transcriptPath": "/t/x.jsonl",
            "modelName": "gemini-x"
        })
        .to_string(),
    );
    let res2 = runner.execute_rule(&agy_rule, &agy_ctx);
    assert_eq!(
        res2.decision,
        Some(HookDecision::Deny {
            reason: "agy-ok".to_string()
        }),
        "unexpected: {:?} (error {:?})",
        res2.decision,
        res2.error
    );

    // No aliases: legacy names must be absent (undefined).
    let no_alias = rule(
        "no-alias",
        r#"export default function(ctx, sys) {
            if (ctx.agentType !== undefined) return { action: "deny", reason: "agentType alias must not exist" };
            if (ctx.toolName !== undefined) return { action: "deny", reason: "toolName alias must not exist" };
            if (ctx.targetFile !== undefined) return { action: "deny", reason: "targetFile alias must not exist" };
            if (ctx.conversationId !== undefined) return { action: "deny", reason: "conversationId alias must not exist" };
            if (ctx.platform !== undefined) return { action: "deny", reason: "platform alias must not exist" };
            return { action: "deny", reason: "no-alias-ok" };
        }"#,
    );
    let res3 = runner.execute_rule(&no_alias, &ctx_for("echo hi"));
    assert_eq!(
        res3.decision,
        Some(HookDecision::Deny {
            reason: "no-alias-ok".to_string()
        }),
        "unexpected: {:?} (error {:?})",
        res3.decision,
        res3.error
    );
}

#[test]
fn test_evaluate_all_short_circuits_on_first_hit_in_order() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let deny = rule(
        "a-deny",
        "export default function(ctx, sys) { return { action: \"deny\", reason: \"no\" }; }",
    );
    let allow = rule(
        "b-allow",
        "export default function(ctx, sys) { return { action: \"allow\" }; }",
    );
    let ctx = ctx_for("echo hi");

    // Deny first: short-circuits, the later allow rule never runs.
    let (dec, results) = runner.evaluate_all(
        &[deny.clone(), allow.clone()],
        &ctx,
        ErrorPolicy::FailClosed,
    );
    assert_eq!(
        dec,
        HookDecision::Deny {
            reason: "no".to_string()
        }
    );
    assert_eq!(results.len(), 1);

    // Allow first: continues, then deny still wins.
    let (dec2, results2) =
        runner.evaluate_all(&[allow.clone(), deny], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(
        dec2,
        HookDecision::Deny {
            reason: "no".to_string()
        }
    );
    assert_eq!(results2.len(), 2);
}

#[test]
fn test_async_rule_is_reported_not_silently_allowed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let async_rule = rule(
        "async-rule",
        r#"export default async function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.includes("danger")) {
                return { action: "deny", reason: "async deny" };
            }
            return null;
        }"#,
    );
    let ctx = ctx_for("danger operation");

    // The rule itself never yields a decision...
    let res = runner.execute_rule(&async_rule, &ctx);
    assert!(res.decision.is_none());
    let err = res.error.as_deref().unwrap_or("");
    assert!(
        err.contains("Promise") || err.contains("async"),
        "expected an async/Promise error, got: {err:?}"
    );

    // ...and the default fail-closed policy turns that into Deny.
    let (dec, _) = runner.evaluate_all(
        std::slice::from_ref(&async_rule),
        &ctx,
        ErrorPolicy::FailClosed,
    );
    assert!(matches!(dec, HookDecision::Deny { .. }));

    // Only an explicit opt-out restores the old allow-on-error behaviour.
    let (dec2, _) = runner.evaluate_all(&[async_rule], &ctx, ErrorPolicy::AllowOnError);
    assert_eq!(dec2, HookDecision::Allow);
}

#[test]
fn test_broken_rule_fails_closed_and_can_opt_out() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let throwing = rule(
        "boom",
        "export default function(ctx, sys) { throw new Error(\"boom\"); }",
    );
    let ctx = ctx_for("echo hi");

    let (dec, _) = runner.evaluate_all(
        std::slice::from_ref(&throwing),
        &ctx,
        ErrorPolicy::FailClosed,
    );
    assert!(matches!(dec, HookDecision::Deny { .. }), "{dec:?}");

    let (dec2, _) = runner.evaluate_all(
        std::slice::from_ref(&throwing),
        &ctx,
        ErrorPolicy::AllowOnError,
    );
    assert_eq!(dec2, HookDecision::Allow);

    // Syntax errors are just as fatal.
    let broken = rule(
        "broken",
        "export default function(ctx, sys) { this is not js !!!",
    );
    let (dec3, _) = runner.evaluate_all(&[broken], &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec3, HookDecision::Deny { .. }), "{dec3:?}");
}

#[test]
fn test_infinite_loop_rule_is_interrupted_by_timeout() {
    let runner =
        RuleRunner::with_timeout(Duration::from_millis(300)).expect("Failed to initialize runner");
    let loop_rule = rule("loop", "export default function() { while (true) {} }");
    let ctx = ctx_for("echo hi");

    let start = std::time::Instant::now();
    let res = runner.execute_rule(&loop_rule, &ctx);
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "rule execution was not bounded by the timeout"
    );
    assert!(res.decision.is_none());
    let err = res.error.as_deref().unwrap_or("");
    assert!(
        err.contains("超时") || err.contains("timed out") || err.contains("interrupted"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_export_default_inside_comments_or_strings_is_not_misparsed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    // Block comment contains a line starting with `export default`; the string
    // literal contains another. Neither may be rewritten into `return`.
    let tricky = r#"
/**
 * 规则示例
 * export default is documented here and must stay a comment
 */
const docs = "export default";
export default function(ctx, sys) {
    if (ctx.cmd && ctx.cmd.includes("wipe")) {
        return { action: "deny", reason: "comment-guard ok" };
    }
    return null;
}
"#;
    let res = runner.execute_rule(&rule("tricky", tricky), &ctx_for("db wipe"));
    assert!(
        res.error.is_none(),
        "comment/string content must not break parsing: {:?}",
        res.error
    );
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "comment-guard ok".to_string()
        })
    );
}

#[test]
fn test_ctx_agent_and_raw_input() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            // Agent identity from the normalized envelope
            if (ctx.agent !== "antigravity") {
                return { action: "deny", reason: "Agent detection failed" };
            }
            // Session identity
            if (!ctx.session || ctx.session.id !== "conv-raw") {
                return { action: "deny", reason: "Session failed" };
            }
            // Raw payload access
            if (!ctx.raw || ctx.raw.customFlag !== "secret_value") {
                return { action: "deny", reason: "Raw payload access failed" };
            }
            // Args access (host-verbatim)
            if (!ctx.args || ctx.args.CommandLine !== "echo hello") {
                return { action: "deny", reason: "Args access failed" };
            }
            return {
                action: "confirm",
                reason: "Confirmed with GUI control",
                title: "Custom Auth Title",
                gui: false,
                timeout: 45
            };
        }
    "#;

    let rule = rule("raw-agent-test", rule_code);

    let ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": "echo hello" }
            },
            "conversationId": "conv-raw",
            "customFlag": "secret_value"
        })
        .to_string(),
    );

    let res = runner.execute_rule(&rule, &ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Confirm {
            reason: "Confirmed with GUI control".to_string(),
            title: Some("Custom Auth Title".to_string()),
            gui: Some(false),
            timeout: Some(45),
            force_gui: None,
        })
    );
}

#[test]
fn test_force_gui_rule() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    // 1. Rule with force_gui: true
    let rule_code1 = r#"
        export default function(ctx, sys) {
            return {
                action: "confirm",
                reason: "Sensitive write operation",
                gui: false,
                force_gui: true
            };
        }
    "#;
    let rule1 = rule("force-gui-1", rule_code1);
    let ctx = ctx_for("rm -rf build");
    let res1 = runner.execute_rule(&rule1, &ctx);
    assert_eq!(
        res1.decision,
        Some(HookDecision::Confirm {
            reason: "Sensitive write operation".to_string(),
            title: None,
            gui: Some(false),
            timeout: None,
            force_gui: Some(true),
        })
    );

    // 2. Rule with action: "force_gui" or "force_confirm"
    let rule_code2 = r#"
        export default function(ctx, sys) {
            return {
                action: "force_gui",
                reason: "Forced popup rule"
            };
        }
    "#;
    let rule2 = rule("force-gui-2", rule_code2);
    let res2 = runner.execute_rule(&rule2, &ctx);
    assert_eq!(
        res2.decision,
        Some(HookDecision::Confirm {
            reason: "Forced popup rule".to_string(),
            title: None,
            gui: Some(true),
            timeout: None,
            force_gui: Some(true),
        })
    );
}

#[test]
fn test_rule_logging_sys_log_api() {
    // console.log / sys.log must not break evaluation. Disable the file
    // channel for tests (env is process-global; no other test logs).
    unsafe {
        std::env::set_var("AI_HOOK_LOG", "0");
    }
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            console.log("console debug line", ctx.agent);
            sys.log("warn", "sys warn line");
            sys.log("only-msg-form");
            return null;
        }
    "#;
    let ctx = ctx_for("echo hi");
    let res = runner.execute_rule(&rule("logger-test", rule_code), &ctx);
    assert!(
        res.error.is_none(),
        "logging must not fail rules: {:?}",
        res.error
    );
    assert_eq!(res.decision, None);
}

// ---------------------------------------------------------------------------
// Git / filesystem helpers inside rules
// ---------------------------------------------------------------------------

#[test]
fn test_sys_autonomous_git_branch() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    // The expected branch is whatever this checkout is on (if it is a git
    // repo); do not hardcode "master" so the test survives branch renames.
    let rule_code = r#"
        export default function(ctx, sys) {
            const branch = sys.git.branch() || "unknown";
            if (ctx.cmd && ctx.cmd.includes("--force")) {
                return { action: "deny", reason: `Force push blocked on ${branch}` };
            }
            return null;
        }
    "#;

    let rule = rule("git-test", rule_code);
    let ctx = ctx_for("git push origin master --force");
    let res = runner.execute_rule(&rule, &ctx);
    let Some(HookDecision::Deny { reason }) = res.decision else {
        panic!(
            "Expected Deny decision, got {:?} (error: {:?})",
            res.decision, res.error
        );
    };
    assert!(
        reason.starts_with("Force push blocked on "),
        "unexpected reason: {reason}"
    );
}

// ---------------------------------------------------------------------------
// Rule loader
// ---------------------------------------------------------------------------

#[test]
fn test_loader_directory_load_is_sorted_and_deterministic() {
    let tmp_root = std::env::temp_dir().join(format!("ai-hook-loader-{}", std::process::id()));
    let dir = tmp_root.join("rules");
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["zebra.js", "alpha.js", "mango.js"] {
        std::fs::write(
            dir.join(name),
            "export default function(ctx, sys) { return null; }",
        )
        .unwrap();
    }

    // Load twice; the order must be file-name sorted regardless of the order
    // the filesystem enumerates them.
    let first = RuleLoader::load_rules(std::slice::from_ref(&dir));
    let second = RuleLoader::load_rules(std::slice::from_ref(&dir));
    let ids = |rules: &[RuleSource]| rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&first), ["alpha", "mango", "zebra"]);
    assert_eq!(ids(&first), ids(&second));

    std::fs::remove_dir_all(&tmp_root).ok();
}

// ---------------------------------------------------------------------------
// Tutorial content
// ---------------------------------------------------------------------------

#[test]
fn test_tutorial_output() {
    // Content must exist and the version placeholder must have been filled.
    let zh = ai_hook::tutorial::tutorial_text("zh");
    let en = ai_hook::tutorial::tutorial_text("en");
    for text in [&zh, &en] {
        assert!(text.contains("ai-hook"), "tutorial must mention ai-hook");
        assert!(
            !text.contains("@@VERSION@@"),
            "version placeholder must be substituted"
        );
        assert!(
            text.contains(env!("CARGO_PKG_VERSION")),
            "tutorial must embed the real package version"
        );
    }
    assert!(
        zh.contains("tutorial"),
        "zh tutorial must contain tutorial cmd"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed regressions (the engine must never silently pass a command when
// a rule is broken: a missing return, an unparsable value, an unknown action).
// ---------------------------------------------------------------------------

#[test]
fn test_missing_return_fails_closed_not_silently_allowed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    // Author intended to deny the command but forgot the `return`: the
    // function falls off the end and yields `undefined`. Under FailClosed
    // this must be reported as an error and DENIED, like an exception.
    let sloppy = rule(
        "sloppy",
        r#"export default function(ctx, sys) {
            if (ctx.cmd && /rm\s+-rf/.test(ctx.cmd)) {
                const d = { action: "deny", reason: "blocked" };
            }
        }"#,
    );
    let ctx = ctx_for("rm -rf /tmp/data");

    let res = runner.execute_rule(&sloppy, &ctx);
    assert!(
        res.error.is_some(),
        "missing return must set an error: {res:?}"
    );

    let (dec, _) =
        runner.evaluate_all(std::slice::from_ref(&sloppy), &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::Deny { .. }), "{dec:?}");

    // Explicit opt-out still restores the old pass-through behaviour.
    let (dec2, _) = runner.evaluate_all(&[sloppy], &ctx, ErrorPolicy::AllowOnError);
    assert_eq!(dec2, HookDecision::Allow);
}

#[test]
fn test_unknown_action_object_fails_closed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let unknown = rule(
        "unknown-action",
        r#"export default function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.includes("op17")) {
                return { action: "no_such_action", reason: "typo" };
            }
            return null;
        }"#,
    );
    let ctx = ctx_for("run op17");
    let res = runner.execute_rule(&unknown, &ctx);
    assert!(
        res.error.is_some(),
        "unknown action must be an error: {res:?}"
    );
    let (dec, _) = runner.evaluate_all(&[unknown], &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::Deny { .. }), "{dec:?}");
}

#[test]
fn test_return_null_remains_no_opinion() {
    // `return null` is the documented "no opinion, move to the next rule" and
    // must keep passing under FailClosed (not treated as a broken rule).
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let pass = rule("pass", "export default function(ctx, sys) { return null; }");
    let ctx = ctx_for("echo hi");
    let (dec, results) = runner.evaluate_all(&[pass], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
    assert_eq!(results[0].error, None);
}

#[test]
fn test_export_default_boundary_rejects_identifier_suffix() {
    // `export defaultValue` is NOT the module default export. Without the
    // trailing-boundary check it would be rewritten to `return Value = 5`,
    // which is legal JS, silently changing semantics: the rule would "pass"
    // (a number is not an actionable value) and the gate would open.
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let weird = rule("boundary", "export defaultValue = 5;");
    let ctx = ctx_for("echo hi");
    let res = runner.execute_rule(&weird, &ctx);
    // The literal `export` keyword stays invalid inside `new Function`, so the
    // rule must surface as an error and fail closed - never as a silent allow.
    assert!(res.error.is_some(), "must be reported as broken: {res:?}");
    assert!(res.decision.is_none());
    let (dec, _) = runner.evaluate_all(&[weird], &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::Deny { .. }), "{dec:?}");
}

// ---------------------------------------------------------------------------
// CLI end-to-end regressions (exercise the real binary through std::process).
// ---------------------------------------------------------------------------

use std::io::Write;
use std::process::{Command, Stdio};

fn write_temp_rule(dir: &std::path::Path, name: &str, code: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(code.as_bytes()).unwrap();
    path
}

#[test]
fn test_cli_test_subcommand_sees_ctx_cmd() {
    // Regression: the `test` subcommand built a payload without `toolCall.name`,
    // so ctx.cmd was always null and every command rule silently no-op'd.
    let tmp = std::env::temp_dir().join(format!("ai-hook-cli-cmd-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let rule_file = write_temp_rule(
        &tmp,
        "cmd-guard.js",
        r#"export default function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.includes("op17")) {
                return { action: "deny", reason: "cli-blocked" };
            }
            return null;
        }"#,
    );

    let out = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args(["test", "run op17", &rule_file.to_string_lossy()])
        .output()
        .expect("run ai-hook test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("cli-blocked"),
        "ctx.cmd must reach the rule; stdout: {stdout} stderr: {stderr}"
    );

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn test_cli_fast_path_can_be_disabled() {
    let tmp = std::env::temp_dir().join(format!("ai-hook-cli-fp-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let rule_file = write_temp_rule(
        &tmp,
        "status-guard.js",
        r#"export default function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.startsWith("git status")) {
                return { action: "deny", reason: "status-blocked" };
            }
            return null;
        }"#,
    );
    let rule_arg = rule_file.to_string_lossy().to_string();
    let payload = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git status --short"}},"conversationId":"c"}"#;

    // Fast path enabled (default): the rule never runs.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args([&rule_arg])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("\"allow\""),
        "fast path should allow without running rules"
    );

    // --no-fast-path: the same command now reaches the rule and is denied.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args(["--no-fast-path", &rule_arg])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"deny\"") && stdout.contains("status-blocked"),
        "--no-fast-path must let the rule deny: {stdout}"
    );

    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn test_cli_unparsable_payload_asks_not_silently_allows() {
    // A payload that is not JSON carries no tool semantics. Silently running
    // rules against an empty view would usually end in an accidental Allow,
    // so ai-hook must emit an "ask" (or deny) instead of an empty stdout.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .env("HOOK_TEST_MODE", "1") // no GUI dialogs in CI/test processes
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "unparsable payload must never produce empty (allow) output"
    );
    assert!(
        stdout.contains("\"ask\"") || stdout.contains("\"deny\""),
        "unparsable payload must ask or deny: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// gui 三态语义:can_ask 宿主矩阵(2026-09-05 约定)
// ---------------------------------------------------------------------------
#[test]
fn test_can_ask_host_matrix() {
    // CC:普通 + bypass(yolo)均可 ask
    let cc = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PreToolUse","permission_mode":"default","tool_input":{"command":"ls"}}).to_string(),
    );
    assert!(cc.can_ask(), "CC 普通模式应可 ask");
    let cc_yolo = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PreToolUse","permission_mode":"bypassPermissions","tool_input":{"command":"ls"}}).to_string(),
    );
    assert!(cc_yolo.can_ask(), "CC bypass 模式也应可 ask(hook ask 最高优先)");

    // Codex:0.152+ 普通可 ask;bypass(yolo)不可
    let codex = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"never","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    assert!(codex.can_ask(), "Codex 普通模式应可 ask(0.152+)");
    let codex_yolo = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"bypassPermissions","tool_input":{"command":"ls"}}).to_string(),
    );
    assert!(!codex_yolo.can_ask(), "Codex bypass 模式不可 ask");

    // AGY:普通交互 force_ask 可;YOLO 不可
    let agy = HookContext::parse(
        &serde_json::json!({"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}}}).to_string(),
    );
    assert!(agy.can_ask(), "AGY 普通交互模式可 ask(force_ask)");
    let agy_yolo = HookContext::parse(
        &serde_json::json!({"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"permission_mode":"bypassPermissions"}).to_string(),
    );
    assert!(!agy_yolo.can_ask(), "AGY YOLO 模式不可 ask(ask 被静默放行)");

    // Generic:无 ask 协议
    let generic = HookContext::parse("not-json");
    assert!(!generic.can_ask(), "Generic 无 ask 协议");
}

/// Codex 普通模式输出层:Confirm + 无 GUI 结果 → permissionDecision ask(0.152+)
#[test]
fn test_codex_confirm_outputs_ask_when_can_ask() {
    let ctx = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"redis-cli flushall"}}).to_string(),
    );
    let decision = HookDecision::Confirm {
        reason: "高危操作确认".to_string(),
        title: None,
        gui: None,
        timeout: None,
        force_gui: None,
    };
    let out = decision.to_json_output(&ctx, None);
    assert!(
        out.contains("\"permissionDecision\":\"ask\""),
        "Codex 普通模式应输出 ask: {out}"
    );
    assert!(out.contains("redis-cli flushall"), "ask reason 应含完整命令: {out}");
}

/// Codex bypass(yolo)输出层:Confirm + 未弹窗(防御路径)→ deny
#[test]
fn test_codex_yolo_confirm_falls_back_to_deny() {
    let ctx = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"bypassPermissions","tool_name":"Bash","tool_input":{"command":"redis-cli flushall"}}).to_string(),
    );
    let decision = HookDecision::Confirm {
        reason: "高危操作确认".to_string(),
        title: None,
        gui: None,
        timeout: None,
        force_gui: None,
    };
    let out = decision.to_json_output(&ctx, None);
    assert!(
        out.contains("\"permissionDecision\":\"deny\""),
        "Codex bypass 未弹窗时必须 deny: {out}"
    );
}

/// gui 三态输出层:CC 缺省 → ask;gui_approved Some(false) → deny(弹窗拒绝)
#[test]
fn test_claude_confirm_ask_vs_dialog_denied() {
    let ctx = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PreToolUse","permission_mode":"default","tool_input":{"command":"ls"}}).to_string(),
    );
    let decision = HookDecision::Confirm {
        reason: "确认删除".to_string(),
        title: None,
        gui: None,
        timeout: None,
        force_gui: None,
    };
    let ask_out = decision.to_json_output(&ctx, None);
    assert!(
        ask_out.contains("\"permissionDecision\":\"ask\""),
        "CC 缺省应输出 ask: {ask_out}"
    );
    let denied_out = decision.to_json_output(&ctx, Some(false));
    assert!(
        denied_out.contains("\"permissionDecision\":\"deny\""),
        "CC 弹窗被拒应输出 deny: {denied_out}"
    );
}

#[test]
fn test_sys_exec_api() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let exec_rule = rule(
        "test-exec",
        r#"export default function(ctx, sys) {
            if (typeof sys.exec !== 'function') {
                return { action: "deny", reason: "sys.exec missing" };
            }
            let res = sys.exec("cmd", ["/c", "echo ai-hook-exec-ok"]);
            if (res.status !== 0 || !res.stdout.includes("ai-hook-exec-ok")) {
                return { action: "deny", reason: "sys.exec failed: " + JSON.stringify(res) };
            }
            return null;
        }"#,
    );
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[exec_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
}

#[test]
fn test_sys_http_api_exposed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let http_rule = rule(
        "test-http",
        r#"export default function(ctx, sys) {
            if (typeof sys.http !== 'object' || typeof sys.http.get !== 'function' || typeof sys.http.post !== 'function') {
                return { action: "deny", reason: "sys.http missing" };
            }
            return null;
        }"#,
    );
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[http_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
}

#[test]
fn test_user_prompt_submit_intercept_block() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let prompt_rule = rule(
        "intercept-prompt",
        r#"export default function(ctx, sys) {
            if (ctx.prompt && ctx.prompt.startsWith("/ai:balance")) {
                return { action: "block", reason: "余额为 100 元" };
            }
            return null;
        }"#,
    );
    let raw_payload = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "/ai:balance",
        "cwd": "C:\\"
    }).to_string();
    let ctx = HookContext::parse(&raw_payload);
    assert_eq!(ctx.prompt.as_deref(), Some("/ai:balance"));
    assert_eq!(ctx.event.as_deref(), Some("UserPromptSubmit"));

    let (dec, _) = runner.evaluate_all(&[prompt_rule], &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::Block { ref reason } if reason == "余额为 100 元"));

    let out = dec.to_json_output(&ctx, None);
    assert_eq!(out, serde_json::json!({
        "decision": "block",
        "reason": "余额为 100 元"
    }).to_string());
}

#[test]
fn test_post_tool_use_additional_context() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let post_rule = rule(
        "post-migration",
        r#"export default function(ctx, sys) {
            return {
                additionalContext: "请注意迁移规范"
            };
        }"#,
    );
    let raw_payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "edit_file",
        "cwd": "C:\\"
    }).to_string();
    let ctx = HookContext::parse(&raw_payload);
    assert_eq!(ctx.event.as_deref(), Some("PostToolUse"));

    let (dec, _) = runner.evaluate_all(&[post_rule], &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::PostContext { ref additional_context } if additional_context == "请注意迁移规范"));

    let out = dec.to_json_output(&ctx, None);
    assert_eq!(out, serde_json::json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "请注意迁移规范"
        }
    }).to_string());
}

#[test]
fn test_codex_dangerously_skip_permissions_env_detection() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let payload = serde_json::json!({
        "turn_id": "codex-turn-1",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": { "command": "rm -rf /" }
    }).to_string();

    let tmp = std::env::temp_dir().join(format!("ai-hook-codex-yolo-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let rule_file = write_temp_rule(
        &tmp,
        "codex-guard.js",
        r#"export default function(ctx, sys) {
            return { action: "confirm", reason: "confirm-danger" };
        }"#,
    );

    // 1. Without CODEX_DANGEROUSLY_SKIP_PERMISSIONS: should output "ask"
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args(["--no-gui", rule_file.to_string_lossy().as_ref()])
        .env_remove("CODEX_DANGEROUSLY_SKIP_PERMISSIONS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"ask\""), "Codex normal should ask: {stdout}");

    // 2. With CODEX_DANGEROUSLY_SKIP_PERMISSIONS=1: should output "deny"
    let mut child_yolo = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args(["--no-gui", rule_file.to_string_lossy().as_ref()])
        .env("CODEX_DANGEROUSLY_SKIP_PERMISSIONS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child_yolo.stdin.as_mut().unwrap().write_all(payload.as_bytes()).unwrap();
    let out_yolo = child_yolo.wait_with_output().unwrap();
    let stdout_yolo = String::from_utf8_lossy(&out_yolo.stdout);
    assert!(stdout_yolo.contains("\"deny\""), "Codex yolo env should deny: {stdout_yolo}");
}


