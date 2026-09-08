use ai_hook::engine::{ErrorPolicy, RuleLoader, RuleRunner, RuleSource};
use ai_hook::fast_path::check_fast_path;
use ai_hook::protocol::{
    AgentKind, FileAction, FileContext, HookContext, HookDecision, HookEvent, Mutation, Platform,
    SearchKind, WebAction,
};
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

/// Removes the CodeBuddy-injected environment variables.
///
/// A CodeBuddy session exports `CODEBUDDY_SESSION_ID` / `CODEBUDDY_PROJECT_DIR`
/// (and, for compatibility, `CLAUDE_*` equivalents) into every child process,
/// which would make platform detection classify a synthetic Claude Code
/// payload as CodeBuddy whenever the suite runs from such a session.
fn clear_codebuddy_env() {
    // SAFETY: tests run in parallel, but no other test depends on these
    // variables; only the platform-detection ones read them.
    unsafe {
        std::env::remove_var("CODEBUDDY_SESSION_ID");
        std::env::remove_var("CODEBUDDY_PROJECT_DIR");
        std::env::remove_var("CODEBUDDY_HOST");
    }
}

/// Builds a RuleSource with `id` and `code`.
fn rule(id: &str, code: &str) -> RuleSource {
    RuleSource {
        id: id.to_string(),
        path: PathBuf::from(format!("{id}.js")),
        code: code.to_string(),
    }
}

static TEST_LOG_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
// Payload ingress parsing (real host schemas, one semantic per property)
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
    clear_codebuddy_env();
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
            paths: vec!["/tmp/a.txt".into()],
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
            paths: vec!["/p/secret.txt".into()],
            action: FileAction::Read
        })
    );
    // Antigravity list_dir carries its target as DirectoryPath.
    let ld_dir = parse_agy("list_dir", serde_json::json!({ "DirectoryPath": "/p/dir" }));
    assert_eq!(
        ld_dir.file,
        Some(FileContext {
            path: Some("/p/dir".into()),
            paths: vec!["/p/dir".into()],
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
// JS rule execution (context injection)
// ---------------------------------------------------------------------------

#[test]
fn test_autonomous_js_rule_execution() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    let rule_code = r#"
        export default function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.includes("drop_database")) {
                return { deny: "Cannot drop database" };
            }
            if (ctx.cmd && ctx.cmd.includes("restart_service")) {
                return { ask: "Needs restart approval" };
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
fn test_context_shapes_inside_js() {
    clear_codebuddy_env();
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    // File tools get file{path,action} and cmd === null.
    let file_rule = rule(
        "file-shape",
        r#"export default function(ctx, sys) {
            if (ctx.cmd !== null) return { deny: "cmd must be null" };
            if (!ctx.file || ctx.file.action !== "write") return { deny: "file action wrong" };
            if (ctx.file.path !== "/tmp/a.txt") return { deny: "file path wrong" };
            if (ctx.tool !== "Write") return { deny: "tool wrong" };
            if (ctx.platform !== "claude_code") return { deny: "agent wrong" };
            if (ctx.mode !== "default") return { deny: "mode wrong" };
            if (!ctx.session || ctx.session.id !== "sess-1") return { deny: "session wrong" };
            if (ctx.session.transcriptPath !== "/s/t.jsonl") return { deny: "transcript wrong" };
            if (ctx.model !== null) return { deny: "model must be null for CC" };
            return { deny: "shape-ok" };
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
            if (ctx.platform !== "antigravity") return { deny: "agent" };
            if (ctx.model !== "gemini-x") return { deny: "model" };
            if (ctx.cmd !== "run deploy") return { deny: "cmd" };
            if (!ctx.session || ctx.session.id !== "conv-9") return { deny: "session" };
            if (ctx.session.transcriptPath !== "/t/x.jsonl") return { deny: "transcript" };
            if (ctx.isYolo !== false) return { deny: "yolo" };
            return { deny: "agy-ok" };
        }"#,
    );
    let agy_ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "run deploy", "Cwd": "/w" } },
            "is_yolo": false,
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

    // ctx/sys expose exactly one name per capability: anything else is absent
    // (undefined). The semantic views themselves (mcp/web/search/agent) are
    // null on a command payload, never undefined.
    let no_alias = rule(
        "no-alias",
        r#"export default function(ctx, sys) {
            if (ctx.agentType !== undefined) return { deny: "agentType alias must not exist" };
            if (ctx.toolName !== undefined) return { deny: "toolName alias must not exist" };
            if (ctx.targetFile !== undefined) return { deny: "targetFile alias must not exist" };
            if (ctx.conversationId !== undefined) return { deny: "conversationId alias must not exist" };
            if (ctx.mcp !== null) return { deny: "mcp must be null on a command" };
            if (ctx.web !== null) return { deny: "web must be null on a command" };
            if (ctx.search !== null) return { deny: "search must be null on a command" };
            if (ctx.agent !== null) return { deny: "agent must be null on a command" };
            return { deny: "no-alias-ok" };
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
        "export default function(ctx, sys) { return { deny: \"no\" }; }",
    );
    let allow = rule(
        "b-allow",
        "export default function(ctx, sys) { return { allow: true }; }",
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
                return { deny: "async deny" };
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
        return { deny: "comment-guard ok" };
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
fn test_ctx_platform_and_raw_input() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            // Agent identity from the normalized envelope
            if (ctx.platform !== "antigravity") {
                return { deny: "Agent detection failed" };
            }
            // Session identity
            if (!ctx.session || ctx.session.id !== "conv-raw") {
                return { deny: "Session failed" };
            }
            // Raw payload access
            if (!ctx.raw || ctx.raw.customFlag !== "secret_value") {
                return { deny: "Raw payload access failed" };
            }
            // Args access (host-verbatim)
            if (!ctx.args || ctx.args.CommandLine !== "echo hello") {
                return { deny: "Args access failed" };
            }
            return {
                ask: "Confirmed with GUI control",
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

    // 1. Rule with forceGui: true (camelCase, no snake_case alias)
    let rule_code1 = r#"
        export default function(ctx, sys) {
            return {
                ask: "Sensitive write operation",
                gui: false,
                forceGui: true
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

    // 2. Rule asking with forceGui: true
    let rule_code2 = r#"
        export default function(ctx, sys) {
            return {
                ask: "Forced popup rule",
                forceGui: true
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
            // forceGui is its own flag; it does not alias `gui`.
            gui: None,
            timeout: None,
            force_gui: Some(true),
        })
    );
}

#[test]
fn test_rule_logging_sys_log_api() {
    let _guard = TEST_LOG_MUTEX.lock().unwrap();
    // console.log / sys.log must not break evaluation. Disable the file
    // channel for tests (env is process-global; no other test logs).
    unsafe {
        std::env::set_var("AI_HOOK_LOG", "0");
    }
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            console.log("console debug line", ctx.platform);
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
    unsafe {
        std::env::remove_var("AI_HOOK_LOG");
    }
}

#[test]
fn test_log_arguments_are_js_coerced_not_strict() {
    let _guard = TEST_LOG_MUTEX.lock().unwrap();
    // console.log / sys.log accept non-string arguments exactly like plain
    // JS: numbers, booleans, null and objects are coerced, never rejected.
    // (A bare rquickjs String param is strict and threw TypeError on
    // console.log(123), failing the whole rule fail-closed.)
    unsafe {
        std::env::set_var("AI_HOOK_LOG", "0");
    }
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            console.log("count:", 123, true, null);
            console.log("obj:", { a: 1 });
            sys.log("warn", 456);
            return { deny: "reached-after-logging" };
        }
    "#;
    let ctx = ctx_for("node -v");
    let res = runner.execute_rule(&rule("logger-coerce", rule_code), &ctx);
    assert!(
        res.error.is_none(),
        "non-string log arguments must coerce, not throw: {:?}",
        res.error
    );
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "reached-after-logging".to_string()
        })
    );
    unsafe {
        std::env::remove_var("AI_HOOK_LOG");
    }
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
                return { deny: `Force push blocked on ${branch}` };
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
fn test_trailing_line_comment_does_not_swallow_handler_table() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    // No trailing newline after the comment: the appended handler table used
    // to be swallowed by the comment, silently dropping every export.
    let r = rule(
        "comment-tail",
        "export default function(ctx, sys) {
  if (ctx.cmd && /boom/.test(ctx.cmd)) {
    return { deny: \"hit\" };
  }
}
// trailing comment without newline",
    );
    let ctx = ctx_for("echo hi");
    let res = runner.execute_rule(&r, &ctx);
    assert!(res.error.is_none(), "error: {:?}", res.error);
    // Non-matching command: the handler falls through -> no opinion.
    assert!(res.decision.is_none(), "{:?}", res.decision);
    let ctx_hit = ctx_for("boom");
    let (dec, _) = runner.evaluate_all(std::slice::from_ref(&r), &ctx_hit, ErrorPolicy::FailClosed);
    assert!(
        matches!(&dec, HookDecision::Deny { reason } if reason == "hit"),
        "{dec:?}"
    );
}

#[test]
fn test_permission_request_uses_behavior_object_shape() {
    let ctx = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    assert_eq!(
        ctx.event_enum,
        ai_hook::protocol::HookEvent::PermissionRequest
    );
    let out = HookDecision::Deny {
        reason: "blocked by policy".to_string(),
    }
    .to_json_output(&ctx, None);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v["hookSpecificOutput"]["decision"]["behavior"],
        serde_json::json!("deny"),
        "{out}"
    );
    // Deny reasons carry the offending target line.
    assert!(
        v["hookSpecificOutput"]["decision"]["message"]
            .as_str()
            .unwrap()
            .starts_with("blocked by policy"),
        "{out}"
    );
    assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
}

#[test]
fn test_user_prompt_submit_confirm_cannot_fail_open() {
    // UPS has no protocol ask on any host; an unresolved confirm must fall
    // back to the ai-hook GUI path (here: no GUI -> fail-closed deny).
    let ctx = HookContext::parse(
        &serde_json::json!({"hook_event_name":"UserPromptSubmit","prompt":"/demo:x"}).to_string(),
    );
    let out = HookDecision::Confirm {
        reason: "r".to_string(),
        title: None,
        gui: None,
        timeout: None,
        force_gui: None,
    }
    .to_json_output(&ctx, None);
    assert!(
        !out.contains("\"ask\""),
        "UPS must never emit protocol ask: {out}"
    );
    assert!(out.contains("block") || out.contains("deny"), "{out}");
}

/// `ctx.can(cap)` 已删除:引擎在 `protocol::output::to_op` 里自动降级宿主
/// 不支持的决策,规则层不需要(也无人使用)手写能力查询。此测试锁定
/// "该 API 不存在" —— 若未来要恢复,必须先回答"为什么自动降级不够"。
#[test]
fn test_ctx_can_is_gone() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let r = rule(
        "can-check",
        r#"export default function(ctx, sys) {
            if (typeof ctx.can !== "undefined") return { deny: "ctx.can should be removed" };
            return { allow: true };
        }"#,
    );
    let ctx = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    let res = runner.execute_rule(&r, &ctx);
    assert!(res.error.is_none(), "error: {:?}", res.error);
    assert_eq!(
        res.decision,
        Some(HookDecision::Allow),
        "{:?}",
        res.decision
    );
}

#[test]
fn test_named_export_dispatches_by_event() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let dispatch = rule(
        "dispatch",
        r#"
export function PreToolUse(ctx, sys) {
    return { deny: "pre-hit" };
}
export function PostToolUse(ctx, sys) {
    return { inject: "post-hit" };
}
export default function(ctx, sys) {
    return { allow: true };
}"#,
    );

    // PreToolUse runs its own handler; the default export must not run.
    let pre = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    let (dec, _) = runner.evaluate_all(
        std::slice::from_ref(&dispatch),
        &pre,
        ErrorPolicy::FailClosed,
    );
    assert!(
        matches!(&dec, HookDecision::Deny { reason } if reason == "pre-hit"),
        "{dec:?}"
    );

    // PostToolUse runs its own handler.
    let post = HookContext::parse(
        &serde_json::json!({"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    let (dec, _) = runner.evaluate_all(
        std::slice::from_ref(&dispatch),
        &post,
        ErrorPolicy::FailClosed,
    );
    assert!(
        matches!(&dec, HookDecision::Modify(m) if m.inject.as_deref() == Some("post-hit")),
        "{dec:?}"
    );

    // An event with no named export falls back to the default export.
    let stop = HookContext::parse(&serde_json::json!({"hook_event_name":"Stop"}).to_string());
    let (dec, _) = runner.evaluate_all(&[dispatch], &stop, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
}

#[test]
fn test_undefined_from_handler_is_no_opinion() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let sloppy = rule(
        "sloppy",
        r#"export default function(ctx, sys) {
            if (ctx.cmd && /rm\s+-rf/.test(ctx.cmd)) {
                return { deny: "blocked" };
            }
        }"#,
    );
    let ctx = ctx_for("rm -rf /tmp/data");
    // A deny still short-circuits even though the fall-through path
    // returns undefined.
    let (dec, _) =
        runner.evaluate_all(std::slice::from_ref(&sloppy), &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::Deny { .. }), "{dec:?}");

    // A non-matching command yields undefined -> no opinion -> allow.
    let ctx_other = ctx_for("echo hi");
    let (dec2, _) = runner.evaluate_all(&[sloppy], &ctx_other, ErrorPolicy::FailClosed);
    assert_eq!(dec2, HookDecision::Allow);
}

#[test]
fn test_unknown_action_object_fails_closed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let unknown = rule(
        "unknown-action",
        r#"export default function(ctx, sys) {
            if (ctx.cmd && ctx.cmd.includes("op17")) {
                return { banana: true };
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
    // null / undefined are the documented "no opinion, move to the next
    // rule" and must keep passing under FailClosed (not a broken rule).
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
                return { deny: "cli-blocked" };
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
                return { deny: "status-blocked" };
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
    // 未建模事件上不存在协议 ask,能力矩阵把 Confirm 降级为 Deny;
    // 宿主最终看到的是 deny / block / block-behavior 之一,绝不是放行。
    assert!(
        stdout.contains("\"ask\"")
            || stdout.contains("\"deny\"")
            || stdout.contains("\"block\"")
            || stdout.contains("\"behavior\""),
        "unparsable payload must ask or deny: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// gui 三态语义:can_ask 宿主矩阵
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
    assert!(
        cc_yolo.can_ask(),
        "CC bypass 模式也应可 ask(hook ask 最高优先)"
    );

    // Codex:全模式均无协议 ask。官方(learn.chatgpt.com/docs/hooks)原文:
    // "`permissionDecision: "ask"` … are parsed but not supported yet. Codex
    // marks the hook run as failed, reports the error, and continues the tool
    // call." → 输出 ask 等于静默放行,故一律 false,confirm 走 GUI / fail-closed。
    let codex = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"never","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    assert!(
        !codex.can_ask(),
        "Codex 全模式均不可走协议 ask(输出 ask = fail open)"
    );
    let codex_yolo = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"bypassPermissions","tool_input":{"command":"ls"}}).to_string(),
    );
    assert!(!codex_yolo.can_ask(), "Codex bypass 模式不可 ask");

    // AGY:普通交互 force_ask 可;YOLO 不可
    let agy = HookContext::parse(
        &serde_json::json!({"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"is_yolo":false}).to_string(),
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

/// Codex 官方(`learn.chatgpt.com/docs/hooks`):`permissionDecision:"ask"` 被判
/// unsupported → 标记 hook run failed、报错、**继续执行工具调用**(fail open)。
/// 因此 Codex 上的 confirm 绝不能渲染成 ask;无 GUI 兜底时必须 fail-closed 拒绝,
/// 否则"请求确认"会变成"静默放行"。
#[test]
fn test_codex_confirm_never_outputs_ask() {
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
        !out.contains("\"ask\""),
        "Codex 上输出 ask = fail open(命令照常执行): {out}"
    );
    assert!(
        out.contains("\"permissionDecision\":\"deny\""),
        "Codex 上 confirm 无 GUI 兜底时应 fail-closed 拒绝: {out}"
    );
    assert!(
        out.contains("redis-cli flushall"),
        "拒绝原因应含完整命令: {out}"
    );
}

/// Codex Allow 必须是**空输出**:裸 `permissionDecision:"allow"`(无
/// updatedInput)同样被判为 unsupported,宿主会报 hook failed。
#[test]
fn test_codex_allow_outputs_nothing() {
    let ctx = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"}}).to_string(),
    );
    assert_eq!(
        HookDecision::Allow.to_json_output(&ctx, None),
        String::new()
    );
    // GUI 通过的 confirm 也走空输出(而不是 allow JSON)。
    assert_eq!(
        HookDecision::Confirm {
            reason: "r".to_string(),
            title: None,
            gui: None,
            timeout: None,
            force_gui: None,
        }
        .to_json_output(&ctx, Some(true)),
        String::new()
    );
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
    let (prog, arg) = if cfg!(windows) {
        ("cmd", "/c")
    } else {
        ("sh", "-c")
    };
    let exec_rule = rule(
        "test-exec",
        &format!(
            r#"export default function(ctx, sys) {{
            if (typeof sys.exec !== 'function') {{
                return {{ deny: "sys.exec missing" }};
            }}
            let res = sys.exec("{}", ["{}", "echo ai-hook-exec-ok"]);
            if (res.code !== 0 || !res.stdout.includes("ai-hook-exec-ok")) {{
                return {{ deny: "sys.exec failed: " + JSON.stringify(res) }};
            }}
            return null;
        }}"#,
            prog, arg
        ),
    );
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[exec_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
}

#[test]
fn test_sys_exec_script_file_auto_resolve() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let tmp = std::env::temp_dir().join(format!("ai-hook-script-resolve-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let (script_name, script_content) = if cfg!(windows) {
        (
            "test_run.bat",
            "@echo off\r\necho script-auto-resolve-ok %1\r\n",
        )
    } else {
        ("test_run.sh", "#!/bin/sh\necho script-auto-resolve-ok $1\n")
    };
    let script_path = tmp.join(script_name);
    std::fs::write(&script_path, script_content).expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).expect("meta").permissions();
        perms.set_mode(0o755);
        let _ = std::fs::set_permissions(&script_path, perms);
    }
    let script_str = script_path.to_string_lossy().replace('\\', "/");

    let rule_content = format!(
        r#"export default function(ctx, sys) {{
            let res = sys.exec("{}", ["test_arg"]);
            if (res.code !== 0 || !res.stdout.includes("script-auto-resolve-ok test_arg")) {{
                return {{ deny: "exec failed: " + JSON.stringify(res) }};
            }}
            return null;
        }}"#,
        script_str
    );

    let script_rule = rule("test-script-resolve", &rule_content);
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[script_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_sys_exec_sh_shebang_auto_resolve() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let tmp = std::env::temp_dir().join(format!("ai-hook-sh-shebang-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let script_path = tmp.join("test_sh.sh");
    std::fs::write(&script_path, "#!/bin/sh\necho sh-shebang-ok $1\n").expect("write sh");
    let script_str = script_path.to_string_lossy().replace('\\', "/");

    let rule_content = format!(
        r#"export default function(ctx, sys) {{
            let res = sys.exec("{}", ["arg_val"]);
            if (res.code !== 0 || !res.stdout.includes("sh-shebang-ok arg_val")) {{
                return {{ deny: "exec failed: " + JSON.stringify(res) }};
            }}
            return null;
        }}"#,
        script_str
    );

    let script_rule = rule("test-sh-shebang", &rule_content);
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[script_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_sys_exec_env_shebang_auto_resolve() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let tmp = std::env::temp_dir().join(format!("ai-hook-env-shebang-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let script_path = tmp.join("test_env.sh");
    std::fs::write(&script_path, "#!/usr/bin/env sh\necho env-shebang-ok $1\n")
        .expect("write env sh");
    let script_str = script_path.to_string_lossy().replace('\\', "/");

    let rule_content = format!(
        r#"export default function(ctx, sys) {{
            let res = sys.exec("{}", ["env_val"]);
            if (res.code !== 0 || !res.stdout.includes("env-shebang-ok env_val")) {{
                return {{ deny: "exec failed: " + JSON.stringify(res) }};
            }}
            return null;
        }}"#,
        script_str
    );

    let script_rule = rule("test-env-shebang", &rule_content);
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[script_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_sys_exec_complex_env_s_shebang() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let tmp = std::env::temp_dir().join(format!("ai-hook-env-s-shebang-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let script_path = tmp.join("test_env_s.sh");
    std::fs::write(
        &script_path,
        "#!/usr/bin/env -S sh\necho env-s-shebang-ok $1\n",
    )
    .expect("write env -S sh");
    let script_str = script_path.to_string_lossy().replace('\\', "/");

    let rule_content = format!(
        r#"export default function(ctx, sys) {{
            let res = sys.exec("{}", ["env_s_val"]);
            if (res.code !== 0 || !res.stdout.includes("env-s-shebang-ok env_s_val")) {{
                return {{ deny: "exec failed: " + JSON.stringify(res) }};
            }}
            return null;
        }}"#,
        script_str
    );

    let script_rule = rule("test-env-s-shebang", &rule_content);
    let ctx = ctx_for("test");
    let (dec, _) = runner.evaluate_all(&[script_rule], &ctx, ErrorPolicy::FailClosed);
    assert_eq!(dec, HookDecision::Allow);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_sys_http_api_exposed() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let http_rule = rule(
        "test-http",
        r#"export default function(ctx, sys) {
            if (typeof sys.http !== 'object' || typeof sys.http.get !== 'function' || typeof sys.http.post !== 'function') {
                return { deny: "sys.http missing" };
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
                return { deny: "余额为 100 元" };
            }
            return null;
        }"#,
    );
    let raw_payload = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "/ai:balance",
        "cwd": "C:\\"
    })
    .to_string();
    let ctx = HookContext::parse(&raw_payload);
    assert_eq!(ctx.prompt.as_deref(), Some("/ai:balance"));
    assert_eq!(ctx.event.as_deref(), Some("UserPromptSubmit"));

    let (dec, _) = runner.evaluate_all(&[prompt_rule], &ctx, ErrorPolicy::FailClosed);
    assert!(matches!(dec, HookDecision::Deny { ref reason } if reason == "余额为 100 元"));

    let out = dec.to_json_output(&ctx, None);
    assert_eq!(
        out,
        serde_json::json!({
            "decision": "block",
            "reason": "余额为 100 元"
        })
        .to_string()
    );
}

#[test]
fn test_post_tool_use_additional_context() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let post_rule = rule(
        "post-migration",
        r#"export default function(ctx, sys) {
            return { inject: "请注意迁移规范" };
        }"#,
    );
    let raw_payload = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "edit_file",
        "cwd": "C:\\"
    })
    .to_string();
    let ctx = HookContext::parse(&raw_payload);
    assert_eq!(ctx.event.as_deref(), Some("PostToolUse"));

    let (dec, _) = runner.evaluate_all(&[post_rule], &ctx, ErrorPolicy::FailClosed);
    assert!(
        matches!(dec, HookDecision::Modify(ref m) if m.inject.as_deref() == Some("请注意迁移规范"))
    );

    let out = dec.to_json_output(&ctx, None);
    assert_eq!(
        out,
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "请注意迁移规范"
            }
        })
        .to_string()
    );
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
    })
    .to_string();

    let tmp = std::env::temp_dir().join(format!("ai-hook-codex-yolo-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let rule_file = write_temp_rule(
        &tmp,
        "codex-guard.js",
        r#"export default function(ctx, sys) {
            return { ask: "confirm-danger" };
        }"#,
    );

    // 1. Without CODEX_DANGEROUSLY_SKIP_PERMISSIONS: Codex 仍无协议 ask(输出
    //    ask = fail open),且 --no-gui 关闭了弹窗兜底 → 必须 fail-closed 拒绝。
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args(["--no-gui", rule_file.to_string_lossy().as_ref()])
        .env_remove("CODEX_DANGEROUSLY_SKIP_PERMISSIONS")
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
        !stdout.contains("\"ask\""),
        "Codex must never emit ask (it fails open): {stdout}"
    );
    assert!(
        stdout.contains("\"permissionDecision\":\"deny\""),
        "Codex normal mode with --no-gui should fail-closed deny: {stdout}"
    );

    // 2. With CODEX_DANGEROUSLY_SKIP_PERMISSIONS=1: should output "deny"
    let mut child_yolo = Command::new(env!("CARGO_BIN_EXE_ai-hook"))
        .args(["--no-gui", rule_file.to_string_lossy().as_ref()])
        .env("CODEX_DANGEROUSLY_SKIP_PERMISSIONS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child_yolo
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out_yolo = child_yolo.wait_with_output().unwrap();
    let stdout_yolo = String::from_utf8_lossy(&out_yolo.stdout);
    assert!(
        stdout_yolo.contains("\"deny\""),
        "Codex yolo env should deny: {stdout_yolo}"
    );
}

// ---------------------------------------------------------------------------
// 官网文档对齐回归测试
// 依据:code.claude.com/docs/en/hooks、learn.chatgpt.com/docs/hooks、
//       geminicli.com/docs/hooks/reference/、antigravity.google/docs/hooks/
// ---------------------------------------------------------------------------

fn ctx_with_event(event: &str, extra: serde_json::Value) -> HookContext {
    let mut payload = serde_json::json!({ "hook_event_name": event });
    for (k, v) in extra.as_object().unwrap() {
        payload[k] = v.clone();
    }
    HookContext::parse(&payload.to_string())
}

/// Claude Code 把 PostToolUseFailure 列入顶层 `decision` 组，并文档化了
/// `hookSpecificOutput.additionalContext`；`updatedToolOutput` 只在 PostToolUse
/// 上有记载，不能借用到这里（否则宿主忽略 = fail open）。
#[test]
fn post_tool_use_failure_deny_uses_top_level_decision() {
    let ctx = ctx_with_event(
        "PostToolUseFailure",
        serde_json::json!({"tool_name":"Bash","tool_input":{"command":"npm test"}}),
    );
    assert_eq!(ctx.event_enum, HookEvent::PostToolUseFailure);
    let out = HookDecision::Deny {
        reason: "测试失败，请先看日志".to_string(),
    }
    .to_json_output(&ctx, None);
    assert!(
        out.contains("\"decision\":\"block\""),
        "PostToolUseFailure 应走顶层 decision block: {out}"
    );
    assert!(
        !out.contains("updatedToolOutput"),
        "updatedToolOutput 未在 PostToolUseFailure 上文档化: {out}"
    );
}

#[test]
fn post_tool_use_failure_inject_uses_additional_context() {
    let ctx = ctx_with_event(
        "PostToolUseFailure",
        serde_json::json!({"tool_name":"Bash","tool_input":{"command":"npm test"}}),
    );
    let out = HookDecision::Modify(Mutation {
        inject: Some("先检查 migration 是否未执行".to_string()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains("\"additionalContext\""),
        "PostToolUseFailure 的注入通道是 additionalContext: {out}"
    );
}

/// Gemini 有两个不同的“展示文本”通道：给模型的是
/// `hookSpecificOutput.additionalContext`（AfterTool / BeforeAgent /
/// SessionStart），`systemMessage` 是显示给用户的。
#[test]
fn gemini_after_tool_inject_targets_the_model() {
    let ctx = ctx_with_event(
        "AfterTool",
        serde_json::json!({"tool_name":"run_shell_command","tool_input":{"command":"ls"}}),
    );
    assert_eq!(ctx.platform, Platform::Gemini);
    let out = HookDecision::Modify(Mutation {
        inject: Some("该文件是生成的".to_string()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains("\"additionalContext\""),
        "AfterTool 注入应给模型(additionalContext): {out}"
    );
    assert!(
        !out.contains("systemMessage"),
        "systemMessage 是给用户看的，不是给模型的: {out}"
    );
}

/// Gemini 官方 BeforeTool 的 Output Fields 只列了 `decision` / `reason` /
/// `hookSpecificOutput.tool_input` / `continue`,**没有 additionalContext**。
/// 官方 `systemMessage` 的定义是 "Displayed immediately to the user in the
/// terminal" —— 是给用户的,不是模型上下文,不能拿它顶替 inject,否则规则
/// 作者会以为"注入给模型"生效了而实际模型什么都没收到。
/// 所以该事件没有 inject 通道,Modify 应降级为空输出(= allow)。
/// (SessionEnd / PreCompress 走 systemMessage 是另一回事:那两个事件的官方
///  Output Fields 本来就写的是 systemMessage。)
#[test]
fn gemini_before_tool_has_no_inject_channel() {
    let ctx = ctx_with_event(
        "BeforeTool",
        serde_json::json!({"tool_name":"run_shell_command","tool_input":{"command":"ls"}}),
    );
    let out = HookDecision::Modify(Mutation {
        inject: Some("注意当前是生产库".to_string()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    // 该事件官方 Output Fields 没有 additionalContext,塞进去会被忽略 ——
    // 所以不能伪造模型上下文。唯一真实存在的文本通道是
    // `systemMessage`(官方:"Displayed immediately to the user in the
    // terminal"),引擎降级到它并在 stderr 明确提示"不会进入模型上下文",
    // 让信息至少到达人,而不是被静默吞掉。
    assert!(
        out.contains(r#""systemMessage":"注意当前是生产库""#),
        "got: {out}"
    );
    assert!(
        !out.contains("additionalContext"),
        "BeforeTool 未文档化 additionalContext,不得输出: {out}"
    );
}

#[test]
fn gemini_after_tool_replace_output_uses_deny_with_reason() {
    let ctx = ctx_with_event(
        "AfterTool",
        serde_json::json!({"tool_name":"run_shell_command","tool_input":{"command":"ls"}}),
    );
    let out = HookDecision::Modify(Mutation {
        replace_output: Some(serde_json::json!("输出过大已省略")),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains("\"decision\":\"deny\"") && out.contains("输出过大已省略"),
        "AfterTool 用 decision deny + reason 替换回给模型的结果: {out}"
    );
}

/// `replaceOutput` 支持结构化对象:Claude Code 内置工具的 `updatedToolOutput`
/// 必须匹配工具的 output shape(Bash 是 `{stdout,stderr,interrupted,isImage}`),
/// 裸字符串会被官方忽略("a value that doesn't match the tool's output schema
/// is ignored")——只有对象值才能替换内置工具的结果。
#[test]
fn claude_code_post_tool_use_replace_output_accepts_structured_value() {
    let ctx = ctx_with_event(
        "PostToolUse",
        serde_json::json!({"tool_name":"Bash","tool_input":{"command":"ls"}}),
    );
    let out = HookDecision::Modify(Mutation {
        replace_output: Some(serde_json::json!({
            "stdout": "[redacted]",
            "stderr": "",
            "interrupted": false,
            "isImage": false
        })),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    // serde_json maps keys in sorted order; assert on key presence, not order.
    assert!(
        out.contains(r#""updatedToolOutput":"#)
            && out.contains(r#""stdout":"[redacted]""#)
            && out.contains(r#""stderr":""#)
            && out.contains(r#""interrupted":false"#)
            && out.contains(r#""isImage":false"#),
        "对象值必须原样嵌入 updatedToolOutput: {out}"
    );
    assert!(
        !out.contains(r#""reason""#),
        "替换语义不得降级成 decision:block 反馈: {out}"
    );
}

/// AGY PostInvocation 的官方 `terminationBehavior`(`force_continue` /
/// `terminate`)**刻意不建模**:Pre/PostInvocation 的 stdin 完全相同
/// (`invocationNum` + `initialNumSteps`)且不带事件名,`input.rs` 把两者统一
/// 归类为 `PreInvocation`;而官方 `PreInvocation` 输出只有 `injectSteps`,
/// 不支持 `terminationBehavior` —— 向其输出该字段是未定义行为。
/// 因此 AGY 的"keep going"只有 `Stop` 的 `decision:"continue"` 一条通道。
#[test]
fn antigravity_invocation_events_have_no_flow_channel() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "invocationNum": 1,
            "initialNumSteps": 3,
            "conversationId": "c"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.event_kind(), HookEvent::PreInvocation);
    // flow=false → keepGoing 降级为 allow(空操作),不输出宿主不支持的字段。
    let caps = ai_hook::protocol::capabilities(Platform::Antigravity, HookEvent::PreInvocation);
    assert!(caps.can_inject());
    assert!(!caps.can_flow());
    let out = HookDecision::KeepGoing {
        reason: "continue the loop".into(),
    }
    .to_json_output(&ctx, None);
    assert_eq!(out, r#"{"decision":"allow"}"#);

    // 对照:AGY Stop 拥有唯一的 flow 通道。
    let stop_caps = ai_hook::protocol::capabilities(Platform::Antigravity, HookEvent::Stop);
    assert!(stop_caps.can_flow());
}

/// Gemini 没有 Stop 事件；AfterAgent 的 `decision:"deny"` 会拒绝响应并强制重试，
/// 这才是 Gemini 上的 keep going。
#[test]
fn gemini_after_agent_keep_going_forces_a_retry() {
    let ctx = ctx_with_event("AfterAgent", serde_json::json!({"prompt":"hi"}));
    let out = HookDecision::KeepGoing {
        reason: "请先补上单元测试".to_string(),
    }
    .to_json_output(&ctx, None);
    assert!(
        out.contains("\"decision\":\"deny\"") && out.contains("请先补上单元测试"),
        "AfterAgent 的 keep going = decision deny + reason: {out}"
    );
}

/// Antigravity 官方 stdin 无事件名，但载荷形状可区分：
/// `executionNum`/`fullyIdle`/`terminationReason` → Stop；`invocationNum` → Invocation。
#[test]
fn antigravity_stop_is_classified_by_payload_shape() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "executionNum": 1,
            "terminationReason": "model_stop",
            "fullyIdle": true,
            "conversationId": "c1"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.event_enum, HookEvent::Stop);
    let out = HookDecision::KeepGoing {
        reason: "还没跑完测试".to_string(),
    }
    .to_json_output(&ctx, None);
    assert!(
        out.contains("\"decision\":\"continue\""),
        "AGY Stop 的 keep going 是 decision:continue: {out}"
    );
}

#[test]
fn antigravity_invocation_injects_steps() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "invocationNum": 3,
            "initialNumSteps": 10,
            "conversationId": "c1"
        })
        .to_string(),
    );
    assert_eq!(ctx.event_enum, HookEvent::PreInvocation);
    let out = HookDecision::Modify(Mutation {
        inject: Some("记得跑 lint".to_string()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains("injectSteps") && out.contains("ephemeralMessage"),
        "AGY 的注入通道是 injectSteps: {out}"
    );
}

/// Codex 把 `deny` + 空 reason 判为 invalid 并 fail open，因此空原因必须被兜底。
#[test]
fn empty_deny_reason_is_backfilled() {
    let ctx = HookContext::parse(
        &serde_json::json!({"turn_id":"t1","tool_name":"Bash","tool_input":{"command":"ls"}})
            .to_string(),
    );
    let out = HookDecision::Deny {
        reason: String::new(),
    }
    .to_json_output(&ctx, None);
    assert!(
        !out.contains("\"permissionDecisionReason\":\"\""),
        "Codex 上空 reason = invalid = fail open，必须补默认文案: {out}"
    );
}

/// UserPromptSubmit 分支必须与工具信封用同一套宿主识别（payload 特征优先）。
#[test]
fn user_prompt_submit_uses_the_shared_platform_detection() {
    let cb = ctx_with_event(
        "UserPromptSubmit",
        serde_json::json!({
            "prompt": "hi",
            "transcript_path": "/home/u/.codebuddy/projects/x.jsonl"
        }),
    );
    assert_eq!(
        cb.platform,
        Platform::CodeBuddy,
        "UPS 应识别出 CodeBuddy(transcript 路径特征)"
    );

    let wb = ctx_with_event(
        "UserPromptSubmit",
        serde_json::json!({
            "prompt": "hi",
            "transcript_path": "/home/u/.workbuddy/projects/x.jsonl"
        }),
    );
    assert_eq!(wb.platform, Platform::WorkBuddy, "UPS 应识别出 WorkBuddy");

    let cx = ctx_with_event(
        "UserPromptSubmit",
        serde_json::json!({"prompt": "hi", "turn_id": "t1"}),
    );
    assert_eq!(cx.platform, Platform::Codex);
}

/// fast path 的白名单前缀里有 `cat` / `head` / `tail` —— 正是读取凭据的命令。
/// 若不拦住凭据目标，"保护私钥读取"这类规则会在规则引擎之前就被旁路掉。
#[test]
fn fast_path_does_not_bypass_secret_reads() {
    for cmd in [
        "cat ~/.ssh/id_rsa",
        "cat ~/.aws/credentials",
        "head -n 5 .env",
        "cat id_ed25519",
        "cat server.pem",
    ] {
        let ctx = HookContext::parse(
            &serde_json::json!({
                "hook_event_name":"PreToolUse",
                "tool_name":"Bash",
                "tool_input":{"command":cmd}
            })
            .to_string(),
        );
        assert!(
            check_fast_path(&ctx).is_none(),
            "敏感读取不得走快速通道(否则读取类规则被旁路): {cmd}"
        );
    }

    // 普通只读命令仍应命中快速通道，不能被误伤。
    let plain = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"cat README.md"}
        })
        .to_string(),
    );
    assert!(
        check_fast_path(&plain).is_some(),
        "普通 cat 仍应命中快速通道"
    );
}

/// fast path 的 git 写操作防护:白名单前缀只放行真正的只读表面。
/// - `git remote -v add …`:git 的 parse_options 在子命令前消费 `-v`,
///   该命令真实执行 `add`(写 config)——不能用 ` -v` 前缀当只读判据;
/// - `git show -o <file>`:`-o` 是 `--output` 的短形式,写盘;
/// - `git log --oneline` 是高频只读命令,不得被 `-o` 检查误伤。
#[test]
fn fast_path_blocks_git_write_flags() {
    let writes = [
        "git remote -v add evil https://x.test/e.git",
        "git remote --verbose add evil https://x.test/e.git",
        "git remote add evil https://x.test/e.git",
        "git remote rename a b",
        "git remote set-url origin https://x.test/e.git",
        "git remote prune origin",
        "git remote update",
        "git show -o out.txt HEAD",
        "git show -oout.txt HEAD",
        "git diff --output=p.txt",
        "git log --output p.txt",
    ];
    for cmd in writes {
        let ctx = ctx_for(cmd);
        assert!(
            check_fast_path(&ctx).is_none(),
            "git 写操作不得走快速通道: {cmd}"
        );
    }

    let reads = [
        "git remote",
        "git remote -v",
        "git remote --verbose",
        "git remote show origin",
        "git remote get-url origin",
        "git log --oneline",
        "git diff HEAD~1",
        "git show HEAD",
    ];
    for cmd in reads {
        let ctx = ctx_for(cmd);
        assert!(
            check_fast_path(&ctx).is_some(),
            "git 只读命令应走快速通道: {cmd}"
        );
    }
}

/// 批量密钥通道:`cat /proc/self/environ` 一次性倒出全部环境变量;
/// `echo $OPENAI_API_KEY` / `echo %OPENAI_API_KEY%` 借 `echo ` 前缀
/// 打印密钥——都不得在规则引擎之前被放行。
#[test]
fn fast_path_blocks_bulk_secret_channels() {
    for cmd in [
        "cat /proc/self/environ",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "echo $OPENAI_API_KEY",
        "echo %OPENAI_API_KEY%",
        "cat ~/.config/gh/hosts.yml",
    ] {
        let ctx = ctx_for(cmd);
        assert!(
            check_fast_path(&ctx).is_none(),
            "批量密钥通道不得走快速通道: {cmd}"
        );
    }

    // 普通环境变量与普通路径不得被新 token 误伤。
    for cmd in ["echo $HOME", "echo %PATH%", "cat package.json"] {
        let ctx = ctx_for(cmd);
        assert!(
            check_fast_path(&ctx).is_some(),
            "普通只读命令应走快速通道: {cmd}"
        );
    }
}

/// Codex `apply_patch` 的目标藏在 patch 文本里。归一化层必须提取它,
/// 否则文件保护类规则只能各自去 ctx.rawInput 里做正则。
#[test]
fn apply_patch_target_is_extracted_from_patch_text() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "turn_id": "t1",
            "tool_name": "apply_patch",
            "tool_input": {
                "patchText": "*** Begin Patch\n*** Update File: ~/.codebuddy/local-plugins/x.js\n@@\n-old\n+new\n*** End Patch"
            }
        })
        .to_string(),
    );
    let file = ctx.file.expect("apply_patch should yield a file context");
    assert_eq!(
        file.action,
        FileAction::Edit,
        "Update File 是 edit: {file:?}"
    );
    assert!(
        file.path.as_deref().unwrap().ends_with("x.js"),
        "path 应来自 *** Update File: 行: {file:?}"
    );
    assert_eq!(file.paths.len(), 1);

    // Multi-file patch: extracts all target paths
    let multi = HookContext::parse(
        &serde_json::json!({
            "turn_id": "t1",
            "tool_name": "apply_patch",
            "tool_input": {
                "patchText": "*** Begin Patch\n*** Update File: src/main.rs\n@@\n*** Add File: config/.env\n+SECRET=1\n*** Delete File: old.tmp\n*** End Patch"
            }
        })
        .to_string(),
    );
    let multi_file = multi
        .file
        .expect("multi apply_patch should yield a file context");
    assert_eq!(multi_file.path.as_deref(), Some("src/main.rs"));
    assert_eq!(multi_file.action, FileAction::Edit);
    assert_eq!(
        multi_file.paths,
        vec![
            "src/main.rs".to_string(),
            "config/.env".to_string(),
            "old.tmp".to_string()
        ]
    );

    // Add File -> write, Delete File -> delete
    let add = HookContext::parse(
        &serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": {"patchText": "*** Begin Patch\n*** Add File: new.txt\n+content\n*** End Patch"}
        })
        .to_string(),
    );
    assert_eq!(add.file.unwrap().action, FileAction::Write);

    let del = HookContext::parse(
        &serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": {"patchText": "*** Begin Patch\n*** Delete File: old.txt\n*** End Patch"}
        })
        .to_string(),
    );
    assert_eq!(del.file.unwrap().action, FileAction::Delete);
}

/// ctx.event 现在是跨宿主一致的规范化名:Gemini 的 AfterTool 必须报告为
/// PostToolUse,原始拼写保留在 eventRaw。这是规则可移植性的核心。
#[test]
fn ctx_event_is_canonical_across_hosts() {
    let gemini = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "AfterTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "ls"}
        })
        .to_string(),
    );
    assert_eq!(gemini.platform, Platform::Gemini);
    assert_eq!(
        gemini.event_enum,
        HookEvent::AfterTool,
        "引擎内部仍保留精确事件"
    );

    let out = HookDecision::Modify(Mutation {
        inject: Some("ctx-event-check".to_string()),
        ..Mutation::default()
    })
    .to_json_output(&gemini, None);
    assert!(
        out.contains("\"hookEventName\":\"AfterTool\""),
        "渲染层仍用宿主原名: {out}"
    );

    // 规则侧(ctx.event)是规范化名 —— 用一条真实规则验证
    let runner = RuleRunner::new().expect("runner");
    let r = rule(
        "event-name-check",
        r#"export default function(ctx, sys) {
            if (ctx.event === "PostToolUse" && ctx.eventRaw === "AfterTool") {
                return { allow: true };
            }
            return { deny: "event names: " + ctx.event + " / " + ctx.eventRaw };
        }"#,
    );
    let res = runner.execute_rule(&r, &gemini);
    assert!(res.error.is_none(), "error: {:?}", res.error);
    assert_eq!(
        res.decision,
        Some(HookDecision::Allow),
        "{:?}",
        res.decision
    );
}

/// ctx.raw 改为访问时解析(lazy getter):payload 可能是 MB 级 transcript,
/// 而上下文每条规则都重建。规则读取 raw 的语义必须保持不变。
#[test]
fn ctx_raw_is_lazy_but_equivalent() {
    let runner = RuleRunner::new().expect("runner");
    let r = rule(
        "raw-lazy-check",
        r#"export default function(ctx, sys) {
            if (typeof ctx.raw !== "object") return { deny: "raw missing" };
            if (ctx.raw.tool_input && ctx.raw.tool_input.command === "ls") {
                return { allow: true };
            }
            return { deny: "unexpected raw: " + JSON.stringify(ctx.raw).slice(0, 80) };
        }"#,
    );
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"ls"}
        })
        .to_string(),
    );
    let res = runner.execute_rule(&r, &ctx);
    assert!(res.error.is_none(), "error: {:?}", res.error);
    assert_eq!(
        res.decision,
        Some(HookDecision::Allow),
        "{:?}",
        res.decision
    );
}

/// 具名导出必须按规范化事件名分派：Gemini 的宿主事件是 `AfterTool`，而规则按
/// 教程写的是 `export function PostToolUse(...)`。分派按 canonical 名进行，
/// 并向宿主原名拼写回退以保证鲁棒。
#[test]
fn named_handlers_dispatch_by_canonical_event_name() {
    let runner = RuleRunner::new().expect("runner");
    let r = rule(
        "canonical-dispatch",
        r#"
        export function PostToolUse(ctx, sys) {
            if (ctx.event === "PostToolUse" && ctx.eventRaw === "AfterTool") {
                return { inject: "canonical dispatch ok" };
            }
            return { deny: "mismatch: " + ctx.event + " / " + ctx.eventRaw };
        }
        "#,
    );
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"AfterTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"ls"}
        })
        .to_string(),
    );
    let res = runner.execute_rule(&r, &ctx);
    assert!(res.error.is_none(), "error: {:?}", res.error);
    match res.decision {
        Some(HookDecision::Modify(m)) => assert_eq!(
            m.inject.as_deref(),
            Some("canonical dispatch ok"),
            "AfterTool 宿主事件必须命中 PostToolUse 具名导出"
        ),
        other => panic!("expected Modify, got {:?}", other),
    }
}

/// Gemini CLI 的 shell 工具注册名是 `run_shell_command`(官方 Tools reference),
/// 必须归一为命令类工具,否则 Gemini 上所有命令规则与 fast path 全部失效。
/// `replace`(edit)/`list_directory`(list)/`read_many_files`(read)同理。
#[test]
fn gemini_tool_names_are_normalized() {
    let shell = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"git status --short"}
        })
        .to_string(),
    );
    assert_eq!(shell.platform, Platform::Gemini);
    assert_eq!(
        shell.cmd.as_deref(),
        Some("git status --short"),
        "run_shell_command 必须产出 ctx.cmd(否则 Gemini 命令规则全部失效)"
    );
    assert_eq!(check_fast_path(&shell), Some(HookDecision::Allow));

    let replace = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"BeforeTool",
            "tool_name":"replace",
            "tool_input":{"file_path":"a.rs","old_string":"x","new_string":"y"}
        })
        .to_string(),
    );
    let f = replace.file.expect("replace 应产出 file 上下文");
    assert_eq!(f.action, FileAction::Edit);
    assert_eq!(f.path.as_deref(), Some("a.rs"));

    let list = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"BeforeTool",
            "tool_name":"list_directory",
            "tool_input":{"dir_path":"src"}
        })
        .to_string(),
    );
    let f = list.file.expect("list_directory 应产出 file 上下文");
    assert_eq!(f.action, FileAction::List);
    assert_eq!(
        f.path.as_deref(),
        Some("src"),
        "dir_path 是 Gemini 的目录参数键"
    );

    let many = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"BeforeTool",
            "tool_name":"read_many_files",
            "tool_input":{"include":["*.rs"]}
        })
        .to_string(),
    );
    let f = many.file.expect("read_many_files 应产出 file 上下文");
    assert_eq!(f.action, FileAction::Read);
    assert!(f.path.is_none(), "read_many_files 无单一路径参数");
}

/// fast path 白名单前缀的写操作子命令不得旁路(设计声明:白名单只放行
/// "单条只读命令")。git branch 的删除/改名/拷贝/force、git show 的
/// --output 落盘、git remote 的 add/update/rename/prune 都会写本地状态。
#[test]
fn fast_path_rejects_git_write_subcommands() {
    let writes = [
        "git branch -d feat",
        "git branch -D feat",
        "git branch -dfeat",   // attached short value
        "git branch -vd feat", // combined short flags hide the -d
        "git branch -m old new",
        "git branch --move old new",
        "git branch -f main HEAD~1",
        "git branch --set-upstream-to=origin/main",
        "git branch --unset-upstream",
        "git branch --no-track",
        "git show --output=/tmp/pwned.txt HEAD",
        "git remote add origin https://example.com/x.git",
        "git remote update",
        "git remote rename a b",
        "git remote prune origin",
        "git remote set-url origin https://example.com/y.git",
    ];
    for cmd in writes {
        assert_eq!(
            check_fast_path(&ctx_for(cmd)),
            None,
            "git 写操作不得走快速通道: {cmd:?}"
        );
    }

    // 只读面必须仍然放行,不能被写检查误伤。
    let reads = [
        "git branch",
        "git branch -a",
        "git branch -av",
        "git branch --show-current",
        "git branch --merged",
        "git branch --list",
        "git remote",
        "git remote -v",
        "git remote show origin",
        "git remote get-url origin",
        "git show HEAD",
        "git diff --stat",
    ];
    for cmd in reads {
        assert_eq!(
            check_fast_path(&ctx_for(cmd)),
            Some(HookDecision::Allow),
            "git 只读命令仍应走快速通道: {cmd:?}"
        );
    }
}

/// 平台嗅探只允许使用宿主控制的字段(transcript_path):payload 内
/// 攻击者可控内容(如命令文本含 "codebuddy")不得翻转平台判定。
/// 同时:非工具类事件(Stop / SessionStart)也必须保留宿主身份,
/// 否则 CB 的 `continue:false` Stop 形态与宿主能力行全部丢失。
#[test]
fn platform_detection_uses_host_controlled_fields_only() {
    clear_codebuddy_env();
    unsafe {
        std::env::remove_var("OPENCODE_COMPAT");
    }

    // Claude Code 载荷,但命令文本里含 "codebuddy" —— 不得误判为 CodeBuddy。
    let cc = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"PreToolUse",
            "tool_name":"Bash",
            "tool_input":{"command":"echo codebuddy > workbuddy.txt"},
            "transcript_path":"/home/u/.claude/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(
        cc.platform,
        Platform::ClaudeCode,
        "payload 内容不得翻转平台"
    );

    // 无工具字段的 CC Stop 载荷:平台必须是 claude_code 而非 generic。
    let cc_stop = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"Stop",
            "session_id":"s1",
            "transcript_path":"/home/u/.claude/projects/t/abc.jsonl",
            "cwd":"/tmp",
            "stop_hook_active":false
        })
        .to_string(),
    );
    assert_eq!(cc_stop.platform, Platform::ClaudeCode);
    assert_eq!(cc_stop.event_enum, HookEvent::Stop);

    // Gemini SessionStart(transcript 位于 ~/.gemini)→ Gemini。
    let g_start = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"SessionStart",
            "session_id":"s2",
            "transcript_path":"/home/u/.gemini/tmp/s2/chats.json",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(g_start.platform, Platform::Gemini);

    // Codex 非turn 级事件(无 turn_id,transcript 位于 ~/.codex)→ Codex。
    let codex_end = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"SessionEnd",
            "session_id":"s3",
            "transcript_path":"/home/u/.codex/sessions/s3.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(codex_end.platform, Platform::Codex);

    // 无 hook_event_name 的未知形态 → Generic(尽力渲染)。
    let unknown = HookContext::parse(r#"{"foo":"bar"}"#);
    assert_eq!(unknown.platform, Platform::Generic);
}

/// CodeBuddy/WorkBuddy 官方文档:Stop 的"继续工作"与 UserPromptSubmit 的
/// 阻断都走 `{"continue": false}`(`decision:"block"` 已废弃)。
#[test]
fn codebuddy_stop_and_prompt_block_use_continue_false() {
    clear_codebuddy_env();
    unsafe {
        std::env::set_var("CODEBUDDY_HOST", "cli");
    }

    let cb_stop = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"Stop",
            "session_id":"s1",
            "transcript_path":"/home/u/.codebuddy/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(cb_stop.platform, Platform::CodeBuddy);
    let out = HookDecision::KeepGoing {
        reason: "keep working".into(),
    }
    .to_json_output(&cb_stop, None);
    // 官方 hooks.md 写的是 `continue: false`,但随包实现要求 blocking=true
    // (`SessionHookManager.executeStopHooks`: `!allowed && message && blocking`),
    // 而 `parseHookOutput` 只对 `decision:"block"` / permissionDecision deny /
    // 退出码 2 置 blocking —— `continue:false` 只是空操作,宿主照常停止。
    // 所以"继续"必须用 decision:"block"。
    assert_eq!(
        out, r#"{"decision":"block","reason":"keep working"}"#,
        "CB Stop keepGoing 必须是 decision:block: {out}"
    );

    let cb_ups = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"UserPromptSubmit",
            "prompt":"do things",
            "session_id":"s1",
            "transcript_path":"/home/u/.codebuddy/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(cb_ups.platform, Platform::CodeBuddy);
    let out = HookDecision::Deny {
        reason: "blocked".into(),
    }
    .to_json_output(&cb_ups, None);
    assert!(
        out.contains(r#""continue":false"#),
        "CB UPS 阻断必须是 continue:false(官方已废弃 decision:block): {out}"
    );

    // Claude Code 的同事件形态不变:UPS 阻断 = 顶层 decision:block,
    // Stop keepGoing = decision:block(CC 官方语义)。
    unsafe {
        std::env::remove_var("CODEBUDDY_HOST");
    }
    let cc_ups = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"UserPromptSubmit",
            "prompt":"do things",
            "session_id":"s1",
            "transcript_path":"/home/u/.claude/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Deny {
        reason: "blocked".into(),
    }
    .to_json_output(&cc_ups, None);
    assert!(
        out.contains(r#""decision":"block""#),
        "CC UPS 阻断仍是顶层 decision:block: {out}"
    );

    // CB/WB 的 **Stop + Deny**:官方 hooks.md 说 `decision:"block"` 已废弃、
    // 请用 `continue: false`,但按随包实现那会让"继续"变成空操作(见上面的
    // keepGoing 断言)。Stop 上 deny 与 keepGoing 本就同形,统一输出
    // `decision:"block"` —— 唯一能让宿主真的不停下来的形状。补上断言防回归。
    unsafe {
        std::env::set_var("CODEBUDDY_HOST", "cli");
    }
    let cb_stop_deny = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"Stop",
            "session_id":"s1",
            "transcript_path":"/home/u/.codebuddy/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Deny {
        reason: "do not stop yet".into(),
    }
    .to_json_output(&cb_stop_deny, None);
    assert!(
        out.contains(r#""decision":"block""#),
        "CB/WB Stop 上的阻断必须是 decision:block(continue:false 在实现里是空操作): {out}"
    );

    // PreCompact 不同:官方只记载退出码 2 阻止压缩,而 `continue: false` 是
    // CodeBuddy 通用的阻断形态(`parseHookOutput` 据此置 allowed=false,
    // 压缩流程随之中止),故这里用 continue:false。
    let cb_precompact = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"PreCompact",
            "trigger":"manual",
            "session_id":"s1",
            "transcript_path":"/home/u/.codebuddy/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Deny {
        reason: "keep the context".into(),
    }
    .to_json_output(&cb_precompact, None);
    assert!(
        out.contains(r#""continue":false"#),
        "CB/WB PreCompact 阻断必须是 continue:false: {out}"
    );
    unsafe {
        std::env::remove_var("CODEBUDDY_HOST");
    }
}

/// Codex 官方 PreCompact 节原文:
/// "If a matching PreCompact hook returns `continue: false`, Codex stops before
/// compacting."
/// 官方没有给该事件 `decision: "block"` 形态(那是 PreToolUse 的 legacy 形状
/// 加 UserPromptSubmit / Stop / SubagentStop 三处),输出它可能被忽略 → 压缩
/// 照常进行(门禁失效)。
#[test]
fn codex_precompact_deny_uses_continue_false() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "turn_id":"t1",
            "hook_event_name":"PreCompact",
            "trigger":"auto",
            "session_id":"s1",
            "transcript_path":"/home/u/.codex/sessions/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Codex);
    let out = HookDecision::Deny {
        reason: "do not compact".into(),
    }
    .to_json_output(&ctx, None);
    assert!(
        out.contains(r#""continue":false"#),
        "Codex PreCompact 阻断必须是 continue:false: {out}"
    );
    assert!(
        !out.contains(r#""decision":"block""#),
        "Codex PreCompact 未记载 decision:block,不该输出它: {out}"
    );
}

/// Claude Code 官方决策控制表原文:Stop / SubagentStop 走顶层
/// `decision:"block"`,且 "**also accept** hookSpecificOutput.additionalContext
/// for non-error feedback that continues the conversation"。
/// 也就是说这两个事件是有 inject 通道的 —— 不能把 inject 一律关掉。
#[test]
fn claude_code_stop_accepts_additional_context() {
    clear_codebuddy_env();
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"Stop",
            "session_id":"s1",
            "transcript_path":"/home/u/.claude/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::ClaudeCode);
    let out = HookDecision::Modify(Mutation {
        inject: Some("run the test suite before finishing".into()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains("additionalContext"),
        "CC Stop 支持 additionalContext 非错误反馈: {out}"
    );
    assert!(
        out.contains(r#""hookEventName":"Stop""#),
        "渲染必须回填真实事件名: {out}"
    );
}

/// `export  default`(export 与 default 之间多于一个空格)仍是合法的默认导出。
/// 早前实现按固定 14 字节窗口替换,多出的空白会把窗口错切进表达式,
/// 规则直接变成 SyntaxError。
#[test]
fn export_default_tolerates_extra_whitespace() {
    let runner = RuleRunner::new().expect("engine");
    let rule = rule(
        "ws",
        "export  default function(ctx) { return { deny: 'WS_OK ' + ctx.cmd }; }",
    );
    let ctx = ctx_for("echo hi");
    let (decision, results) = runner.evaluate_all(&[rule], &ctx, ErrorPolicy::FailClosed);
    assert!(results[0].error.is_none(), "err: {:?}", results[0].error);
    match decision {
        HookDecision::Deny { reason } => assert!(
            reason.contains("WS_OK echo hi"),
            "多空格 export default 应正常执行: {reason}"
        ),
        other => panic!("expected deny, got {other:?}"),
    }
}

/// Codex 的 unified exec 工具。官方 Tool coverage 表:
/// "Unified exec (`exec_command`) Yes Yes Match as Bash."
/// 不识别它的话 `ctx.cmd` 恒为 null,所有命令规则静默跳过 = 放行。
#[test]
fn codex_exec_command_is_a_command_tool() {
    for tool in ["exec_command", "Bash", "bash"] {
        let ctx = HookContext::parse(
            &serde_json::json!({
                "turn_id":"t1",
                "hook_event_name":"PreToolUse",
                "tool_name": tool,
                "tool_input":{"command":"rm -rf /tmp/x"},
                "cwd":"/tmp"
            })
            .to_string(),
        );
        assert_eq!(
            ctx.cmd.as_deref(),
            Some("rm -rf /tmp/x"),
            "{tool} 必须被识别为命令工具,否则命令规则全部失效: {:?}",
            ctx.cmd
        );
    }
}

/// SubagentStart 标注为 inject,必须真的可注入(此前枚举缺失,永远落 Other →
/// 能力静默归零)。
#[test]
fn subagent_start_inject_context() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "SubagentStart",
            "session_id":"s1",
            "transcript_path":"/home/u/.claude/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Modify(Mutation {
        inject: Some("ctx-note".into()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains("additionalContext"),
        "SubagentStart 必须支持 additionalContext 注入, got: {out}"
    );
    assert!(
        out.contains(r#""hookEventName":"SubagentStart""#),
        "渲染必须回填真实事件名: {out}"
    );
}

/// PostCompact **没有** inject 通道,三个宿主都不给:Claude Code 官方决策控制表把
/// PostCompact 与 Setup / Notification / SessionEnd 并列为
/// "None. No decision control.";Codex 官方只记载 `continue: false`;
/// CodeBuddy / WorkBuddy 官方没有 PostCompact 的决策控制节。
/// 因此它必须和"被过滤光的 Modify"一样降级为 Allow(空输出),
/// 而不是输出一个宿主会丢弃的空壳 JSON。
#[test]
fn postcompact_has_no_inject_channel_and_degrades_to_allow() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PostCompact",
            "session_id":"s1",
            "transcript_path":"/home/u/.claude/projects/t/abc.jsonl",
            "cwd":"/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Modify(Mutation {
        inject: Some("ctx-note".into()),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.is_empty(),
        "PostCompact 没有 inject 通道,必须降级为空输出(空 = allow), got: {out}"
    );
}

/// Setup 在能力矩阵中必须无任何通道:Claude Code 官方 Setup decision control
/// 原文是 "On every exit code, Claude Code discards a Setup hook's JSON output
/// fields, such as systemMessage, continue, and hookSpecificOutput.
/// additionalContext." —— 注入会被宿主直接丢弃,建模为可注入只会产出静默
/// 无效的规则;CodeBuddy 虽列出 Setup 事件但未记载任何输出通道,同样不开放。
/// 因此 Setup 上的 Modify 整体降级为 Allow(空输出),绝不输出空壳
/// `{"hookSpecificOutput":{...}}`。
#[test]
fn setup_event_has_no_inject_channel_and_degrades_to_allow() {
    for platform_dir in ["claude", "codebuddy"] {
        let transcript = format!("/home/u/.{platform_dir}/projects/t/abc.jsonl");
        let ctx = HookContext::parse(
            &serde_json::json!({
                "hook_event_name": "Setup",
                "session_id":"s1",
                "transcript_path": transcript,
                "cwd":"/tmp",
                "trigger":"init"
            })
            .to_string(),
        );
        assert_eq!(ctx.event_enum, HookEvent::Setup);
        let caps = ai_hook::protocol::capabilities(ctx.platform, HookEvent::Setup);
        assert!(
            !caps.can_inject() && !caps.gate,
            "Setup 不得开放任何能力: {ctx:?} caps={caps:?}"
        );

        // 规则在 Setup 上 inject:整体降级为 Allow(空输出),宿主视为无决策。
        let out = HookDecision::Modify(Mutation {
            inject: Some("ctx-note".into()),
            ..Mutation::default()
        })
        .to_json_output(&ctx, None);
        assert_eq!(
            out,
            String::new(),
            "Setup 注入必须降级为空输出(allow), got: {out}"
        );
    }
}

/// Gemini BeforeTool 官方支持 `hookSpecificOutput.tool_input`
/// (merge 覆盖模型参数)—— mutateInput 在 Gemini 上必须真的下发。
#[test]
fn gemini_before_tool_mutate_input_emits_tool_input_override() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name":"BeforeTool",
            "tool_name":"run_shell_command",
            "tool_input":{"command":"git push --force origin main"}
        })
        .to_string(),
    );
    let out = HookDecision::Modify(Mutation {
        mutate_input: Some(serde_json::json!({"command":"git push origin main"})),
        ..Mutation::default()
    })
    .to_json_output(&ctx, None);
    assert!(
        out.contains(r#""tool_input":{"command":"git push origin main"}"#),
        "Gemini BeforeTool 必须输出 hookSpecificOutput.tool_input: {out}"
    );
    assert!(out.contains(r#""hookEventName":"BeforeTool""#), "{out}");
}

/// sys.exec 必须有硬超时(JS 看门狗管不到原生阻塞调用),默认 10s,
/// 可用 opts.timeout 覆盖;超时终止进程组并返回 ok=false。
#[test]
fn sys_exec_times_out_hanging_child() {
    let runner = RuleRunner::new().expect("runner");
    let r = rule(
        "exec-timeout",
        r#"export default function(ctx, sys) {
            var t0 = Date.now();
            var res = sys.exec("node", ["-e", "setInterval(function(){}, 1000)"], { timeout: 400 });
            var elapsed = Date.now() - t0;
            if (res.ok) return { deny: "hanging child must not succeed" };
            if (res.code !== -1) return { deny: "expected code -1, got " + res.code };
            if (elapsed > 5000) return { deny: "exec did not respect the timeout: " + elapsed + "ms" };
            if (String(res.stderr).indexOf("timed out") < 0) return { deny: "missing timeout note: " + res.stderr };
            return { allow: true };
        }"#,
    );
    let ctx = ctx_for("git status");
    let res = runner.execute_rule(&r, &ctx);
    assert!(res.error.is_none(), "error: {:?}", res.error);
    assert_eq!(
        res.decision,
        Some(HookDecision::Allow),
        "exec 超时语义不符: {:?}",
        res.decision
    );
}

// ---------------------------------------------------------------------------
// 第四轮 review 的回归锁定(2026-09-07)
// ---------------------------------------------------------------------------

/// deny 绝不能被降级成空壳。
///
/// 曾经在 `caps.gate == false` 的事件上把 deny 转成
/// `Op::Modify { replace_output }`,而 `replace_output` 只被 post 事件消费 ——
/// 非 post 事件(Stop / SessionStart / PostCompact / 退化载荷)会渲染成
/// `{"hookSpecificOutput":{"hookEventName": …}}`,宿主按"无决策"处理 =
/// 静默放行。连"空 payload 必须拒绝"这条最基本的保证都因此失效。
/// 现在 deny 恒为 `Op::Deny`:每个渲染器对每个事件都有拒绝形态,
/// 宿主最多忽略它,绝不会反过来放行。
#[test]
fn deny_is_never_swallowed_into_an_empty_shell() {
    let cases: &[(&str, serde_json::Value)] = &[
        (
            "Stop",
            serde_json::json!({"hook_event_name": "Stop", "session_id": "s", "cwd": "/tmp"}),
        ),
        (
            "SessionStart",
            serde_json::json!({"hook_event_name": "SessionStart", "session_id": "s", "cwd": "/tmp", "source": "startup"}),
        ),
        (
            "PostCompact",
            serde_json::json!({"hook_event_name": "PostCompact", "session_id": "s", "cwd": "/tmp"}),
        ),
        (
            "SubagentStart",
            serde_json::json!({"hook_event_name": "SubagentStart", "session_id": "s", "cwd": "/tmp"}),
        ),
    ];
    for (name, payload) in cases {
        let ctx = HookContext::parse(&payload.to_string());
        let out = HookDecision::Deny {
            reason: "blocked by rule".into(),
        }
        .to_json_output(&ctx, None);
        // 空壳只含 hookEventName,原因必然丢失 —— 因此原因存在即证明未被吞。
        assert!(
            out.contains("blocked by rule"),
            "{name}: deny 被吞成无决策输出(宿主会静默放行): {out}"
        );
    }
}

/// Claude Code 的 PostToolUse 属于官方 Decision control 表的"顶层 decision"组,
/// 反馈应走 `decision:"block"` + `reason`;而 `updatedToolOutput` 要求"值必须
/// 匹配工具的 output shape",内置工具上的裸字符串会被忽略(官方原文:
/// "a value that doesn't match the tool's output schema is ignored")。
#[test]
fn claude_code_post_tool_use_deny_uses_top_level_block() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "npm run build" },
            "tool_response": { "stdout": "ok" },
            "session_id": "s",
            "transcript_path": "/u/.claude/projects/s.jsonl",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::ClaudeCode, "{ctx:?}");
    let out = HookDecision::Deny {
        reason: "needs review".into(),
    }
    .to_json_output(&ctx, None);
    assert!(
        out.contains(r#""decision":"block""#),
        "PostToolUse 的 deny 必须走顶层 decision:block: {out}"
    );
    assert!(
        !out.contains("updatedToolOutput"),
        "内置工具会忽略不匹配 output shape 的 updatedToolOutput: {out}"
    );
}

/// Gemini CLI 的写工具注册名是 `write_file`(官方 Tools reference),Antigravity
/// 的才是 `write_to_file`。只建模其中一个,另一个宿主上 `ctx.file` 恒为 null,
/// 所有基于文件写保护规则静默失效。
#[test]
fn gemini_write_file_and_antigravity_write_to_file_are_both_file_tools() {
    let gem = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "BeforeTool",
            "tool_name": "write_file",
            "tool_input": { "file_path": "/tmp/a.txt", "content": "x" },
            "session_id": "s",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    assert_eq!(gem.platform, Platform::Gemini, "{gem:?}");
    assert_eq!(
        gem.file.as_ref().map(|f| f.action),
        Some(FileAction::Write),
        "Gemini write_file 未被识别为写工具: {gem:?}"
    );
    assert_eq!(
        gem.file.as_ref().and_then(|f| f.path.as_deref()),
        Some("/tmp/a.txt")
    );

    let agy = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "write_to_file", "args": { "TargetFile": "/tmp/b.txt" } },
            "conversationId": "c"
        })
        .to_string(),
    );
    assert_eq!(agy.platform, Platform::Antigravity, "{agy:?}");
    assert_eq!(
        agy.file.as_ref().map(|f| f.action),
        Some(FileAction::Write),
        "Antigravity write_to_file 回归: {agy:?}"
    );
    assert_eq!(
        agy.file.as_ref().and_then(|f| f.path.as_deref()),
        Some("/tmp/b.txt")
    );
}

/// Claude Code 的 Stop 在任何环境下都不得输出 `continue: false`。
///
/// Claude Code 官方:`continue` 为 `false` 时 "Claude stops processing entirely
/// after the hook runs. Takes precedence over any event-specific decision
/// fields" —— 与 `keepGoing`("继续干活")完全相反。曾因把
/// `CODEBUDDY_SESSION_ID` / `CODEBUDDY_PROJECT_DIR` 当作平台判据,在装了
/// CodeBuddy 的机器上会把 Claude Code 误判成 CodeBuddy 并输出该形态。
#[test]
fn stop_keepgoing_never_emits_continue_false_for_claude_code() {
    // 故意注入 CodeBuddy 的会话级环境变量:它们不再参与平台判定。
    // SAFETY: 修复后没有任何代码读取这两个变量,故不影响并行中的其他用例。
    unsafe {
        std::env::set_var("CODEBUDDY_SESSION_ID", "sess-from-codebuddy");
        std::env::set_var("CODEBUDDY_PROJECT_DIR", "/tmp/proj");
    }
    let ctx = HookContext::parse(
        &serde_json::json!({
            "session_id": "s",
            "cwd": "/tmp",
            "hook_event_name": "Stop",
            "stop_hook_active": false
        })
        .to_string(),
    );
    assert_eq!(
        ctx.platform,
        Platform::ClaudeCode,
        "会话级 CODEBUDDY_* 变量不得影响平台判定: {ctx:?}"
    );
    let out = HookDecision::KeepGoing {
        reason: "run the tests first".into(),
    }
    .to_json_output(&ctx, None);
    assert!(
        out.contains(r#""decision":"block""#),
        "Stop 的 keepGoing 必须走 decision:block: {out}"
    );
    assert!(
        !out.contains("continue"),
        "Claude Code 上 continue:false 表示立即完全停止,与 keepGoing 语义相反: {out}"
    );
    unsafe {
        std::env::remove_var("CODEBUDDY_SESSION_ID");
        std::env::remove_var("CODEBUDDY_PROJECT_DIR");
    }
}

/// Antigravity 的 PreToolUse **没有**改参通道。
///
/// 官方三处来源(https://antigravity.google/docs/hooks/、
/// https://antigravity.google/docs/ide/hooks.md,SDK 版是 Python 装饰器与
/// JSON hook 协议无关)的 PreToolUse Output Fields 表都只有
/// `decision` / `reason` / `permissionOverrides` 三项。
/// 早前这里断言的 `overwrite` 字段无从证实。发出
/// `{"decision":"allow","overwrite":{…}}` 的后果是宿主按 allow 放行**原始**
/// 参数,规则却以为改写成功了 —— 比丢弃并告警危险得多,因此能力矩阵关闭
/// mutate_input,Modify 整体降级为 Allow(空输出)。
#[test]
fn antigravity_mutate_input_is_dropped() {
    let caps = ai_hook::protocol::capabilities(Platform::Antigravity, HookEvent::PreToolUse);
    assert!(
        !caps.can_mutate(),
        "AGY 官方输出字段表没有改参通道,能力矩阵不得开放 mutate_input"
    );

    let ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": "dangerous command" }
            },
            "conversationId": "test-conv"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.event_enum, HookEvent::PreToolUse);

    let decision = HookDecision::Modify(Mutation {
        inject: None,
        notify: None,
        mutate_input: Some(serde_json::json!({ "CommandLine": "echo safe" })),
        replace_output: None,
    });
    let out = decision.to_json_output(&ctx, None);
    // AGY 在 gating 事件上要求输出 `decision`,所以降级后是显式的 allow
    // (不是空串) —— 关键是绝不能带 `overwrite`:那会让宿主按 allow 放行
    // **原始**命令,而规则以为自己改写成功了。
    assert_eq!(out, r#"{"decision":"allow"}"#, "got: {out}");
    assert!(!out.contains("overwrite"), "got: {out}");
}

/// Claude Code 原生 View 工具名正确归一为 FileAction::Read
#[test]
fn claude_code_view_tool_is_recognized_as_read() {
    clear_codebuddy_env();
    let ctx = HookContext::parse(
        &serde_json::json!({
            "session_id": "sess-cc-view",
            "transcript_path": "/path/.claude/projects/sess.jsonl",
            "cwd": "/work",
            "hook_event_name": "PreToolUse",
            "tool_name": "View",
            "tool_input": { "file_path": "/work/src/secret.key" }
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::ClaudeCode);
    assert_eq!(ctx.tool_name, "View");
    assert_eq!(
        ctx.file,
        Some(FileContext {
            path: Some("/work/src/secret.key".into()),
            paths: vec!["/work/src/secret.key".into()],
            action: FileAction::Read
        })
    );
}

/// 支持 camelCase 命名 (toolInput, sessionId, permissionMode, turnId)
#[test]
fn camel_case_tool_input_and_session_id_parsed_correctly() {
    clear_codebuddy_env();
    let ctx = HookContext::parse(
        &serde_json::json!({
            "sessionId": "sess-camel",
            "transcriptPath": "/path/.codex/projects/sess.jsonl",
            "turnId": "turn-123",
            "cwd": "/camel-work",
            "permissionMode": "bypassPermissions",
            "hookEventName": "PreToolUse",
            "toolName": "Bash",
            "toolInput": { "command": "echo camel" }
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Codex);
    assert_eq!(ctx.tool_name, "Bash");
    assert_eq!(ctx.cmd.as_deref(), Some("echo camel"));
    assert_eq!(ctx.cwd, "/camel-work");
    assert!(ctx.is_yolo);
    assert_eq!(
        ctx.conversation.as_ref().and_then(|c| c.id.as_deref()),
        Some("sess-camel")
    );
    assert_eq!(
        ctx.conversation
            .as_ref()
            .and_then(|c| c.transcript_path.as_deref()),
        Some("/path/.codex/projects/sess.jsonl")
    );
}

// ---------------------------------------------------------------------------
// 2026-09-07 终审修复回归(M4 / M5h / 空 Modify)
// ---------------------------------------------------------------------------

/// M4:非工具事件(分支 4)此前把 conversation 与 model 置 None,SessionStart/
/// Stop 等事件上 ctx.session / ctx.model 恒为 null。官方 Common Input Fields
/// 携带 session_id/transcript_path,SessionStart 官方还带 model,必须还原。
#[test]
fn session_start_carries_session_and_model() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "SessionStart",
            "session_id": "sess-s",
            "transcript_path": "/u/.claude/projects/t/abc.jsonl",
            "cwd": "/w",
            "model": "claude-sonnet-4-5",
            "source": "startup"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::ClaudeCode);
    assert_eq!(ctx.event_enum, HookEvent::SessionStart);
    assert_eq!(
        ctx.conversation.as_ref().and_then(|c| c.id.as_deref()),
        Some("sess-s"),
        "SessionStart 必须携带会话 id"
    );
    assert_eq!(
        ctx.conversation
            .as_ref()
            .and_then(|c| c.transcript_path.as_deref()),
        Some("/u/.claude/projects/t/abc.jsonl")
    );
    assert_eq!(
        ctx.model.as_deref(),
        Some("claude-sonnet-4-5"),
        "SessionStart 官方带 model 字段,不得丢弃"
    );
}

/// M4 反向:无会话字段的 Stop 载荷 conversation 保持 None(不产生空对象)。
#[test]
fn stop_without_session_fields_keeps_conversation_null() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "Stop",
            "cwd": "/tmp",
            "stop_hook_active": false
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::ClaudeCode);
    assert!(ctx.conversation.is_none());
}

/// M5h:eventRaw 必须是宿主自己的拼写。Antigravity 的 stdin 没有事件名
/// (官方 schema 无 hook_event_name),因此 eventRaw 必须为 null —— 绝不把
/// 引擎按载荷形状推断出的名字回填成"宿主原始拼写"。ctx.event 仍保留推断名,
/// 供规则按规范事件分派。
#[test]
fn antigravity_event_raw_is_null_not_backfilled() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "ls" } },
            "conversationId": "c1"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.event_enum, HookEvent::PreToolUse);
    // 推断名只进 ctx.event(分派需要),不进 eventRaw。
    assert_eq!(ctx.event.as_deref(), Some("PreToolUse"));
    assert!(
        ctx.event_raw.is_none(),
        "AGY 无宿主事件名,eventRaw 不得回填推断名"
    );

    // 对照:真实携带事件名的宿主(CC 家族)eventRaw = 宿主拼写。
    let cc = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "ls" },
            "transcript_path": "/u/.claude/projects/x.jsonl"
        })
        .to_string(),
    );
    assert_eq!(cc.platform, Platform::ClaudeCode);
    assert_eq!(cc.event.as_deref(), Some("PostToolUse"));
    assert_eq!(cc.event_raw.as_deref(), Some("PostToolUse"));
}

/// 空 Modify(修饰项全部被能力矩阵裁剪)必须输出 Allow(空输出 / 显式 allow),
/// 绝不输出只含 hookEventName 的空壳 hookSpecificOutput —— 宿主要么读成
/// "无决策",要么在 schema 校验上失败;两者都不如一个明确的 allow。
#[test]
fn fully_dropped_modify_degrades_to_allow_not_empty_shell() {
    // CC 的 Setup:inject 被丢弃(官方丢弃 Setup 全部 JSON 输出)。
    let setup = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "Setup",
            "session_id": "s",
            "transcript_path": "/u/.claude/projects/x.jsonl",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Modify(Mutation {
        inject: Some("note".into()),
        ..Mutation::default()
    })
    .to_json_output(&setup, None);
    assert_eq!(out, String::new(), "空 Modify 必须降级为空输出: {out}");

    // AGY 的 PreToolUse 没有 inject 通道，仅有 inject 的 Modify 被丢弃后 → 显式 allow。
    let agy = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "run_command", "args": { "CommandLine": "ls" } },
            "conversationId": "c1"
        })
        .to_string(),
    );
    let out_agy = HookDecision::Modify(Mutation {
        inject: Some("note".into()),
        ..Mutation::default()
    })
    .to_json_output(&agy, None);
    assert!(
        out_agy.contains("\"decision\":\"allow\""),
        "AGY 空 Modify 必须显式 allow: {out_agy}"
    );
    assert!(!out_agy.contains("hookSpecificOutput"), "{out_agy}");
}

// ---------------------------------------------------------------------------
// ctx.mcp / ctx.web / ctx.search / ctx.agent 归一化(2026-09-07 新增)
// ---------------------------------------------------------------------------

/// MCP 工具名两种官方分隔符都要归一成 {server, tool}:Claude Code/Codex/
/// CodeBuddy 的 mcp__server__tool(双下划线)与 Gemini CLI 的
/// mcp_server_tool(单下划线)。
#[test]
fn mcp_tool_names_normalize_to_server_and_tool() {
    let parse_cc = |tool: &str| {
        HookContext::parse(
            &serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": { "query": "x" },
                "transcript_path": "/u/.claude/projects/t.jsonl"
            })
            .to_string(),
        )
    };
    let cc = parse_cc("mcp__github__search_repositories");
    assert_eq!(
        cc.mcp.as_ref().and_then(|m| m.server.as_deref()),
        Some("github")
    );
    assert_eq!(
        cc.mcp.as_ref().and_then(|m| m.tool.as_deref()),
        Some("search_repositories")
    );
    assert!(
        cc.cmd.is_none() && cc.file.is_none(),
        "MCP 工具不得落入 cmd/file"
    );

    // 双下划线短名形态(Codex 文档示例 mcp__fs__read)。
    let codex = parse_cc("mcp__fs__read");
    assert_eq!(
        codex.mcp.as_ref().and_then(|m| m.server.as_deref()),
        Some("fs")
    );
    assert_eq!(
        codex.mcp.as_ref().and_then(|m| m.tool.as_deref()),
        Some("read")
    );

    // Gemini CLI 单下划线形态。
    let gemini = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "BeforeTool",
            "tool_name": "mcp_github_search_repositories",
            "tool_input": { "query": "x" },
            "transcript_path": "/u/.gemini/tmp/s.json"
        })
        .to_string(),
    );
    assert_eq!(gemini.platform, Platform::Gemini);
    assert_eq!(
        gemini.mcp.as_ref().and_then(|m| m.server.as_deref()),
        Some("github")
    );
    assert_eq!(
        gemini.mcp.as_ref().and_then(|m| m.tool.as_deref()),
        Some("search_repositories")
    );
}

/// Web 工具归一:WebFetch/read_url_content → fetch(带 url);WebSearch/
/// search_web → search(带 query)。
#[test]
fn web_tools_normalize_to_fetch_and_search() {
    let fetch = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": { "url": "https://example.com/x", "prompt": "what is it" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let w = fetch.web.expect("WebFetch 必须产出 ctx.web");
    assert_eq!(w.action, WebAction::Fetch);
    assert_eq!(w.url.as_deref(), Some("https://example.com/x"));
    assert!(w.query.is_none());

    let search = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebSearch",
            "tool_input": { "query": "rust hooks" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let w = search.web.expect("WebSearch 必须产出 ctx.web");
    assert_eq!(w.action, WebAction::Search);
    assert_eq!(w.query.as_deref(), Some("rust hooks"));

    // Antigravity:read_url_content 参数键是 Url(search_web 是 query)。
    let agy = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "read_url_content", "args": { "Url": "https://a.b/c" } },
            "conversationId": "c"
        })
        .to_string(),
    );
    let w = agy.web.expect("AGY read_url_content 必须产出 ctx.web");
    assert_eq!(w.action, WebAction::Fetch);
    assert_eq!(w.url.as_deref(), Some("https://a.b/c"));
}

/// 代码搜索工具归一:Glob → {kind:"glob"},Grep/grep_search →
/// {kind:"grep"};路径与模式按各家参数键提取。
#[test]
fn code_search_tools_normalize() {
    let glob = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Glob",
            "tool_input": { "pattern": "**/*.rs", "path": "/w/src" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let s = glob.search.expect("Glob 必须产出 ctx.search");
    assert_eq!(s.kind, SearchKind::Glob);
    assert_eq!(s.pattern.as_deref(), Some("**/*.rs"));
    assert_eq!(s.path.as_deref(), Some("/w/src"));

    let grep = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_input": { "pattern": "TODO", "path": "/w" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    assert_eq!(grep.search.as_ref().map(|s| s.kind), Some(SearchKind::Grep));

    // Antigravity grep_search 的参数键是 SearchPath / Query。
    let agy = HookContext::parse(
        &serde_json::json!({
            "toolCall": { "name": "grep_search", "args": { "SearchPath": "/w", "Query": "secret" } },
            "conversationId": "c"
        })
        .to_string(),
    );
    let s = agy.search.expect("AGY grep_search 必须产出 ctx.search");
    assert_eq!(s.kind, SearchKind::Grep);
    assert_eq!(s.path.as_deref(), Some("/w"));
    assert_eq!(s.pattern.as_deref(), Some("secret"));
}

/// 委托类工具归一:Agent/spawn_agent → kind:"agent",Workflow →
/// "workflow";description/prompt 跨宿主键提取。
#[test]
fn delegation_tools_normalize() {
    let agent = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Agent",
            "tool_input": { "description": "review diff", "subagent_type": "review" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let a = agent.agent.expect("Agent 工具必须产出 ctx.agent");
    assert_eq!(a.kind, AgentKind::Agent);
    assert_eq!(a.description.as_deref(), Some("review diff"));

    let workflow = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Workflow",
            "tool_input": { "name": "nightly-release" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let a = workflow.agent.expect("Workflow 工具必须产出 ctx.agent");
    assert_eq!(a.kind, AgentKind::Workflow);
    assert_eq!(a.description.as_deref(), Some("nightly-release"));

    // Codex spawn_agent 形态。
    let codex = HookContext::parse(
        &serde_json::json!({
            "turn_id": "t1",
            "tool_name": "Agent",
            "tool_input": { "description": "fix tests", "prompt": "run and fix" },
            "transcript_path": "/u/.codex/s.jsonl"
        })
        .to_string(),
    );
    let a = codex.agent.expect("Codex Agent 必须产出 ctx.agent");
    assert_eq!(a.prompt.as_deref(), Some("run and fix"));
}

/// JS 规则内读取 ctx.mcp/ctx.web 的端到端形状(跨宿主规则写法)。
#[test]
fn mcp_and_web_views_reach_the_rule() {
    let runner = RuleRunner::new().expect("runner");
    let r = rule(
        "mcp-web-rule",
        r#"export default function(ctx, sys) {
            if (ctx.mcp && ctx.mcp.server === "github" && ctx.mcp.tool === "search_repositories") {
                return { deny: "mcp-hit" };
            }
            if (ctx.web && ctx.web.action === "fetch" && ctx.web.url && /^https:\/\/10\./.test(ctx.web.url)) {
                return { deny: "web-hit" };
            }
            if (ctx.search && ctx.search.kind === "grep") return { deny: "search-hit" };
            if (ctx.agent && ctx.agent.kind === "agent") return { deny: "agent-hit" };
            return null;
        }"#,
    );
    let mcp_ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__search_repositories",
            "tool_input": { "query": "x" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let (dec, _) = runner.evaluate_all(std::slice::from_ref(&r), &mcp_ctx, ErrorPolicy::FailClosed);
    assert!(
        matches!(&dec, HookDecision::Deny { reason } if reason == "mcp-hit"),
        "{dec:?}"
    );

    let web_ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": { "url": "https://10.0.0.5/secret" },
            "transcript_path": "/u/.claude/projects/t.jsonl"
        })
        .to_string(),
    );
    let (dec, _) = runner.evaluate_all(std::slice::from_ref(&r), &web_ctx, ErrorPolicy::FailClosed);
    assert!(
        matches!(&dec, HookDecision::Deny { reason } if reason == "web-hit"),
        "{dec:?}"
    );
}

/// 验证 RuleLoader 能正确识别并剥离 Windows 记事本等编辑器保存的 UTF-8 BOM 头
#[test]
fn test_loader_strips_utf8_bom() {
    let tmp = std::env::temp_dir().join(format!("ai-hook-bom-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let rule_path = tmp.join("bom_rule.js");

    // 写入包含 UTF-8 BOM (\u{feff} = EF BB BF) 的 JS 代码
    let content_with_bom = "\u{feff}export default function(ctx) { if (ctx.cmd === 'test-bom') return { deny: 'bom-detected' }; return null; }";
    std::fs::write(&rule_path, content_with_bom).expect("write rule with bom");

    let rules = ai_hook::engine::RuleLoader::load_rules(&[rule_path]);
    assert_eq!(rules.len(), 1);
    assert!(!rules[0].code.starts_with('\u{feff}'), "BOM 必须被成功剥离");

    let runner = RuleRunner::new().expect("runner");
    let ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": "test-bom" }
            }
        })
        .to_string(),
    );
    let (dec, _) = runner.evaluate_all(&rules, &ctx, ErrorPolicy::FailClosed);
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        matches!(&dec, HookDecision::Deny { reason } if reason == "bom-detected"),
        "带 BOM 的规则必须能被正确解析并执行: {dec:?}"
    );
}

#[test]
fn test_debug_log_collector_and_retention() {
    use ai_hook::engine::debug::{DebugCollector, RuleTrace, prune_old_log_files};

    let tmp = std::env::temp_dir().join(format!("ai-hook-debug-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let debug_file = tmp.join("test-debug.log");

    unsafe {
        std::env::set_var("AI_HOOK_DEBUG_FILE", debug_file.to_str().unwrap());
    }

    let raw_payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "npm test" },
        "session_id": "sess-dbg-1"
    })
    .to_string();

    let ctx = HookContext::parse(&raw_payload);
    let mut collector = DebugCollector::new();
    collector.raw_input = raw_payload.clone();
    collector.rules_evaluated.push(RuleTrace {
        id: "rule_test".to_string(),
        path: "/path/to/rule.js".to_string(),
        duration_ms: 1.25,
        decision: Some(serde_json::json!({ "type": "Allow" })),
        error: None,
    });
    collector.hit_rule = Some("rule_test".to_string());

    let decision = HookDecision::Allow;
    let rendered = decision.to_json_output(&ctx, None);

    collector.record("claude_code", Some(&ctx), &decision, &rendered, 0);

    // Assert the debug file was created and contains expected JSON
    assert!(debug_file.is_file(), "Debug log file must exist");
    let content = std::fs::read_to_string(&debug_file).expect("read debug log");
    assert!(!content.is_empty());

    let json_line: serde_json::Value =
        serde_json::from_str(content.lines().next().unwrap()).expect("parse debug jsonl");
    assert_eq!(json_line["raw_input"], raw_payload);
    assert_eq!(json_line["agent"], "claude_code");
    assert_eq!(json_line["type"], "debug");
    assert!(json_line["time"].is_string());
    assert!(json_line["date"].is_string());
    assert_eq!(json_line["context"]["platform"], "claude_code");
    assert_eq!(json_line["context"]["tool"], "Bash");
    assert_eq!(json_line["context"]["cmd"], "npm test");
    assert_eq!(json_line["rules_evaluated"].as_array().unwrap().len(), 1);
    assert_eq!(json_line["rules_evaluated"][0]["id"], "rule_test");
    assert_eq!(json_line["hit_rule"], "rule_test");
    assert_eq!(json_line["result"]["rule_decision"]["type"], "Allow");
    assert_eq!(json_line["result"]["exit_code"], 0);

    // Test retention: create 16 files with prefix, prune to 14
    let prefix = "ai-hook-debug-claude_code-";
    for i in 1..=16 {
        let f = tmp.join(format!("ai-hook-debug-claude_code-202609{:02}.log", i));
        let _ = std::fs::write(&f, "mock");
    }
    prune_old_log_files(&tmp, prefix, 14);
    let count = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .count();
    assert_eq!(count, 14, "Must retain exactly 14 files");

    unsafe {
        std::env::remove_var("AI_HOOK_DEBUG_FILE");
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_rule_log_and_debug_log_namespace_isolation_and_retention() {
    use ai_hook::engine::debug::prune_old_log_files;

    let tmp = std::env::temp_dir().join(format!("ai_hook_retention_iso_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    let rule_prefix = "ai-hook-claude_code-";
    let debug_prefix = "ai-hook-debug-claude_code-";

    // Create 16 rule logs and 16 debug logs
    for i in 1..=16 {
        let rf = tmp.join(format!("ai-hook-claude_code-202609{:02}.log", i));
        let df = tmp.join(format!("ai-hook-debug-claude_code-202609{:02}.log", i));
        let _ = std::fs::write(&rf, "rule log");
        let _ = std::fs::write(&df, "debug log");
    }

    // Pruning rule logs should ONLY prune rule logs, not debug logs
    prune_old_log_files(&tmp, rule_prefix, 14);

    let rule_count = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with(rule_prefix) && !name.contains("-debug-")
        })
        .count();
    let debug_count = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(debug_prefix))
        .count();

    assert_eq!(rule_count, 14, "Rule logs must be pruned to 14");
    assert_eq!(
        debug_count, 16,
        "Debug logs must not be affected by rule log pruning"
    );

    // Now prune debug logs
    prune_old_log_files(&tmp, debug_prefix, 14);
    let debug_count_after = std::fs::read_dir(&tmp)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(debug_prefix))
        .count();
    assert_eq!(debug_count_after, 14, "Debug logs must be pruned to 14");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_clean_all_logs_multi_category_and_dry_run() {
    use ai_hook::engine::debug::clean_all_logs;

    let tmp = std::env::temp_dir().join(format!("ai_hook_clean_all_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    // Create 18 rule logs for claude_code, 18 debug logs for claude_code, 18 inbound logs
    for i in 1..=18 {
        let _ = std::fs::write(
            tmp.join(format!("ai-hook-claude_code-202609{:02}.log", i)),
            "content",
        );
        let _ = std::fs::write(
            tmp.join(format!("ai-hook-debug-claude_code-202609{:02}.log", i)),
            "content",
        );
        let _ = std::fs::write(
            tmp.join(format!("ai-hook-inbound-202609{:02}.log", i)),
            "content",
        );
    }

    // Dry-run first with max_files = 14
    let report_dry = clean_all_logs(&tmp, 14, true);
    assert_eq!(report_dry.total_scanned, 18 * 3);
    assert_eq!(report_dry.files_deleted, 4 * 3); // 4 per category
    assert_eq!(report_dry.files_retained, 14 * 3); // 14 per category
    assert_eq!(report_dry.categories.len(), 3);

    // Verify all 54 files still exist because it was dry-run
    let actual_count_dry = std::fs::read_dir(&tmp).unwrap().flatten().count();
    assert_eq!(actual_count_dry, 54);

    // Actual execution
    let report_real = clean_all_logs(&tmp, 14, false);
    assert_eq!(report_real.files_deleted, 4 * 3);
    assert_eq!(report_real.files_retained, 14 * 3);

    // Verify directory has exactly 14 * 3 = 42 files remaining
    let actual_count_real = std::fs::read_dir(&tmp).unwrap().flatten().count();
    assert_eq!(actual_count_real, 42);

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_all_logs_contain_datetime_single_line_agent_type() {
    let _guard = TEST_LOG_MUTEX.lock().unwrap();
    let tmp = std::env::temp_dir().join(format!("ai_hook_log_format_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    let rule_log_file = tmp.join("test-rule.log");
    unsafe {
        std::env::set_var("AI_HOOK_LOG_FILE", rule_log_file.to_str().unwrap());
        std::env::set_var("AI_HOOK_LOG", "1");
    }

    // 1. Trigger rule log
    let runner = RuleRunner::new().expect("init runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            sys.log("info", "test message 1");
            return null;
        }
    "#;
    let ctx = ctx_for("git status");
    let _ = runner.execute_rule(&rule("logger-fmt-test", rule_code), &ctx);

    assert!(rule_log_file.is_file());
    let rule_content = std::fs::read_to_string(&rule_log_file).unwrap();
    let non_empty_lines: Vec<&str> = rule_content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(!non_empty_lines.is_empty(), "Rule log must not be empty");

    // Verify every line is valid single-line JSONL with timestamp fields
    for line in &non_empty_lines {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("Every line in rule log must be single-line JSONL");
        assert!(v["time"].is_string());
        assert!(v["date"].is_string());
        assert!(v["ts"].is_number());
    }

    let target_line = non_empty_lines
        .iter()
        .find(|l| l.contains("test message 1"))
        .expect("Should contain our test message");
    let rule_json: serde_json::Value = serde_json::from_str(target_line).unwrap();
    assert_eq!(rule_json["type"], "rule");
    assert_eq!(rule_json["agent"], "antigravity");
    assert!(rule_json["time"].is_string());
    assert!(rule_json["date"].is_string());
    assert!(rule_json["ts"].is_number());
    assert_eq!(rule_json["level"], "info");
    assert_eq!(rule_json["msg"], "test message 1");

    unsafe {
        std::env::remove_var("AI_HOOK_LOG_FILE");
        std::env::remove_var("AI_HOOK_LOG");
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_install_command_lifecycle_and_force_flag() {
    let tmp = std::env::temp_dir().join(format!(
        "ai_hook_test_install_cli_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&tmp);

    let bin_path = env!("CARGO_BIN_EXE_ai-hook");
    let exe_name = if cfg!(windows) {
        "ai-hook.exe"
    } else {
        "ai-hook"
    };
    let target_file = tmp.join(exe_name);

    // 1. First install without -f into empty directory: succeeds
    let out1 = Command::new(bin_path)
        .args(["install", "-t", &tmp.to_string_lossy()])
        .output()
        .expect("Failed to run install");
    assert!(out1.status.success(), "First install should succeed");
    assert!(
        target_file.exists(),
        "Target file should exist after install"
    );

    // Verify the newly installed binary is functional
    let ver_out = Command::new(&target_file)
        .arg("--version")
        .output()
        .expect("Installed binary should execute");
    assert!(ver_out.status.success());
    let ver_str = String::from_utf8_lossy(&ver_out.stdout);
    assert!(
        ver_str.contains("ai-hook"),
        "Version output should contain ai-hook: {ver_str}"
    );

    // 2. Second install without -f: detects existing file and hints -f/--force
    let out2 = Command::new(bin_path)
        .args(["install", "-t", &tmp.to_string_lossy()])
        .output()
        .expect("Failed to run install without force");
    assert!(out2.status.success());
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        stdout2.contains("force") || stdout2.contains("-f"),
        "Second install without force should advise using -f / --force: {stdout2}"
    );

    // 3. Force install with -f: succeeds and overwrites safely
    let out3 = Command::new(bin_path)
        .args(["install", "-f", "-t", &tmp.to_string_lossy()])
        .output()
        .expect("Failed to run install with force");
    assert!(out3.status.success(), "Force install should succeed");
    assert!(target_file.exists());

    // 4. Force install with --force: succeeds
    let out4 = Command::new(bin_path)
        .args(["install", "--force", "-t", &tmp.to_string_lossy()])
        .output()
        .expect("Failed to run install with --force");
    assert!(
        out4.status.success(),
        "Force install with --force should succeed"
    );
    assert!(target_file.exists());

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_install_binary_file_safety_rollback_on_broken_source() {
    use ai_hook::install::{InstallOutcome, install_binary_file};
    let tmp = std::env::temp_dir().join(format!(
        "ai_hook_test_install_rollback_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&tmp);

    let bin_path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_ai-hook"));
    let exe_name = if cfg!(windows) {
        "ai-hook.exe"
    } else {
        "ai-hook"
    };
    let target_file = tmp.join(exe_name);

    // 1. Initial successful install
    let res1 = install_binary_file(&bin_path, &tmp, false);
    assert_eq!(res1, Ok(InstallOutcome::Installed(target_file.clone())));
    assert!(target_file.exists());

    // Record original valid binary size
    let orig_len = std::fs::metadata(&target_file).unwrap().len();

    // 2. Prepare a corrupted non-executable dummy file
    let broken_src = tmp.join("corrupted_payload.bin");
    std::fs::write(&broken_src, b"THIS_IS_NOT_A_VALID_AI_HOOK_BINARY").unwrap();

    // 3. Attempt force install with the broken source file
    let res_broken = install_binary_file(&broken_src, &tmp, true);
    assert!(res_broken.is_err(), "Install of corrupted binary must fail");
    let err = res_broken.unwrap_err();
    assert!(
        err.contains("回滚") || err.contains("mismatch") || err.contains("大小不一致"),
        "Failure must trigger safety rollback: {err}"
    );

    // 4. Verify that target file was restored and still functions!
    assert!(target_file.exists(), "Target file must be restored");
    let restored_len = std::fs::metadata(&target_file).unwrap().len();
    assert_eq!(
        orig_len, restored_len,
        "File size must match original before failed install"
    );

    let test_run = Command::new(&target_file)
        .arg("--version")
        .output()
        .unwrap();
    assert!(
        test_run.status.success(),
        "Restored binary must still be executable"
    );
    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("ai-hook"),
        "Restored binary must pass self-check: {stdout}"
    );

    // 5. Verify temporary backups are cleaned up
    let old_backups: Vec<_> = std::fs::read_dir(&tmp)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".old."))
        .collect();
    assert!(
        old_backups.is_empty(),
        "Temporary backup files should be cleaned up on rollback"
    );

    // Clean up
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_cli_unrecognized_subcommand_error_reporting() {
    let bin_path = env!("CARGO_BIN_EXE_ai-hook");
    let out = Command::new(bin_path)
        .arg("totally_nonexistent_command_xyz")
        .output()
        .expect("Failed to run ai-hook");

    assert_eq!(
        out.status.code(),
        Some(2),
        "Unrecognized command should exit with code 2"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("未识别的命令") || stderr.contains("unrecognized subcommand"),
        "Stderr should clearly report unrecognized command: {stderr}"
    );
    assert!(
        stderr.contains("totally_nonexistent_command_xyz"),
        "Stderr should mention the exact unknown command name: {stderr}"
    );
    assert!(
        stderr.contains("--help"),
        "Stderr should advise user to run --help: {stderr}"
    );
}

#[test]
fn test_cli_unknown_arguments_are_safely_ignored() {
    let bin_path = env!("CARGO_BIN_EXE_ai-hook");

    // 1. Unknown options with -V/--version: unknown options are ignored and version succeeds
    let out1 = Command::new(bin_path)
        .args(["--some-unknown-flag", "--session-id=test1234", "-x", "-V"])
        .output()
        .expect("Failed to run with unknown arguments");
    assert!(
        out1.status.success(),
        "Unknown flags should be safely ignored"
    );
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    assert!(
        stdout1.contains("ai-hook"),
        "Version output expected: {stdout1}"
    );

    // 2. Unknown options inside a subcommand (e.g. version)
    let out2 = Command::new(bin_path)
        .args(["version", "--unknown-flag", "--foo=bar"])
        .output()
        .expect("Failed to run version with unknown arguments");
    assert!(
        out2.status.success(),
        "Unknown flags in subcommand should be ignored"
    );
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        stdout2.contains("ai-hook"),
        "Version output expected: {stdout2}"
    );

    // 3. Subcommand aliases: help, version
    let out_help = Command::new(bin_path)
        .arg("help")
        .output()
        .expect("Failed to run help subcommand");
    assert!(out_help.status.success(), "'ai-hook help' should succeed");
}

#[test]
fn test_cross_platform_args_alias_enrichment() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    // Test Antigravity payload (has CommandLine, TargetFile, CodeContent)
    let agy_ctx = HookContext::parse(
        &serde_json::json!({
            "conversationId": "c1",
            "toolCall": {
                "name": "run_command",
                "args": {
                    "CommandLine": "echo 123",
                    "TargetFile": "/app/test.php",
                    "CodeContent": "<?php echo 1;"
                }
            }
        })
        .to_string(),
    );

    let script = rule(
        "test-alias",
        r#"export default function(ctx) {
            // Check cross-platform aliases
            if (ctx.args.command === "echo 123" &&
                ctx.args.file_path === "/app/test.php" &&
                ctx.args.content === "<?php echo 1;") {
                return { deny: "alias_ok" };
            }
            return null;
        }"#,
    );

    let res = runner.execute_rule(&script, &agy_ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "alias_ok".to_string()
        })
    );
}

#[test]
fn test_fast_path_sensitive_tokens_extension() {
    use ai_hook::fast_path::check_fast_path;

    // Commands targeting newly protected sensitive tokens must NOT hit fast path
    let tests = [
        "cat ~/.npmrc",
        "head -n 10 ~/.dockercfg",
        "cat .docker/config.json",
        "cat /etc/ssl/private_key.pem",
        "cat app_secret_key.txt",
    ];

    for cmd in tests {
        let ctx = HookContext::parse(
            &serde_json::json!({
                "tool_name": "Bash",
                "tool_input": { "command": cmd }
            })
            .to_string(),
        );
        assert!(
            check_fast_path(&ctx).is_none(),
            "Command '{cmd}' must be rejected by fast path due to sensitive tokens"
        );
    }
}

// =========================================================================
// Sanitized Authentic Payload Fixtures Captured from Real Agent Debug Logs
// =========================================================================

#[test]
fn test_real_fixture_antigravity_run_command() {
    clear_codebuddy_env();
    // Sanitized authentic payload from ai-hook-debug-antigravity-20260907.log
    let raw = r#"{
        "artifactDirectoryPath": "C:/Users/test_developer/.gemini/antigravity-cli/brain/11111111-2222-3333-4444-555555555555",
        "conversationId": "11111111-2222-3333-4444-555555555555",
        "modelName": "gemini-3.8-flash-high",
        "stepIdx": 2,
        "toolCall": {
            "args": {
                "CommandLine": "git status",
                "Cwd": "C:\\Users\\test_developer\\workspace",
                "WaitMsBeforeAsync": 5000,
                "toolAction": "Check git repository status",
                "toolSummary": "Run git status"
            },
            "name": "run_command"
        },
        "transcriptPath": "C:/Users/test_developer/.gemini/antigravity-cli/brain/11111111-2222-3333-4444-555555555555/.system_generated/logs/transcript_full.jsonl",
        "workspacePaths": ["C:/Users/test_developer/workspace"]
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.event_enum, HookEvent::PreToolUse);
    assert_eq!(ctx.tool_name, "run_command");
    assert_eq!(ctx.cmd.as_deref(), Some("git status"));
    assert_eq!(ctx.model.as_deref(), Some("gemini-3.8-flash-high"));
    assert_eq!(ctx.cwd, "C:\\Users\\test_developer\\workspace");
    assert_eq!(
        ctx.conversation.as_ref().and_then(|c| c.id.as_deref()),
        Some("11111111-2222-3333-4444-555555555555")
    );

    // Rule execution asserting cross-platform alias and properties
    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "agy-cmd-test",
        r#"export default function(ctx) {
            if (ctx.cmd === "git status" && ctx.args.command === "git status") {
                return { allow: true };
            }
            return { deny: "mismatch" };
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert_eq!(res.decision, Some(HookDecision::Allow));
}

#[test]
fn test_real_fixture_antigravity_write_to_file() {
    clear_codebuddy_env();
    let raw = r#"{
        "artifactDirectoryPath": "C:/Users/test_developer/.gemini/antigravity-cli/brain/11111111-2222-3333-4444-555555555555",
        "conversationId": "11111111-2222-3333-4444-555555555555",
        "modelName": "gemini-3.8-flash-high",
        "stepIdx": 174,
        "toolCall": {
            "args": {
                "CodeContent": "package main\n\nfunc main() {}\n",
                "Description": "Creating entrypoint file",
                "Overwrite": true,
                "TargetFile": "C:\\Users\\test_developer\\workspace\\main.go",
                "toolAction": "Writing entrypoint file",
                "toolSummary": "Create main.go"
            },
            "name": "write_to_file"
        },
        "transcriptPath": "C:/Users/test_developer/.gemini/antigravity-cli/brain/11111111-2222-3333-4444-555555555555/.system_generated/logs/transcript_full.jsonl",
        "workspacePaths": ["C:/Users/test_developer/workspace"]
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.tool_name, "write_to_file");
    let f = ctx.file.as_ref().expect("file context expected");
    assert_eq!(f.action, FileAction::Write);
    assert_eq!(
        f.path.as_deref(),
        Some("C:\\Users\\test_developer\\workspace\\main.go")
    );
    assert_eq!(
        f.paths,
        vec!["C:\\Users\\test_developer\\workspace\\main.go".to_string()]
    );

    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "agy-write-test",
        r#"export default function(ctx) {
            if (ctx.file.action === "write" && ctx.args.file_path === "C:\\Users\\test_developer\\workspace\\main.go") {
                return { allow: true };
            }
            return { deny: "mismatch" };
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert_eq!(res.decision, Some(HookDecision::Allow));
}

#[test]
fn test_real_fixture_antigravity_replace_file_content() {
    clear_codebuddy_env();
    let raw = r#"{
        "artifactDirectoryPath": "C:/Users/test_developer/.gemini/antigravity-cli/brain/11111111-2222-3333-4444-555555555555",
        "conversationId": "11111111-2222-3333-4444-555555555555",
        "modelName": "gemini-3.8-flash-high",
        "stepIdx": 272,
        "toolCall": {
            "args": {
                "AllowMultiple": false,
                "Description": "Updating configuration comment",
                "EndLine": 5,
                "Instruction": "Update comment line",
                "ReplacementContent": "// configuration updated",
                "StartLine": 5,
                "TargetContent": "// configuration default",
                "TargetFile": "C:\\Users\\test_developer\\workspace\\config.go",
                "toolAction": "Editing configuration",
                "toolSummary": "Edit config.go"
            },
            "name": "replace_file_content"
        }
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.tool_name, "replace_file_content");
    let f = ctx.file.expect("file context expected");
    assert_eq!(f.action, FileAction::Edit);
    assert_eq!(
        f.path.as_deref(),
        Some("C:\\Users\\test_developer\\workspace\\config.go")
    );
}

#[test]
fn test_real_fixture_antigravity_view_file_sensitive_path() {
    clear_codebuddy_env();
    let raw = r#"{
        "conversationId": "conv-test",
        "toolCall": {
            "name": "view_file",
            "args": {
                "AbsolutePath": "C:/Users/test_user/.ssh/id_rsa"
            }
        }
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.tool_name, "view_file");
    let f = ctx.file.expect("file context expected");
    assert_eq!(f.action, FileAction::Read);
    assert_eq!(f.path.as_deref(), Some("C:/Users/test_user/.ssh/id_rsa"));
}

#[test]
fn test_real_fixture_claude_code_user_prompt_submit() {
    clear_codebuddy_env();
    let raw = r#"{
        "session_id": "22222222-3333-4444-5555-666666666666",
        "transcript_path": "C:\\Users\\test_developer\\.claude\\projects\\test-proj\\22222222-3333-4444-5555-666666666666.jsonl",
        "cwd": "C:\\Users\\test_developer\\workspace",
        "prompt_id": "33333333-4444-5555-6666-777777777777",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "/ai:balance",
        "effort": "low"
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::ClaudeCode);
    assert_eq!(ctx.event_enum, HookEvent::UserPromptSubmit);
    assert_eq!(ctx.prompt.as_deref(), Some("/ai:balance"));
    assert_eq!(ctx.permission_mode.as_deref(), Some("default"));
    assert_eq!(
        ctx.conversation.as_ref().and_then(|c| c.id.as_deref()),
        Some("22222222-3333-4444-5555-666666666666")
    );

    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "intercept-prompt",
        r#"export default function(ctx) {
            if (ctx.event === "UserPromptSubmit" && ctx.prompt === "/ai:balance") {
                return { deny: "Balance quota: $100.00" };
            }
            return null;
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "Balance quota: $100.00".to_string()
        })
    );
}

#[test]
fn test_real_fixture_claude_code_pre_tool_use_bash_yolo() {
    clear_codebuddy_env();
    let raw = r#"{
        "session_id": "22222222-3333-4444-5555-666666666666",
        "transcript_path": "C:\\Users\\test_developer\\.claude\\projects\\test-proj\\22222222-3333-4444-5555-666666666666.jsonl",
        "cwd": "C:\\Users\\test_developer\\workspace",
        "prompt_id": "33333333-4444-5555-6666-777777777777",
        "permission_mode": "bypassPermissions",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "rm -rf /",
            "description": "Clean root files"
        }
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::ClaudeCode);
    assert_eq!(ctx.event_enum, HookEvent::PreToolUse);
    assert_eq!(ctx.tool_name, "Bash");
    assert_eq!(ctx.cmd.as_deref(), Some("rm -rf /"));
    assert!(ctx.is_yolo);

    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "rm-root-guard",
        r#"export default function(ctx) {
            if (ctx.cmd && ctx.cmd.startsWith("rm -rf /")) {
                return { deny: "Forbidden deletion of root" };
            }
            return null;
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "Forbidden deletion of root".to_string()
        })
    );
}

#[test]
fn test_real_fixture_claude_code_file_tools_suite() {
    clear_codebuddy_env();
    // 1. Write
    let raw_write = r#"{
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": "/app/src/index.ts", "content": "console.log('hi');" }
    }"#;
    let ctx_w = HookContext::parse(raw_write);
    assert_eq!(ctx_w.tool_name, "Write");
    let fw = ctx_w.file.unwrap();
    assert_eq!(fw.action, FileAction::Write);
    assert_eq!(fw.path.as_deref(), Some("/app/src/index.ts"));

    // 2. Edit
    let raw_edit = r#"{
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": { "file_path": "/app/src/index.ts", "old_string": "hi", "new_string": "hello" }
    }"#;
    let ctx_e = HookContext::parse(raw_edit);
    assert_eq!(ctx_e.file.unwrap().action, FileAction::Edit);

    // 3. Delete
    let raw_del = r#"{
        "hook_event_name": "PreToolUse",
        "tool_name": "Delete",
        "tool_input": { "file_path": "/app/tmp/cache.lock" }
    }"#;
    let ctx_d = HookContext::parse(raw_del);
    assert_eq!(ctx_d.file.unwrap().action, FileAction::Delete);
}

#[test]
fn test_real_fixture_claude_code_post_tool_use_context_injection() {
    clear_codebuddy_env();
    let raw = r#"{
        "hook_event_name": "PostToolUse",
        "session_id": "22222222-3333-4444-5555-666666666666",
        "transcript_path": "C:\\Users\\test_developer\\.claude\\projects\\test-proj\\22222222-3333-4444-5555-666666666666.jsonl",
        "cwd": "C:\\Users\\test_developer\\workspace",
        "tool_name": "Bash",
        "tool_input": { "command": "git worktree add -b feature-test ../wt-test" },
        "tool_response": "Preparing worktree (checking out 'feature-test')",
        "duration_ms": 120
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.event_enum, HookEvent::PostToolUse);
    assert_eq!(ctx.tool_name, "Bash");

    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "worktree-reminder",
        r#"export default function(ctx) {
            if (ctx.event === "PostToolUse" && ctx.cmd && ctx.cmd.includes("worktree add")) {
                return { inject: "Remember to register worktree in bay" };
            }
            return null;
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Modify(ai_hook::protocol::Mutation {
            inject: Some("Remember to register worktree in bay".to_string()),
            ..Default::default()
        }))
    );
}

#[test]
fn test_real_fixture_codebuddy_superset_fields() {
    clear_codebuddy_env();
    // Authentic structure from ai-hook-debug-codebuddy-20260907.log
    let raw = r#"{
        "session_id": "44444444-5555-6666-7777-888888888888",
        "transcript_path": "C:\\Users\\test_developer\\.codebuddy\\projects\\test-proj\\44444444-5555-6666-7777-888888888888.jsonl",
        "cwd": "C:\\Users\\test_developer\\workspace",
        "hook_event_name": "PreToolUse",
        "prompt": "Optimize database queries",
        "permission_mode": "bypassPermissions",
        "client": "codebuddy",
        "version": "1.8.0",
        "generation_id": "gen-82910381",
        "model": "glm-5.3-flash",
        "agent_type": "developer",
        "tool_name": "Bash",
        "tool_input": {
            "command": "php artisan db:wipe",
            "description": "Reset test database"
        },
        "call_id": "call-12345",
        "tool_use_id": "tool-call-999"
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::CodeBuddy);
    assert_eq!(ctx.event_enum, HookEvent::PreToolUse);
    assert_eq!(ctx.model.as_deref(), Some("glm-5.3-flash"));
    assert_eq!(ctx.tool_name, "Bash");
    assert_eq!(ctx.cmd.as_deref(), Some("php artisan db:wipe"));
    assert!(ctx.is_yolo);

    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "db-wipe-confirm",
        r#"export default function(ctx) {
            if (ctx.cmd && ctx.cmd.includes("db:wipe")) {
                return { confirm: "Wiping database requires explicit confirmation" };
            }
            return null;
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert!(matches!(
        res.decision,
        Some(HookDecision::Confirm { ref reason, .. })
            if reason.contains("Wiping database requires explicit confirmation")
    ));
}

#[test]
fn test_real_fixture_codex_bash_and_can_ask_boundary() {
    clear_codebuddy_env();
    // Authentic structure from ai-hook-debug-codex-20260907.log
    let raw = r#"{
        "hook_event_name": "PreToolUse",
        "permission_mode": "bypassPermissions",
        "turn_id": "turn-codex-test-001",
        "model": "gpt-5.6-sol",
        "tool_name": "Bash",
        "tool_input": {
            "command": "php artisan db:wipe --force"
        }
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Codex);
    assert_eq!(ctx.event_enum, HookEvent::PreToolUse);
    assert_eq!(ctx.model.as_deref(), Some("gpt-5.6-sol"));
    assert_eq!(ctx.cmd.as_deref(), Some("php artisan db:wipe --force"));
    // Codex protocol has no native ask: can_ask must be false to avoid Fail-open
    assert!(!ctx.can_ask());
}

#[test]
fn test_real_fixture_codex_apply_patch_multi_target() {
    clear_codebuddy_env();
    let raw = r#"{
        "hook_event_name": "PreToolUse",
        "permission_mode": "bypassPermissions",
        "turn_id": "turn-codex-test-002",
        "model": "gpt-5.6-sol",
        "tool_name": "apply_patch",
        "tool_input": {
            "command": "*** Begin Patch\n*** Update File: C:/Users/test_user/project/src/main.rs\n@@\n-old\n+new\n*** Add File: C:/Users/test_user/project/config/.env\n+SECRET_KEY=123\n*** End Patch"
        }
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Codex);
    assert_eq!(ctx.tool_name, "apply_patch");
    let f = ctx
        .file
        .as_ref()
        .expect("file context expected for apply_patch");
    assert_eq!(f.action, FileAction::Edit);
    assert_eq!(
        f.path.as_deref(),
        Some("C:/Users/test_user/project/src/main.rs")
    );
    // Verified: all targets extracted into paths
    assert_eq!(f.paths.len(), 2);
    assert_eq!(f.paths[0], "C:/Users/test_user/project/src/main.rs");
    assert_eq!(f.paths[1], "C:/Users/test_user/project/config/.env");

    let runner = RuleRunner::new().expect("runner init");
    let script = rule(
        "protect-env-in-patch",
        r#"export default function(ctx) {
            // Can inspect all target paths from apply_patch
            if (ctx.file.paths && ctx.file.paths.some(p => p.includes(".env"))) {
                return { deny: "Forbidden modification of .env via patch" };
            }
            return null;
        }"#,
    );
    let res = runner.execute_rule(&script, &ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Deny {
            reason: "Forbidden modification of .env via patch".to_string()
        })
    );
}

#[test]
fn test_real_fixture_codex_read_file() {
    clear_codebuddy_env();
    let raw = r#"{
        "hook_event_name": "PreToolUse",
        "permission_mode": "bypassPermissions",
        "turn_id": "turn-codex-test-003",
        "tool_name": "read_file",
        "tool_input": {
            "path": "~/.aws/credentials"
        }
    }"#;

    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Codex);
    assert_eq!(ctx.tool_name, "read_file");
    let f = ctx.file.expect("file context expected");
    assert_eq!(f.action, FileAction::Read);
    assert_eq!(f.path.as_deref(), Some("~/.aws/credentials"));
}

#[test]
fn test_real_fixture_generic_unparseable_code_payload() {
    clear_codebuddy_env();
    // From ai-hook-debug-generic-20260907.log line 1: non-JSON raw JS text passed to stdin
    let raw = "export default function(ctx, sys) { const r = sys.exec(\"bash\", [\"-c\", \"echo hello\"]); return { deny: JSON.stringify(r) }; }\r\n";
    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Generic);
    assert!(ctx.parse_failed);
}

#[test]
fn test_real_fixture_generic_truncated_json_payload() {
    clear_codebuddy_env();
    // From ai-hook-debug-generic-20260907.log line 2: truncated JSON
    let raw = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"ls"}},"#;
    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Generic);
    assert!(ctx.parse_failed);
}

#[test]
fn test_real_fixture_generic_empty_payload() {
    clear_codebuddy_env();
    // From ai-hook-debug-generic-20260907.log line 11: completely empty stdin
    let raw = "";
    let ctx = HookContext::parse(raw);
    assert_eq!(ctx.platform, Platform::Generic);
}

// ---------------------------------------------------------------------------
// 2026-09-08 取证修复的回归测试
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
/// Antigravity 的委托类工具(官方工具表里的 invoke_subagent 等)此前未建模,
/// `ctx.agent` 恒为 null → 所有"禁止派发子 agent"的规则在该宿主上静默放行。
#[test]
fn antigravity_delegation_tools_normalize() {
    let ctx = HookContext::parse(
        &serde_json::json!({
            "toolCall": {
                "name": "invoke_subagent",
                "args": { "Subagents": [ { "Prompt": "refactor the auth module", "Role": "coder" } ] }
            },
            "conversationId": "c1"
        })
        .to_string(),
    );
    assert_eq!(ctx.platform, Platform::Antigravity);
    let agent = ctx
        .agent
        .as_ref()
        .expect("invoke_subagent 必须归一化到 ctx.agent");
    assert_eq!(agent.kind, AgentKind::Agent);
    assert_eq!(agent.prompt.as_deref(), Some("refactor the auth module"));

    for tool in ["manage_task", "schedule"] {
        let c = HookContext::parse(
            &serde_json::json!({
                "toolCall": { "name": tool, "args": { "Prompt": "run the tests hourly" } },
                "conversationId": "c1"
            })
            .to_string(),
        );
        let a = c
            .agent
            .as_ref()
            .unwrap_or_else(|| panic!("{tool} 必须归一化"));
        assert_eq!(a.kind, AgentKind::Task, "{tool} 应是 Task 类");
    }
}

/// Gemini CLI 的搜索工具用 `dir_path` 官方键、遗留名 `search_file_content`;
/// Antigravity 的 `find_by_name` 用 `SearchDirectory` + `Pattern`。
/// 缺这些键会让 `ctx.search.path` 在半数宿主上恒为 null。
#[test]
fn search_tools_read_host_specific_path_keys() {
    // Gemini:glob / grep_search -> {pattern, dir_path}
    let g = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "BeforeTool",
            "tool_name": "glob",
            "tool_input": { "pattern": "*.rs", "dir_path": "/srv/app" },
            "session_id": "s1",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    let s = g.search.as_ref().expect("glob 必须归一化");
    assert_eq!(s.kind, SearchKind::Glob);
    assert_eq!(s.path.as_deref(), Some("/srv/app"));
    assert_eq!(s.pattern.as_deref(), Some("*.rs"));

    // Gemini 遗留别名
    let legacy = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "BeforeTool",
            "tool_name": "search_file_content",
            "tool_input": { "pattern": "secret", "dir_path": "/srv" },
            "session_id": "s1",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    let s = legacy
        .search
        .as_ref()
        .expect("search_file_content 必须归一化");
    assert_eq!(s.kind, SearchKind::Grep);
    assert_eq!(s.path.as_deref(), Some("/srv"));

    // Antigravity:find_by_name -> {SearchDirectory, Pattern}
    let a = HookContext::parse(
        &serde_json::json!({
            "toolCall": {
                "name": "find_by_name",
                "args": { "SearchDirectory": "/srv", "Pattern": "*.ts" }
            },
            "conversationId": "c1"
        })
        .to_string(),
    );
    let s = a.search.as_ref().expect("find_by_name 必须归一化");
    assert_eq!(s.kind, SearchKind::Glob);
    assert_eq!(s.path.as_deref(), Some("/srv"));
    assert_eq!(s.pattern.as_deref(), Some("*.ts"));
}

/// `sys.fs.*` / `sys.env` 的字符串参数此前是严格类型:规则里写
/// `sys.fs.exists(ctx.file.path)` 而 path 为 null 会抛 TypeError,
/// 整条规则 fail-closed 拒绝 —— 与 console.log 用的 Coerced 语义不一致。
#[test]
fn sys_fs_and_env_tolerate_null_without_failing_closed() {
    let runner = RuleRunner::new().expect("runner");
    let r = rule(
        "null-safe-sys",
        r#"export default function(ctx, sys) {
            // Write 工具没有 file_path(只有 content)→ ctx.file.path 为 null
            if (sys.fs.exists(ctx.file && ctx.file.path)) return { deny: "should not exist" };
            // Rust 侧的 None 落到 JS 是 undefined,用宽松比较覆盖 null/undefined
            if (sys.fs.readText(ctx.file && ctx.file.path) != null) return { deny: "should be null" };
            if (sys.env("AI_HOOK_DEFINITELY_UNSET_VAR") != null) return { deny: "env should be null" };
            if (sys.fs.list(undefined).length === 0) return { deny: "list should default to cwd" };
            return { allow: true };
        }"#,
    );
    let ctx = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "content": "x" },
            "transcript_path": "/x/.claude/projects/s.jsonl",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    let res = runner.execute_rule(&r, &ctx);
    assert!(res.error.is_none(), "规则不应抛异常: {:?}", res.error);
    assert_eq!(
        res.decision,
        Some(HookDecision::Allow),
        "null 参数不应触发 fail-closed: {:?}",
        res.decision
    );
}

/// `git diff/log/show --ext-diff` / `--textconv` 会让 git 执行配置的外部
/// 驱动 = 任意代码执行。白名单宣称"只放行单条只读命令",必须挡掉。
#[test]
fn fast_path_rejects_external_drivers() {
    for cmd in [
        "git diff --ext-diff",
        "git log --textconv -p",
        "git show --ext-diff HEAD",
        "git diff --output=/tmp/x",
    ] {
        let ctx = ctx_for(cmd);
        assert!(
            check_fast_path(&ctx).is_none(),
            "{cmd} 不得命中只读白名单旁路"
        );
    }
    // 对照:普通只读命令仍然走旁路。
    assert!(check_fast_path(&ctx_for("git status --short")).is_some());
}

/// Gemini CLI 的 base input schema 带 `timestamp`(官方 hooks/reference),
/// 这是 Gemini 独有的公共字段。事件名速查覆盖不到 SessionStart /
/// SessionEnd / Notification(与 Claude 家族同名),缺了这个信号它们会被
/// 误判成 claude_code,从而用错能力矩阵。
#[test]
fn gemini_session_events_are_detected_by_timestamp() {
    let g = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "SessionEnd",
            "reason": "other",
            "session_id": "s1",
            "cwd": "/tmp",
            "timestamp": "2026-09-08T00:00:00Z"
        })
        .to_string(),
    );
    assert_eq!(g.platform, Platform::Gemini);
    // Gemini 的 SessionEnd 只有 systemMessage(给用户),没有模型上下文通道。
    let out = HookDecision::Modify(Mutation {
        inject: Some("收尾提示".into()),
        ..Mutation::default()
    })
    .to_json_output(&g, None);
    assert!(out.contains(r#""systemMessage":"收尾提示""#), "got: {out}");
    assert!(!out.contains("additionalContext"), "{out}");

    // 没有 timestamp 的同名事件仍按 Claude 家族处理(那里连 systemMessage
    // 都会被丢弃)。
    let cc = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "SessionEnd",
            "reason": "other",
            "session_id": "s1",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    assert_eq!(cc.platform, Platform::ClaudeCode);
    let out = HookDecision::Modify(Mutation {
        inject: Some("收尾提示".into()),
        ..Mutation::default()
    })
    .to_json_output(&cc, None);
    assert_eq!(out, "", "CC SessionEnd 没有任何文本通道: {out}");
}
