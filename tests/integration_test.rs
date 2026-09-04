use ai_hook::engine::{RuleRunner, RuleSource};
use ai_hook::fast_path::check_fast_path;
use ai_hook::protocol::{HookContext, HookDecision, Platform};
use std::path::PathBuf;

#[test]
fn test_fast_path_filtering() {
    let safe_payload = serde_json::json!({
        "toolName": "run_command",
        "toolCall": { "args": { "CommandLine": "git status" } }
    }).to_string();
    let ctx = HookContext::parse(&safe_payload);
    assert_eq!(check_fast_path(&ctx), Some(HookDecision::Allow));

    let dangerous_payload = serde_json::json!({
        "toolName": "run_command",
        "toolCall": { "args": { "CommandLine": "git status > dangerous.txt" } }
    }).to_string();
    let ctx_danger = HookContext::parse(&dangerous_payload);
    assert_eq!(check_fast_path(&ctx_danger), None);
}

#[test]
fn test_protocol_ingress_parsing() {
    // 1. Antigravity
    let agy_raw = serde_json::json!({
        "toolName": "run_command",
        "toolCall": {
            "args": {
                "CommandLine": "echo hello",
                "TargetFile": "target.txt"
            }
        },
        "conversationId": "conv-123"
    }).to_string();
    let ctx = HookContext::parse(&agy_raw);
    assert_eq!(ctx.platform, Platform::Antigravity);
    assert_eq!(ctx.cmd, "echo hello");
    assert_eq!(ctx.target_file, "target.txt");
    assert_eq!(ctx.conversation_id.as_deref(), Some("conv-123"));

    // 2. Claude Code
    let cc_raw = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "npm test"
        }
    }).to_string();
    let ctx_cc = HookContext::parse(&cc_raw);
    assert_eq!(ctx_cc.platform, Platform::ClaudeCode);
    assert_eq!(ctx_cc.cmd, "npm test");

    // 3. Codex
    let codex_raw = serde_json::json!({
        "turn_id": "turn-abc",
        "tool_name": "Bash",
        "tool_input": {
            "command": "cargo check"
        }
    }).to_string();
    let ctx_codex = HookContext::parse(&codex_raw);
    assert_eq!(ctx_codex.platform, Platform::Codex);
    assert_eq!(ctx_codex.cmd, "cargo check");
}

#[test]
fn test_autonomous_js_rule_execution() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    let rule_code = r#"
        export default function(ctx, sys) {
            if (ctx.cmd.includes("drop_database")) {
                return { action: "deny", reason: "Cannot drop database" };
            }
            if (ctx.cmd.includes("restart_service")) {
                return { action: "confirm", reason: "Needs restart approval" };
            }
            return null;
        }
    "#;

    let rule = RuleSource {
        id: "test-rule".to_string(),
        path: PathBuf::from("test-rule.js"),
        code: rule_code.to_string(),
    };

    let deny_ctx = HookContext::parse(&serde_json::json!({
        "toolName": "run_command",
        "toolCall": { "args": { "CommandLine": "psql -c drop_database" } }
    }).to_string());

    let res_deny = runner.execute_rule(&rule, &deny_ctx);
    assert_eq!(
        res_deny.decision,
        Some(HookDecision::Deny {
            reason: "Cannot drop database".to_string()
        })
    );

    let confirm_ctx = HookContext::parse(&serde_json::json!({
        "toolName": "run_command",
        "toolCall": { "args": { "CommandLine": "systemctl restart_service" } }
    }).to_string());

    let res_confirm = runner.execute_rule(&rule, &confirm_ctx);
    assert_eq!(
        res_confirm.decision,
        Some(HookDecision::Confirm {
            reason: "Needs restart approval".to_string(),
            title: None,
            gui: None,
            timeout: None,
        })
    );

    let pass_ctx = HookContext::parse(&serde_json::json!({
        "toolName": "run_command",
        "toolCall": { "args": { "CommandLine": "cargo check" } }
    }).to_string());

    let res_pass = runner.execute_rule(&rule, &pass_ctx);
    assert_eq!(res_pass.decision, None);
}

#[test]
fn test_sys_autonomous_git_branch() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");

    let rule_code = r#"
        export default function(ctx, sys) {
            const branch = sys.git.branch();
            if (branch && ctx.cmd.includes("--force")) {
                return { action: "deny", reason: `Force push blocked on ${branch}` };
            }
            return null;
        }
    "#;

    let rule = RuleSource {
        id: "git-test".to_string(),
        path: PathBuf::from("git-test.js"),
        code: rule_code.to_string(),
    };

    let ctx = HookContext::parse(&serde_json::json!({
        "toolName": "run_command",
        "toolCall": {
            "args": {
                "CommandLine": "git push origin master --force",
                "Cwd": std::env::current_dir().unwrap().to_string_lossy().to_string()
            }
        }
    }).to_string());

    let res = runner.execute_rule(&rule, &ctx);
    assert!(res.decision.is_some());
    if let Some(HookDecision::Deny { reason }) = res.decision {
        assert!(reason.contains("Force push blocked on master"));
    } else {
        panic!("Expected Deny decision");
    }
}

#[test]
fn test_ctx_agent_and_raw_input() {
    let runner = RuleRunner::new().expect("Failed to initialize runner");
    let rule_code = r#"
        export default function(ctx, sys) {
            // Verify agent type detection
            if (ctx.agent !== "antigravity" && ctx.agentType !== "antigravity") {
                return { action: "deny", reason: "Agent detection failed" };
            }
            // Verify raw input access
            if (!ctx.raw || ctx.raw.customFlag !== "secret_value") {
                return { action: "deny", reason: "Raw payload access failed" };
            }
            // Verify args access
            if (!ctx.args || ctx.args.CommandLine !== "echo hello") {
                return { action: "deny", reason: "Args access failed" };
            }
            // Verify GUI control return
            return {
                action: "confirm",
                reason: "Confirmed with GUI control",
                title: "Custom Auth Title",
                gui: false,
                timeout: 45
            };
        }
    "#;

    let rule = RuleSource {
        id: "raw-agent-test".to_string(),
        path: PathBuf::from("raw-agent-test.js"),
        code: rule_code.to_string(),
    };

    let ctx = HookContext::parse(&serde_json::json!({
        "toolName": "run_command",
        "customFlag": "secret_value",
        "toolCall": {
            "args": {
                "CommandLine": "echo hello"
            }
        }
    }).to_string());

    let res = runner.execute_rule(&rule, &ctx);
    assert_eq!(
        res.decision,
        Some(HookDecision::Confirm {
            reason: "Confirmed with GUI control".to_string(),
            title: Some("Custom Auth Title".to_string()),
            gui: Some(false),
            timeout: Some(45),
        })
    );
}
