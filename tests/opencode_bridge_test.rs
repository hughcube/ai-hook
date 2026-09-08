//! opencode 桥(OPENCODE_COMPAT)相关断言。
//!
//! 平台判别依赖**进程级**环境变量,而同一个 integration test 二进制里的用例
//! 是并发跑的 —— 放在 `integration_test.rs` 里会把它对 `OPENCODE_COMPAT`
//! 的置位泄漏给同时运行的其它用例(实测把
//! `platform_detection_uses_host_controlled_fields_only` 判成了 OpenCode)。
//! cargo 为每个 integration 文件起独立进程,所以这里单独成文件。

use ai_hook::protocol::{HookContext, HookDecision, Platform, capabilities};

fn clear_codebuddy_env() {
    unsafe {
        std::env::remove_var("CODEBUDDY_SESSION_ID");
        std::env::remove_var("CODEBUDDY_PROJECT_DIR");
        std::env::remove_var("CODEBUDDY_HOST");
    }
}

fn opencode_pretooluse_ctx(command: &str) -> HookContext {
    HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": { "command": command },
            "session_id": "s1",
            "cwd": "/tmp"
        })
        .to_string(),
    )
}

/// opencode 桥(`opencode-claude-hooks` 0.1.0)的三条通道约束,逐条对应其实现:
///
/// - `src/executor.ts`:`const blocked = exitCode === 2`;
/// - `src/index.ts` 的 `tool.execute.before` 只判 `result.blocked`,
///   **从不读 permissionDecision**;
/// - `permission.ask` 只读 `result.permissionDecision`(不认 `decision.behavior`);
/// - 没有注册 `Stop` / `UserPromptSubmit`,`tool.execute.after` 丢弃全部返回;
/// - ask 两个分支都没实现。
#[test]
fn opencode_bridge_channel_shapes() {
    clear_codebuddy_env();
    unsafe {
        std::env::set_var("OPENCODE_COMPAT", "1");
    }

    // 1. PreToolUse 的 deny 必须走退出码 2 + stderr。
    let ctx = opencode_pretooluse_ctx("npm run deploy");
    assert_eq!(ctx.platform, Platform::OpenCode);
    let rendered = HookDecision::Deny {
        reason: "opencode bridge only reads exit codes".into(),
    }
    .render(&ctx, None);
    let (code, reason) = rendered
        .exit()
        .expect("opencode 的 deny 必须走退出码通道,不能输出 JSON");
    assert_eq!(code, 2);
    assert!(reason.contains("opencode bridge only reads exit codes"));
    assert_eq!(rendered.json(), "", "退出码通道上不得再输出 JSON");

    // 2. PermissionRequest 用 permissionDecision,不是 decision.behavior。
    let perm = HookContext::parse(
        &serde_json::json!({
            "hook_event_name": "PermissionRequest",
            "tool_name": "bash",
            "tool_input": { "command": "npm run deploy" },
            "session_id": "s1",
            "cwd": "/tmp"
        })
        .to_string(),
    );
    let out = HookDecision::Deny {
        reason: "no".into(),
    }
    .to_json_output(&perm, None);
    assert!(
        out.contains(r#""permissionDecision":"deny""#),
        "opencode PermissionRequest 必须用 permissionDecision: {out}"
    );
    assert!(
        !out.contains(r#""behavior""#),
        "桥不读 decision.behavior: {out}"
    );

    // 3. ask 不支持 → confirm 必须降级;未接线的事件不得声称能力。
    assert!(!ctx.can_ask(), "桥没有 ask 通道,发 ask 等于静默放行");
    let confirm_out = HookDecision::Confirm {
        reason: "please confirm".into(),
        title: None,
        gui: None,
        timeout: None,
        force_gui: None,
    }
    .to_json_output(&ctx, None);
    assert!(
        !confirm_out.contains(r#""ask""#),
        "桥不支持 ask,confirm 必须降级: {confirm_out}"
    );
    for ev in ["Stop", "UserPromptSubmit", "PostToolUse"] {
        let c = HookContext::parse(
            &serde_json::json!({
                "hook_event_name": ev,
                "prompt": "hi",
                "session_id": "s1",
                "cwd": "/tmp"
            })
            .to_string(),
        );
        assert_eq!(
            capabilities(c.platform, c.event_enum),
            ai_hook::protocol::Capabilities::NONE,
            "opencode 在 {ev} 上不得声称任何能力"
        );
    }

    unsafe {
        std::env::remove_var("OPENCODE_COMPAT");
    }
}
