use super::input::{HookContext, Platform};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    Allow,
    Confirm { reason: String },
    Deny { reason: String },
}

impl HookDecision {
    pub fn to_json_output(&self, ctx: &HookContext, gui_approved: Option<bool>) -> String {
        match ctx.platform {
            Platform::Antigravity => match self {
                HookDecision::Allow => json!({ "decision": "allow" }).to_string(),
                HookDecision::Confirm { reason } => {
                    if ctx.is_yolo {
                        // In YOLO / skip-permissions mode, check GUI prompt result
                        if gui_approved == Some(true) {
                            json!({ "decision": "allow" }).to_string()
                        } else {
                            let manual_reason = format!(
                                "【硬阻断】Agent 不会自动执行该高危操作。请在独立终端手动执行：\n{}",
                                if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                            );
                            json!({
                                "decision": "deny",
                                "reason": manual_reason
                            })
                            .to_string()
                        }
                    } else {
                        // Interactive mode: force_ask
                        let ask_msg = format!(
                            "{}\n即将执行：\n{}",
                            reason,
                            if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                        );
                        json!({
                            "decision": "force_ask",
                            "reason": ask_msg
                        })
                        .to_string()
                    }
                }
                HookDecision::Deny { reason } => {
                    let msg = format!(
                        "{}\n{}",
                        reason,
                        if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                    );
                    json!({
                        "decision": "deny",
                        "reason": msg
                    })
                    .to_string()
                }
            },
            Platform::Codex => match self {
                HookDecision::Allow => {
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "allow"
                        }
                    })
                    .to_string()
                }
                HookDecision::Confirm { reason } => {
                    if gui_approved == Some(true) {
                        json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "allow"
                            }
                        })
                        .to_string()
                    } else {
                        let manual_reason = format!(
                            "【硬阻断】Codex PreToolUse 不支持 ask 确认。请在终端手动执行：\n{}\n原因: {}",
                            if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd },
                            reason
                        );
                        json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": manual_reason
                            }
                        })
                        .to_string()
                    }
                }
                HookDecision::Deny { reason } => {
                    let msg = format!(
                        "{}\n{}",
                        reason,
                        if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                    );
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": msg
                        }
                    })
                    .to_string()
                }
            },
            Platform::ClaudeCode | Platform::Generic => match self {
                HookDecision::Allow => String::new(),
                HookDecision::Confirm { reason } => {
                    let ask_msg = format!(
                        "{}\n即将执行：\n{}",
                        reason,
                        if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                    );
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "ask",
                            "permissionDecisionReason": ask_msg
                        }
                    })
                    .to_string()
                }
                HookDecision::Deny { reason } => {
                    let msg = format!(
                        "{}\n{}",
                        reason,
                        if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                    );
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": msg
                        }
                    })
                    .to_string()
                }
            },
        }
    }
}
