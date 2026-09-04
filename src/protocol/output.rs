use super::input::{HookContext, Platform};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    Allow,
    Confirm {
        reason: String,
        title: Option<String>,
        gui: Option<bool>,
        timeout: Option<u32>,
    },
    Deny {
        reason: String,
    },
}

impl HookDecision {
    pub fn to_json_output(&self, ctx: &HookContext, gui_approved: Option<bool>) -> String {
        match ctx.platform {
            Platform::Antigravity => match self {
                HookDecision::Allow => json!({ "decision": "allow" }).to_string(),
                HookDecision::Confirm { reason, .. } => {
                    if let Some(approved) = gui_approved {
                        if approved {
                            json!({ "decision": "allow" }).to_string()
                        } else {
                            let deny_reason = format!(
                                "【安全门禁已拒绝】用户在弹窗中选择拒绝或倒计时超时：\n{}\n命令：{}",
                                reason,
                                if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                            );
                            json!({
                                "decision": "deny",
                                "reason": deny_reason
                            })
                            .to_string()
                        }
                    } else if ctx.is_yolo {
                        // In YOLO mode with GUI disabled, reject for safety
                        let manual_reason = format!(
                            "【硬阻断】免确认模式下未获得授权。请在终端手动执行：\n{}",
                            if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                        );
                        json!({
                            "decision": "deny",
                            "reason": manual_reason
                        })
                        .to_string()
                    } else {
                        // Interactive terminal ask
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
                HookDecision::Confirm { reason, .. } => {
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
                            "【硬阻断】用户拒绝或 Codex PreToolUse 不支持交互式确认。命令：\n{}\n原因: {}",
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
            Platform::ClaudeCode | Platform::CodeBuddy | Platform::Generic => match self {
                HookDecision::Allow => String::new(),
                HookDecision::Confirm { reason, .. } => {
                    if let Some(approved) = gui_approved {
                        if approved {
                            String::new()
                        } else {
                            let deny_reason = format!(
                                "【安全门禁已拒绝】用户在弹窗中选择拒绝或倒计时超时：\n{}\n命令：{}",
                                reason,
                                if ctx.cmd.is_empty() { &ctx.target_file } else { &ctx.cmd }
                            );
                            json!({
                                "hookSpecificOutput": {
                                    "hookEventName": "PreToolUse",
                                    "permissionDecision": "deny",
                                    "permissionDecisionReason": deny_reason
                                }
                            })
                            .to_string()
                        }
                    } else {
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
