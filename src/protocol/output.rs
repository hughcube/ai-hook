use super::{HookContext, Platform};
use crate::i18n::{Msg, t};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDecision {
    Allow,
    Confirm {
        reason: String,
        title: Option<String>,
        gui: Option<bool>,
        timeout: Option<u32>,
        force_gui: Option<bool>,
    },
    Deny {
        reason: String,
    },
    Block {
        reason: String,
    },
    PostContext {
        additional_context: String,
    },
}

/// The offending command (or file when no command) of the current context.
fn ctx_target(ctx: &HookContext) -> &str {
    if let Some(cmd) = ctx.cmd.as_deref()
        && !cmd.is_empty()
    {
        return cmd;
    }
    ctx.file
        .as_ref()
        .and_then(|f| f.path.as_deref())
        .unwrap_or("")
}

/// Localized wrapper messages (rule-supplied `reason` text itself is kept
/// verbatim — it is authored by the rule writer in their own language).
impl HookDecision {
    pub fn to_json_output(&self, ctx: &HookContext, gui_approved: Option<bool>) -> String {
        match self {
            HookDecision::Block { reason } => {
                return json!({
                    "decision": "block",
                    "reason": reason
                })
                .to_string();
            }
            HookDecision::PostContext { additional_context } => {
                let event_name = match ctx.event.as_deref() {
                    Some("UserPromptSubmit") => "UserPromptSubmit",
                    _ => "PostToolUse",
                };
                return json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "additionalContext": additional_context
                    }
                })
                .to_string();
            }
            _ => {}
        }

        let target = ctx_target(ctx);
        let denied_label = t(Msg::M005);
        let command_label = t(Msg::M006);
        let about_to_run = t(Msg::M007);

        match ctx.platform {
            Platform::Antigravity => match self {
                HookDecision::Allow => json!({ "decision": "allow" }).to_string(),
                HookDecision::Confirm { reason, .. } => {
                    if let Some(approved) = gui_approved {
                        if approved {
                            json!({ "decision": "allow" }).to_string()
                        } else {
                            let deny_reason = format!(
                                "{}\n{}\n{}: {}",
                                denied_label, reason, command_label, target
                            );
                            json!({
                                "decision": "deny",
                                "reason": deny_reason
                            })
                            .to_string()
                        }
                    } else if ctx.is_yolo {
                        // In YOLO mode with GUI disabled, reject for safety
                        let manual_reason =
                            format!("{}\n{}: {}", t(Msg::M008), command_label, target);
                        json!({
                            "decision": "deny",
                            "reason": manual_reason
                        })
                        .to_string()
                    } else {
                        // Interactive terminal ask
                        let ask_msg = format!("{}\n{}:\n{}", reason, about_to_run, target);
                        json!({
                            "decision": "force_ask",
                            "reason": ask_msg
                        })
                        .to_string()
                    }
                }
                HookDecision::Deny { reason } => {
                    let msg = format!("{}\n{}: {}", reason, command_label, target);
                    json!({
                        "decision": "deny",
                        "reason": msg
                    })
                    .to_string()
                }
                HookDecision::Block { .. } | HookDecision::PostContext { .. } => unreachable!(),
            },
            Platform::Codex => match self {
                HookDecision::Allow => json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow"
                    }
                })
                .to_string(),
                HookDecision::Confirm { reason, .. } => {
                    if gui_approved == Some(true) {
                        json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "allow"
                            }
                        })
                        .to_string()
                    } else if gui_approved == Some(false) {
                        let deny_reason = format!(
                            "{}\n{}\n{}: {}",
                            denied_label, reason, command_label, target
                        );
                        json!({
                            "hookSpecificOutput": {
                                "hookEventName": "PreToolUse",
                                "permissionDecision": "deny",
                                "permissionDecisionReason": deny_reason
                            }
                        })
                        .to_string()
                    } else if ctx.is_yolo {
                        // 防御:yolo 且未弹窗(正常流程 yolo 无 ask → 已弹窗或自动拒绝)
                        let manual_reason = format!(
                            "{}\n{}: {}\n{}: {}",
                            t(Msg::M008),
                            command_label,
                            target,
                            t(Msg::M010),
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
                    } else {
                        // Codex 0.152+:普通(非 yolo)模式支持 PreToolUse ask
                        //(2026-09-05 用户实测口径;旧版 0.151 曾 unsupported,
                        //  由 main 层 can_ask=false 降级弹窗/拒绝兜底)
                        let ask_msg = format!("{}\n{}:\n{}", reason, about_to_run, target);
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
                    let msg = format!("{}\n{}: {}", reason, command_label, target);
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": msg
                        }
                    })
                    .to_string()
                }
                HookDecision::Block { .. } | HookDecision::PostContext { .. } => unreachable!(),
            },
            Platform::ClaudeCode | Platform::CodeBuddy | Platform::Generic => match self {
                HookDecision::Allow => String::new(),
                HookDecision::Confirm { reason, .. } => {
                    if let Some(approved) = gui_approved {
                        if approved {
                            String::new()
                        } else {
                            let deny_reason = format!(
                                "{}\n{}\n{}: {}",
                                denied_label, reason, command_label, target
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
                        let ask_msg = format!("{}\n{}:\n{}", reason, about_to_run, target);
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
                    let msg = format!("{}\n{}: {}", reason, command_label, target);
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": msg
                        }
                    })
                    .to_string()
                }
                HookDecision::Block { .. } | HookDecision::PostContext { .. } => unreachable!(),
            },
        }
    }
}
