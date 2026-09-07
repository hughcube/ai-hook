use super::decision::{HookDecision, Mutation};
use super::{Capabilities, HookContext, HookEvent, Platform, capabilities};
use crate::errln;
use crate::i18n::{Msg, t, tf};
use serde_json::json;

/// Derives a human-friendly action description from context.
pub fn resolve_action_description(ctx: &HookContext) -> &'static str {
    let l = crate::i18n::lang();
    if ctx.cmd.is_some() {
        return l.pick("执行命令", "Execute Command");
    }
    if let Some(ref f) = ctx.file {
        return match f.action {
            crate::protocol::input::FileAction::Read => l.pick("读取文件", "Read File"),
            crate::protocol::input::FileAction::Write => l.pick("写入文件", "Write File"),
            crate::protocol::input::FileAction::Edit => l.pick("修改文件", "Edit File"),
            crate::protocol::input::FileAction::Delete => l.pick("删除文件", "Delete File"),
            crate::protocol::input::FileAction::List => l.pick("查看目录", "List Directory"),
            crate::protocol::input::FileAction::Other => l.pick("文件操作", "File Operation"),
        };
    }
    if ctx.mcp.is_some() {
        return l.pick("MCP工具调用", "MCP Tool Call");
    }
    if ctx.web.is_some() {
        return l.pick("网络请求", "Web Request");
    }
    if ctx.search.is_some() {
        return l.pick("代码搜索", "Code Search");
    }
    if ctx.agent.is_some() {
        return l.pick("子Agent派发", "Subagent Delegation");
    }
    l.pick("工具调用", "Tool Invocation")
}

/// Resolves the primary target resource (command, file, URL, MCP) from context.
pub fn resolve_context_target(ctx: &HookContext) -> String {
    if let Some(cmd) = ctx.cmd.as_deref()
        && !cmd.is_empty()
    {
        return cmd.to_string();
    }
    if let Some(path) = ctx.file.as_ref().and_then(|f| f.path.as_deref())
        && !path.is_empty()
    {
        return path.to_string();
    }
    if let Some(mcp) = ctx.mcp.as_ref() {
        let s = mcp.server.as_deref().unwrap_or("");
        let t = mcp.tool.as_deref().unwrap_or("");
        if !s.is_empty() && !t.is_empty() {
            return format!("{}/{}", s, t);
        } else if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Some(web) = ctx.web.as_ref() {
        if let Some(url) = &web.url {
            return url.clone();
        }
        if let Some(q) = &web.query {
            return q.clone();
        }
    }
    if let Some(search) = ctx.search.as_ref() {
        if let Some(p) = &search.pattern {
            return p.clone();
        }
        if let Some(p) = &search.path {
            return p.clone();
        }
    }
    String::new()
}

/// Formats a complete, structured prompt for interactive confirmation (terminal ask / host inline prompt).
/// Aligns with the information displayed in the GUI security confirmation dialog.
pub fn format_ask_prompt(title: Option<&str>, reason: &str, ctx: &HookContext) -> String {
    let l = crate::i18n::lang();
    let default_title = l.pick("操作安全授权确认", "Security Authorization Required");
    let effective_title = title
        .filter(|t| !t.trim().is_empty())
        .unwrap_or(default_title);

    let prefix = l.pick("【ai-hook 安全确认】", "[ai-hook Security Confirmation] ");
    let mut lines = Vec::new();
    lines.push(format!("{}{}", prefix, effective_title));

    let trimmed_reason = reason.trim();
    if !trimmed_reason.is_empty() {
        lines.push(format!("{}: {}", l.pick("原因", "Reason"), trimmed_reason));
    }

    let action_desc = resolve_action_description(ctx);
    if !ctx.tool_name.is_empty() {
        lines.push(format!(
            "{}: {} ({})",
            l.pick("操作", "Operation"),
            action_desc,
            ctx.tool_name
        ));
    } else {
        lines.push(format!("{}: {}", l.pick("操作", "Operation"), action_desc));
    }

    let target = resolve_context_target(ctx);
    let target_display = if target.is_empty() {
        ctx_target(ctx)
    } else {
        &target
    };
    if !target_display.is_empty() {
        lines.push(format!("{}: {}", l.pick("目标", "Target"), target_display));
    }

    let cwd = ctx.cwd.trim();
    if !cwd.is_empty() {
        lines.push(format!("{}: {}", l.pick("目录", "Directory"), cwd));
    }

    lines.join("\n")
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

/// Appends the "命令: <target>" line only when there is something to name —
/// prompt / session events have no target and must not grow an empty tail.
fn append_target(reason: &str, label: &str, target: &str) -> String {
    if target.is_empty() {
        reason.to_string()
    } else {
        format!("{}\n{}: {}", reason, label, target)
    }
}

/// A platform-agnostic render action.
///
/// `HookDecision` (what the rule meant) is first normalized into an `Op` (what
/// can actually be said to this host on this event, after the capability
/// matrix downgraded anything unsupported). Only `render()` knows host JSON.
enum Op {
    Allow,
    Deny { reason: String },
    Ask { reason: String },
    KeepGoing { reason: String },
    Modify(Mutation),
}

/// Guarantees a non-empty denial reason.
///
/// Codex treats `permissionDecision:"deny"` with an empty
/// `permissionDecisionReason` as invalid, marks the hook run failed and
/// **continues the tool call** — a rule that returned `{ deny: "" }` would
/// silently allow. Every host also reads better with a reason, so all
/// platforms get the same guard.
fn non_empty_reason(msg: String) -> String {
    if msg.trim().is_empty() {
        t(Msg::M154).to_string()
    } else {
        msg
    }
}

impl HookDecision {
    /// Downgrades the rule's intent against what the host can express.
    fn to_op(&self, ctx: &HookContext, caps: &Capabilities, gui_approved: Option<bool>) -> Op {
        let target_str = resolve_context_target(ctx);
        let target = if target_str.is_empty() {
            ctx_target(ctx)
        } else {
            &target_str
        };
        let denied_label = t(Msg::M005);
        let command_label = t(Msg::M006);

        match self {
            Self::Allow => Op::Allow,

            Self::Deny { reason } => {
                let msg = non_empty_reason(append_target(reason, command_label, target));
                // A deny is never downgraded to a mutation. Downgrading used to
                // route the reason into `replace_output`, which (a) bypassed the
                // capability filter that `Self::Modify` applies and (b) is only
                // consumed by post events — on Stop / SessionStart / advisory
                // events and on degraded payloads with no recognizable event
                // name it rendered as `{"hookSpecificOutput":{"hookEventName":…}}`,
                // an empty shell every host reads as "no decision" = silent ALLOW.
                //
                // Every renderer has a denial shape for every event (Claude
                // family: top-level `decision:"block"`; Antigravity / Gemini:
                // top-level `decision:"deny"`), so keeping `Op::Deny` either
                // blocks or is ignored — never the opposite of what the rule asked.
                if !caps.gate {
                    eprintln!("[ai-hook] {}: {}", t(Msg::M150), ctx.event_enum.as_str());
                }
                Op::Deny { reason: msg }
            }

            Self::Confirm { reason, title, .. } => match gui_approved {
                Some(true) => Op::Allow,
                Some(false) => Op::Deny {
                    reason: non_empty_reason(format!(
                        "{}\n{}",
                        reason,
                        append_target(denied_label, command_label, target)
                    )),
                },
                None => {
                    // Two gates must pass: the protocol has an ask (matrix)
                    // and the host still prompts in this mode (can_ask).
                    if caps.ask && ctx.can_ask() {
                        Op::Ask {
                            reason: format_ask_prompt(title.as_deref(), reason, ctx),
                        }
                    } else {
                        // The host cannot ask and no dialog was shown: an
                        // "ask" would be ignored (or worse, fail open), so the
                        // only safe outcome is a refusal.
                        Op::Deny {
                            reason: non_empty_reason(append_target(reason, command_label, target)),
                        }
                    }
                }
            },

            Self::Modify(mutation) => {
                let mut m = mutation.clone();
                // The modifier slots have different types (String vs Value),
                // so a shared helper is a macro, not a closure.
                macro_rules! drop_modifier {
                    ($name:expr, $slot:expr) => {{
                        *$slot = None;
                        let ev: &str = ctx.event_enum.as_str();
                        let args: [&dyn std::fmt::Display; 2] = [&$name, &ev];
                        errln!("[ai-hook] {}", tf(Msg::M159, &args));
                    }};
                }
                // Only warn when a modifier the rule actually supplied is
                // dropped — an already-empty slot is not a capability loss.
                if m.inject.is_some() && !caps.inject {
                    drop_modifier!("inject", &mut m.inject);
                }
                if m.mutate_input.is_some() && !caps.mutate_input {
                    drop_modifier!("mutateInput", &mut m.mutate_input);
                }
                if m.replace_output.is_some() && !caps.replace_output {
                    drop_modifier!("replaceOutput", &mut m.replace_output);
                }
                // A Modify whose modifiers were all dropped must read as a
                // plain Allow (empty stdout), never as an empty-shell
                // `{"hookSpecificOutput":{...}}` that hosts parse as "no
                // decision" or fail schema validation on.
                if m.is_empty() {
                    Op::Allow
                } else {
                    Op::Modify(m)
                }
            }

            Self::KeepGoing { reason } => {
                if caps.control_flow {
                    Op::KeepGoing {
                        reason: reason.clone(),
                    }
                } else {
                    Op::Allow
                }
            }
        }
    }

    /// Renders the decision in the host's protocol.
    ///
    /// `gui_approved` carries the outcome of ai-hook's own dialog:
    /// `Some(true)` = user allowed, `Some(false)` = user refused, `None` = no
    /// dialog was shown (the host should ask, or the decision stands as is).
    pub fn to_json_output(&self, ctx: &HookContext, gui_approved: Option<bool>) -> String {
        // Hosts validate `hookEventName` against the event they actually fired;
        // a hard-coded "PreToolUse" would make every decision on PostToolUse /
        // Stop / ... silently discarded while the rule looks like it works.
        let event_name = match ctx.event_enum.as_str() {
            "" => ctx.event.as_deref().unwrap_or("PreToolUse"),
            name => name,
        };

        let caps = capabilities(ctx.platform, ctx.event_enum);
        let op = self.to_op(ctx, &caps, gui_approved);
        render(ctx.platform, ctx.event_enum, op, event_name)
    }
}

fn render(platform: Platform, event: HookEvent, op: Op, event_name: &str) -> String {
    match platform {
        Platform::Antigravity => render_antigravity(event, op),
        Platform::Gemini => render_gemini(event, op, event_name),
        _ => render_cc_family(platform, event, op, event_name),
    }
}

/// Claude Code / Codex / CodeBuddy / WorkBuddy / OpenCode / unknown hosts.
///
/// They share the `hookSpecificOutput` envelope; only Stop handling and the
/// input-rewrite keys differ.
fn render_cc_family(platform: Platform, event: HookEvent, op: Op, event_name: &str) -> String {
    match op {
        Op::Allow => String::new(),

        Op::Deny { reason } => {
            // PermissionRequest speaks `decision: {behavior, message}` on
            // both Claude Code and Codex; PreToolUse gates through
            // `hookSpecificOutput.permissionDecision`; CodeBuddy/WorkBuddy
            // prompt blocking uses `continue: false` (their official docs
            // deprecate `decision: "block"`); every other blocking event
            // (UserPromptSubmit on CC/Codex, PreCompact, ...) uses the
            // top-level `decision: "block"` shape. Unknown events keep the
            // `hookSpecificOutput` shape as the best-effort default.
            if event == HookEvent::PermissionRequest {
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "decision": { "behavior": "deny", "message": reason }
                    }
                })
                .to_string()
            } else if matches!(event, HookEvent::PreToolUse | HookEvent::Other) {
                // `Other` = 宿主事件名 ai-hook 未建模(如 Claude Code 的
                // TaskCompleted / ConfigChange)。它们的官方决策形态各不相同
                // (TaskCompleted 用 `continue:false` 或退出码 2),没有通用解;
                // 这里沿用 `permissionDecision` 形态属于**尽力而为**:能力矩阵
                // 已把它们标成 NONE(调用方会打 stderr 告警),而 Deny 从不降级,
                // 最坏结果是宿主忽略这条输出 —— 不会变成相反的语义。
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason
                    }
                })
                .to_string()
            } else if matches!(platform, Platform::CodeBuddy | Platform::WorkBuddy)
                && matches!(
                    event,
                    HookEvent::UserPromptSubmit
                        | HookEvent::Stop
                        | HookEvent::SubagentStop
                        | HookEvent::PreCompact
                )
            {
                // CodeBuddy / WorkBuddy 官方(`@tencent-ai/codebuddy-code` 随包
                // hooks.md)在三处明确标注:
                //   "**注意**：`decision: "block"` 字段已废弃,请使用 `continue: false`。"
                // (PostToolUse / UserPromptSubmit / Stop·SubagentStop)
                // PreCompact 官方只记载「退出码 2 阻止压缩」,JSON 决策控制节缺失,
                // 而 `continue: false` 是这两个宿主通用的阻断形态,故一并使用。
                json!({ "continue": false, "reason": reason }).to_string()
            } else if platform == Platform::Codex && event == HookEvent::PreCompact {
                // Codex 官方 PreCompact 节原文:"If a matching PreCompact hook
                // returns `continue: false`, Codex stops before compacting."
                // 官方没有给该事件 `decision: "block"` 形态(那是 PreToolUse 的
                // legacy 形状 + UserPromptSubmit / Stop / SubagentStop 三处),
                // 输出它可能被忽略 → 压缩照常进行(即门禁失效)。
                json!({ "continue": false, "reason": reason }).to_string()
            } else {
                json!({ "decision": "block", "reason": reason }).to_string()
            }
        }

        Op::Ask { reason } => json!({
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "ask",
                "permissionDecisionReason": reason
            }
        })
        .to_string(),

        Op::KeepGoing { reason } => {
            // CodeBuddy / WorkBuddy stop the loop with `continue: false`;
            // Claude Code, Codex and the OpenCode bridge use a blocking
            // decision whose meaning on Stop is "keep going".
            if matches!(platform, Platform::CodeBuddy | Platform::WorkBuddy) {
                json!({ "continue": false, "reason": reason }).to_string()
            } else {
                json!({ "decision": "block", "reason": reason }).to_string()
            }
        }

        Op::Modify(m) => {
            let mut hso = json!({ "hookEventName": event_name });
            if let Some(text) = m.inject {
                hso["additionalContext"] = json!(text);
            }
            // Rewriting arguments is a gate-event concern: Codex rejects
            // `updatedInput` unless paired with `permissionDecision: "allow"`,
            // and CodeBuddy's docs and implementation disagree on the key
            // (`modifiedInput` vs `updatedInput`), so both keys are emitted
            // there.
            if event.is_gate_event()
                && let Some(input) = m.mutate_input
            {
                hso["permissionDecision"] = json!("allow");
                hso["updatedInput"] = input.clone();
                if matches!(platform, Platform::CodeBuddy | Platform::WorkBuddy) {
                    hso["modifiedInput"] = input;
                }
            }
            if event.is_post_event()
                && let Some(out) = m.replace_output
            {
                // Codex parses `updatedToolOutput` but does not implement it;
                // its feedback channel is the top-level blocking decision.
                if platform == Platform::Codex {
                    let reason = match out {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    return json!({ "decision": "block", "reason": reason }).to_string();
                }
                // Structured values pass through as-is so a rule can match the
                // tool's output shape (Claude Code ignores shape mismatches on
                // built-in tools); strings stay strings (CodeBuddy wraps them).
                hso["updatedToolOutput"] = out;
            }
            json!({ "hookSpecificOutput": hso }).to_string()
        }
    }
}

/// Antigravity: top-level `decision`, and context only via `injectSteps`.
fn render_antigravity(event: HookEvent, op: Op) -> String {
    match op {
        Op::Allow => r#"{"decision":"allow"}"#.to_string(),
        Op::Deny { reason } => json!({ "decision": "deny", "reason": reason }).to_string(),
        // `force_ask` ignores the session's "Always Allow" cache.
        Op::Ask { reason } => json!({ "decision": "force_ask", "reason": reason }).to_string(),
        Op::KeepGoing { reason } => {
            // Only `Stop` reaches here on AGY (capability `flow=true`): the
            // official "continue" prevents the stop and re-enters the loop;
            // any other value allows the stop.
            json!({ "decision": "continue", "reason": reason }).to_string()
        }
        Op::Modify(m) => {
            // No `mutate_input` branch on purpose: Antigravity's official
            // PreToolUse output fields are `decision` / `reason` /
            // `permissionOverrides` only, so the capability matrix keeps
            // mutate_input closed and `to_op` drops the modifier before it
            // ever reaches here. Emitting an undocumented key (e.g.
            // `overwrite`) would make AGY honour the `decision:"allow"` and run
            // the **original** arguments while the rule believes it rewrote
            // them — strictly worse than dropping it.
            debug_assert!(
                m.mutate_input.is_none(),
                "AGY has no input-rewrite channel; the modifier must be dropped upstream"
            );
            let injectable = matches!(event, HookEvent::PreInvocation | HookEvent::PostInvocation);
            if let Some(text) = m.inject
                && injectable
            {
                return json!({ "injectSteps": [{ "ephemeralMessage": text }] }).to_string();
            }
            // Anything left over (a modifier that reached the renderer
            // without a channel) is emitted as an explicit allow, never as an
            // empty object — AGY requires `decision` on gating events.
            r#"{"decision":"allow"}"#.to_string()
        }
    }
}

/// Gemini CLI: top-level `decision`, no `ask` in the protocol at all.
///
/// Two different "show this text" channels exist and must not be mixed up:
/// - `hookSpecificOutput.additionalContext` → **the model** sees it (documented
///   for `BeforeAgent`, `AfterTool`, `SessionStart`).
/// - `systemMessage` → "Displayed immediately to the user in the terminal".
fn render_gemini(event: HookEvent, op: Op, event_name: &str) -> String {
    let context_for_model = matches!(
        event,
        HookEvent::BeforeAgent | HookEvent::AfterTool | HookEvent::SessionStart
    );

    match op {
        Op::Allow => r#"{"decision":"allow"}"#.to_string(),
        Op::Deny { reason } | Op::Ask { reason } => {
            json!({ "decision": "deny", "reason": reason }).to_string()
        }
        // Gemini has no Stop event. On `AfterAgent`, `decision:"deny"` rejects
        // the response and forces a retry — that is Gemini's "keep going".
        Op::KeepGoing { reason } => {
            if event == HookEvent::AfterAgent {
                json!({ "decision": "deny", "reason": reason }).to_string()
            } else {
                String::new()
            }
        }
        Op::Modify(m) => {
            let mut out = json!({});
            // `AfterTool`: deny hides the real output and `reason` becomes the
            // result the model sees. It composes with `additionalContext`.
            // Gemini's reason is a string; structured replacements are
            // serialized.
            if let Some(text) = m.replace_output {
                let text = match text {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                out["decision"] = json!("deny");
                out["reason"] = json!(text);
            }
            // `BeforeTool`: `hookSpecificOutput.tool_input` "merges with and
            // overrides the model's arguments before execution" (official
            // reference). Emitted alone or next to a deny.
            let mut hso = serde_json::Map::new();
            if let Some(input) = m.mutate_input {
                hso.insert("hookEventName".into(), json!(event_name));
                hso.insert("tool_input".into(), input);
            }
            if let Some(text) = m.inject {
                if context_for_model {
                    if hso.is_empty() {
                        hso.insert("hookEventName".into(), json!(event_name));
                    }
                    hso.insert("additionalContext".into(), json!(text));
                } else {
                    out["systemMessage"] = json!(text);
                }
            }
            if !hso.is_empty() {
                out["hookSpecificOutput"] = serde_json::Value::Object(hso);
            }
            if out.as_object().is_none_or(|o| o.is_empty()) {
                String::new()
            } else {
                out.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::input::FileAction;

    #[test]
    fn test_format_ask_prompt_command_tool() {
        let mut ctx = HookContext::parse(
            &serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": { "command": "DELETE FROM users WHERE 1=1" },
                "cwd": "/var/www/project"
            })
            .to_string(),
        );
        ctx.cmd = Some("DELETE FROM users WHERE 1=1".to_string());
        ctx.cwd = "/var/www/project".to_string();

        let prompt = format_ask_prompt(
            Some("SQL 破坏性操作确认"),
            "SQL 破坏性操作可能批量删除/修改数据，请确认是否允许执行？",
            &ctx,
        );

        let l = crate::i18n::lang();
        let expected_prefix = l.pick("【ai-hook 安全确认】", "[ai-hook Security Confirmation] ");
        assert!(prompt.contains(expected_prefix));
        assert!(prompt.contains("SQL 破坏性操作确认"));
        assert!(prompt.contains(&format!(
            "{}: SQL 破坏性操作可能批量删除/修改数据，请确认是否允许执行？",
            l.pick("原因", "Reason")
        )));
        assert!(prompt.contains(&format!(
            "{}: {} (Bash)",
            l.pick("操作", "Operation"),
            l.pick("执行命令", "Execute Command")
        )));
        assert!(prompt.contains(&format!(
            "{}: DELETE FROM users WHERE 1=1",
            l.pick("目标", "Target")
        )));
        assert!(prompt.contains(&format!(
            "{}: /var/www/project",
            l.pick("目录", "Directory")
        )));
    }

    #[test]
    fn test_format_ask_prompt_file_tool() {
        let mut ctx = HookContext::parse(
            &serde_json::json!({
                "toolCall": {
                    "name": "replace_file_content",
                    "args": { "TargetFile": "C:/app/config.php" }
                }
            })
            .to_string(),
        );
        ctx.cwd = "C:/app".to_string();
        if let Some(ref mut f) = ctx.file {
            f.action = FileAction::Edit;
            f.path = Some("C:/app/config.php".to_string());
        }

        let prompt = format_ask_prompt(Some("核心配置修改"), "禁止擅自覆写核心业务配置", &ctx);

        let l = crate::i18n::lang();
        let expected_prefix = l.pick("【ai-hook 安全确认】", "[ai-hook Security Confirmation] ");
        assert!(prompt.contains(expected_prefix));
        assert!(prompt.contains("核心配置修改"));
        assert!(prompt.contains(&format!(
            "{}: 禁止擅自覆写核心业务配置",
            l.pick("原因", "Reason")
        )));
        assert!(prompt.contains(&format!(
            "{}: {} (replace_file_content)",
            l.pick("操作", "Operation"),
            l.pick("修改文件", "Edit File")
        )));
        assert!(prompt.contains(&format!("{}: C:/app/config.php", l.pick("目标", "Target"))));
        assert!(prompt.contains(&format!("{}: C:/app", l.pick("目录", "Directory"))));
    }
}
