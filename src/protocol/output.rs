use super::capability::{AskShape, DenyShape, FlowShape, InjectShape, MutateShape, ReplaceShape};
use super::decision::{HookDecision, Mutation};
use super::{Capabilities, HookContext, Platform, capabilities};
use crate::errln;
use crate::i18n::{Msg, t, tf};
use serde_json::{Map, json};

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
/// matrix downgraded anything unsupported). `render()` then turns the `Op`
/// into the shape the capability matrix declared for this (host, event) —
/// there is no per-platform branch left in it.
enum Op {
    Allow,
    Deny { reason: String },
    Ask { reason: String },
    KeepGoing { reason: String },
    Modify(Mutation),
}

/// The finished decision in the form the host consumes.
///
/// Almost every host reads a JSON object on stdout, but a host that does not
/// parse hook JSON at all (the opencode bridge only looks at the exit code)
/// needs the process to exit non-zero with the reason on stderr instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rendered {
    /// JSON to write to stdout. An empty string means "no decision" = allow.
    Json(String),
    /// Write `reason` to stderr and exit with `code`; print nothing to stdout.
    Exit { code: i32, reason: String },
}

impl Rendered {
    /// The stdout payload (empty for the exit-code channel).
    #[must_use]
    pub fn json(&self) -> &str {
        match self {
            Self::Json(s) => s,
            Self::Exit { .. } => "",
        }
    }

    /// `Some` when the decision must be expressed through the exit code.
    #[must_use]
    pub fn exit(&self) -> Option<(i32, &str)> {
        match self {
            Self::Json(_) => None,
            Self::Exit { code, reason } => Some((*code, reason)),
        }
    }
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
                    if caps.can_ask() && ctx.can_ask() {
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
                //
                // `inject` is the one slot with a降级路径:宿主只有
                // `systemMessage`(给用户)而没有模型上下文通道时,把文本
                // 挪到 `notify`,规则至少还能把话说出去。
                if m.inject.is_some() && !caps.can_inject() {
                    if caps.notify_user && m.notify.is_none() {
                        let text = m.inject.take().unwrap_or_default();
                        let ev: &str = ctx.event_enum.as_str();
                        let args: [&dyn std::fmt::Display; 1] = [&ev];
                        errln!("[ai-hook] {}", tf(Msg::M169, &args));
                        m.notify = Some(text);
                    } else {
                        drop_modifier!("inject", &mut m.inject);
                    }
                }
                if m.notify.is_some() && !caps.notify_user {
                    drop_modifier!("notify", &mut m.notify);
                }
                if m.mutate_input.is_some() && !caps.can_mutate() {
                    drop_modifier!("mutateInput", &mut m.mutate_input);
                }
                if m.replace_output.is_some() && !caps.can_replace() {
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
                if caps.can_flow() {
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
    #[must_use]
    pub fn render(&self, ctx: &HookContext, gui_approved: Option<bool>) -> Rendered {
        // Hosts validate `hookEventName` against the event they actually fired;
        // a hard-coded "PreToolUse" would make every decision on PostToolUse /
        // Stop / ... silently discarded while the rule looks like it works.
        let event_name = match ctx.event_enum.as_str() {
            "" => ctx.event.as_deref().unwrap_or("PreToolUse"),
            name => name,
        };

        let caps = capabilities(ctx.platform, ctx.event_enum);
        let op = self.to_op(ctx, &caps, gui_approved);
        render(ctx.platform, op, event_name, &caps)
    }

    /// The stdout JSON of [`Self::render`] — an empty string means "no
    /// decision" (allow) in every host protocol, and also covers hosts that
    /// only understand exit codes.
    #[must_use]
    pub fn to_json_output(&self, ctx: &HookContext, gui_approved: Option<bool>) -> String {
        self.render(ctx, gui_approved).json().to_string()
    }
}

/// Turns an `Op` into whatever this (host, event) actually understands.
///
/// Every branch reads its shape straight out of the capability matrix — the
/// only remaining platform switch is [`fallback_deny_shape`], used when a deny
/// lands on an event that has no blocking slot at all (a deny is never
/// downgraded: the host may ignore the output, but must never read it as an
/// allow).
fn render(platform: Platform, op: Op, event_name: &str, caps: &Capabilities) -> Rendered {
    match op {
        // Antigravity 与 Gemini 把 `decision` 声明为必填字段(AGY 官方:
        // "`decision` | string | **Required.**"),所以"放行"也要显式写出来;
        // 其余宿主读空 stdout 就是放行,多打一个 JSON 反而要承担被误解析的风险。
        Op::Allow if host_requires_explicit_allow(platform) => {
            Rendered::Json(r#"{"decision":"allow"}"#.to_string())
        }
        Op::Allow => Rendered::Json(String::new()),

        Op::Deny { reason } => {
            let shape = match caps.deny {
                DenyShape::None => fallback_deny_shape(platform),
                declared => declared,
            };
            render_deny(shape, event_name, &reason)
        }

        Op::Ask { reason } => match caps.ask {
            AskShape::PermissionAsk => Rendered::Json(
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "permissionDecision": "ask",
                        "permissionDecisionReason": reason
                    }
                })
                .to_string(),
            ),
            // `force_ask` ignores the session's "Always Allow" cache.
            AskShape::ForceAsk => {
                Rendered::Json(json!({ "decision": "force_ask", "reason": reason }).to_string())
            }
            // Unreachable: `to_op` only produces `Op::Ask` when the matrix has
            // an ask slot. Keep it deny-shaped rather than empty so a future
            // divergence can never become a silent allow.
            AskShape::None => render_deny(fallback_deny_shape(platform), event_name, &reason),
        },

        Op::KeepGoing { reason } => Rendered::Json(match caps.flow {
            // Claude Code / Codex / CodeBuddy / WorkBuddy.
            FlowShape::BlockDecision => {
                json!({ "decision": "block", "reason": reason }).to_string()
            }
            // Antigravity Stop: any value other than "continue" allows the stop.
            FlowShape::ContinueDecision => {
                json!({ "decision": "continue", "reason": reason }).to_string()
            }
            // Gemini AfterAgent: reject the response and force a retry.
            FlowShape::RetryDecision => json!({ "decision": "deny", "reason": reason }).to_string(),
            // Unreachable: `to_op` downgrades to `Op::Allow` first.
            FlowShape::None => String::new(),
        }),

        Op::Modify(m) => render_modify(platform, m, event_name, caps),
    }
}

/// Hosts whose protocol marks the top-level `decision` field as required, so
/// even "no objection" has to be spelled out.
///
/// This is the one place `render` still looks at the platform: it is a property
/// of the host's wire format rather than of a (host, event) capability, so it
/// does not belong in the matrix.
const fn host_requires_explicit_allow(platform: Platform) -> bool {
    matches!(platform, Platform::Antigravity | Platform::Gemini)
}

/// The best-effort denial shape for an event with no documented blocking slot
/// (Claude Code's `Notification` / `SessionEnd` / `PostCompact`, Antigravity's
/// invocation hooks, …).
const fn fallback_deny_shape(platform: Platform) -> DenyShape {
    match platform {
        Platform::Antigravity | Platform::Gemini => DenyShape::HostDecisionDeny,
        _ => DenyShape::TopLevelBlock,
    }
}

/// Writes one denial shape into `out`. Returns `None` when the host has no JSON
/// channel at all and the caller must fall back to the exit code.
fn apply_deny_shape(
    out: &mut Map<String, serde_json::Value>,
    shape: DenyShape,
    event_name: &str,
    reason: &str,
) -> Option<i32> {
    match shape {
        DenyShape::None => {}
        DenyShape::PermissionDecision => {
            out.insert(
                "hookSpecificOutput".into(),
                json!({
                    "hookEventName": event_name,
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason
                }),
            );
        }
        DenyShape::BehaviorDeny => {
            out.insert(
                "hookSpecificOutput".into(),
                json!({
                    "hookEventName": event_name,
                    "decision": { "behavior": "deny", "message": reason }
                }),
            );
        }
        DenyShape::TopLevelBlock => {
            out.insert("decision".into(), json!("block"));
            out.insert("reason".into(), json!(reason));
        }
        DenyShape::ContinueFalse => {
            out.insert("continue".into(), json!(false));
            out.insert("reason".into(), json!(reason));
        }
        DenyShape::HostDecisionDeny => {
            out.insert("decision".into(), json!("deny"));
            out.insert("reason".into(), json!(reason));
        }
        DenyShape::ExitCode2 => return Some(2),
    }
    None
}

fn render_deny(shape: DenyShape, event_name: &str, reason: &str) -> Rendered {
    let mut out = Map::new();
    match apply_deny_shape(&mut out, shape, event_name, reason) {
        // No JSON channel: the host reads the exit code and stderr.
        Some(code) => Rendered::Exit {
            code,
            reason: reason.to_string(),
        },
        None => Rendered::Json(serde_json::Value::Object(out).to_string()),
    }
}

fn render_modify(
    platform: Platform,
    m: Mutation,
    event_name: &str,
    caps: &Capabilities,
) -> Rendered {
    let mut out = Map::new();
    let mut hso = Map::new();

    // 1. Tool-result replacement. Hosts without an `updatedToolOutput`
    //    equivalent borrow the denial shape instead: the replacement text is
    //    delivered as the `reason`, which the host feeds back to the model
    //    (Codex: "replaces the tool result with that feedback"; Gemini
    //    AfterTool: "replaces the tool result sent back to the model").
    if let Some(value) = m.replace_output {
        match caps.replace_output {
            ReplaceShape::UpdatedToolOutput => {
                // Structured values pass through as-is so a rule can match the
                // tool's output shape (Claude Code ignores shape mismatches on
                // built-in tools); strings stay strings (CodeBuddy wraps them).
                hso.insert("updatedToolOutput".into(), value);
            }
            ReplaceShape::AsReason(shape) => {
                let text = match value {
                    serde_json::Value::String(s) => s,
                    other => other.to_string(),
                };
                if let Some(code) = apply_deny_shape(&mut out, shape, event_name, &text) {
                    // A host that neither replaces nor reads JSON decisions has
                    // no way to carry the replacement at all.
                    return Rendered::Exit { code, reason: text };
                }
            }
            ReplaceShape::None => {}
        }
    }

    // 2. Model-visible context.
    if let Some(text) = m.inject {
        match caps.inject {
            InjectShape::AdditionalContext => {
                hso.insert("additionalContext".into(), json!(text));
            }
            InjectShape::InjectSteps => {
                return Rendered::Json(
                    json!({ "injectSteps": [{ "ephemeralMessage": text }] }).to_string(),
                );
            }
            InjectShape::None => {}
        }
    }

    // 3. Rewriting arguments. Codex rejects `updatedInput` unless it is paired
    //    with `permissionDecision:"allow"`, and CodeBuddy's docs and
    //    implementation disagree on the key (`modifiedInput` vs `updatedInput`)
    //    — its two code paths each read one of them, so both are emitted.
    if let Some(input) = m.mutate_input {
        match caps.mutate_input {
            MutateShape::UpdatedInput => {
                hso.insert("permissionDecision".into(), json!("allow"));
                hso.insert("updatedInput".into(), input.clone());
                if matches!(platform, Platform::CodeBuddy | Platform::WorkBuddy) {
                    hso.insert("modifiedInput".into(), input);
                }
            }
            MutateShape::ToolInput => {
                hso.insert("tool_input".into(), input);
            }
            MutateShape::None => {}
        }
    }

    // 4. User-visible text (`systemMessage`) — never reaches the model.
    if let Some(text) = m.notify {
        out.insert("systemMessage".into(), json!(text));
    }

    if !hso.is_empty() {
        hso.insert("hookEventName".into(), json!(event_name));
        out.insert("hookSpecificOutput".into(), serde_json::Value::Object(hso));
    }

    if out.is_empty() {
        Rendered::Json(String::new())
    } else {
        Rendered::Json(serde_json::Value::Object(out).to_string())
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
