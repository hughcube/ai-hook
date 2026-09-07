use super::decision::{HookDecision, Mutation};
use super::{Capabilities, HookContext, HookEvent, Platform, capabilities};
use crate::errln;
use crate::i18n::{Msg, t, tf};
use serde_json::json;

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
        let target = ctx_target(ctx);
        let denied_label = t(Msg::M005);
        let command_label = t(Msg::M006);
        let about_to_run = t(Msg::M007);

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

            Self::Confirm { reason, .. } => match gui_approved {
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
                            reason: format!("{}\n{}:\n{}", reason, about_to_run, target),
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
                json!({
                    "hookSpecificOutput": {
                        "hookEventName": event_name,
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason
                    }
                })
                .to_string()
            } else if matches!(event, HookEvent::UserPromptSubmit)
                && matches!(platform, Platform::CodeBuddy | Platform::WorkBuddy)
            {
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
            // Antigravity PreToolUse: official schema explicitly supports `overwrite`
            // (key-value pairs shallow-merged into the tool call's arguments).
            if let Some(args) = m.mutate_input {
                let mut map = serde_json::Map::new();
                map.insert("decision".into(), json!("allow"));
                map.insert("overwrite".into(), args);
                return serde_json::Value::Object(map).to_string();
            }
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
