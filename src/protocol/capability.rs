use super::event::HookEvent;
use super::input::Platform;

/// What a (platform, event) pair can actually express to the host.
///
/// Every field mirrors a documented host capability; when a capability is
/// `false`, emitting the corresponding output would either be ignored or —
/// far worse — make the host fail **open** (Codex treats an unsupported
/// `permissionDecision` as "hook failed, continue"), so the engine must
/// downgrade instead.
///
/// 官网出处(逐条可核对):
/// - Claude Code  `https://code.claude.com/docs/en/hooks`
///   (Decision control 表 / PreToolUse / PostToolUse / PostToolUseFailure /
///   Stop decision control)
/// - Codex CLI    `https://learn.chatgpt.com/docs/hooks`
///   (Common output fields / PreToolUse / PostToolUse / Stop)
/// - Gemini CLI   `https://geminicli.com/docs/hooks/reference/`
///   (Common output fields / BeforeTool / AfterTool / BeforeAgent / AfterAgent)
/// - Antigravity  `https://antigravity.google/docs/hooks/`
///   (Supported Events / 各事件 Output Fields)
/// - CodeBuddy    `@tencent-ai/codebuddy-code` 随包文档
///   `dist/web-ui/docs/cn/cli/hooks.md`(PreToolUse / PostToolUse /
///   Stop·SubagentStop / UserPromptSubmit 决策控制)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The event can stop the action (`deny`).
    pub gate: bool,
    /// The host can prompt the user itself (`ask` / `force_ask`).
    pub ask: bool,
    /// Context can be handed back to the model.
    pub inject: bool,
    /// Tool arguments can be rewritten.
    pub mutate_input: bool,
    /// The tool result can be replaced.
    pub replace_output: bool,
    /// Stop-like events can be told to keep going.
    pub control_flow: bool,
}

impl Capabilities {
    const NONE: Self = Self {
        gate: false,
        ask: false,
        inject: false,
        mutate_input: false,
        replace_output: false,
        control_flow: false,
    };

    const fn new(
        gate: bool,
        ask: bool,
        inject: bool,
        mutate_input: bool,
        replace_output: bool,
        control_flow: bool,
    ) -> Self {
        Self {
            gate,
            ask,
            inject,
            mutate_input,
            replace_output,
            control_flow,
        }
    }
}

/// Static capability matrix.
///
/// Implemented as a plain `match` so it compiles to a jump table / constant
/// folding — the hook hot path must not pay for the abstraction.
#[must_use]
pub fn capabilities(platform: Platform, event: HookEvent) -> Capabilities {
    use HookEvent as E;
    use Platform as P;

    match (platform, event) {
        // ------------------------------------------------------------------
        // Pre-tool gate: the only event where all five primitives can appear.
        // ------------------------------------------------------------------
        (P::ClaudeCode | P::OpenCode, E::PreToolUse) => {
            Capabilities::new(true, true, true, true, false, false)
        }
        // Codex: official docs — `permissionDecision:"ask"` is "parsed but not
        // supported yet. Codex marks the hook run as failed, reports the
        // error, and continues the tool call." Emitting an ask is therefore a
        // silent ALLOW, so the protocol ask channel is closed here and
        // confirmations fall back to ai-hook's GUI (or fail-closed deny).
        (P::Codex, E::PreToolUse) => Capabilities::new(true, false, true, true, false, false),
        (P::CodeBuddy | P::WorkBuddy, E::PreToolUse) => {
            Capabilities::new(true, true, true, true, false, false)
        }
        // Antigravity PreToolUse: 官方输出字段表(antigravity.google/docs/hooks/ 与
        // /docs/ide/hooks.md)只有 `decision` / `reason` / `permissionOverrides`
        // 三项 —— 没有改写参数的通道。任何改写形态(如 `overwrite`)都未被官方
        // 文档记载,发出去只会让宿主按 `decision:"allow"` 放行**原始**参数,
        // 规则却以为改写成功了 —— 比"丢弃并告警"危险得多。故 mutate_input=false。
        (P::Antigravity, E::PreToolUse) => {
            Capabilities::new(true, true, false, false, false, false)
        }
        // Gemini BeforeTool: official reference documents
        // `hookSpecificOutput.tool_input` as an object that "merges with and
        // overrides the model's arguments before execution".
        // 该事件的 Output Fields 只列了 `decision` / `reason` / `tool_input` /
        // `continue`:没有 `additionalContext`,所以 inject 无通道(官方
        // `systemMessage` 的定义是 "Displayed immediately to the user in the
        // terminal",是给用户的,不是模型上下文,不能拿它顶替 inject)。
        (P::Gemini, E::BeforeTool) => Capabilities::new(true, false, false, true, false, false),
        (P::Generic, E::PreToolUse) => Capabilities::new(true, false, true, true, false, false),

        // ------------------------------------------------------------------
        // Post-tool: nothing can be undone; only feedback is possible.
        // ------------------------------------------------------------------
        (
            P::ClaudeCode | P::CodeBuddy | P::WorkBuddy | P::OpenCode | P::Generic,
            E::PostToolUse,
        ) => Capabilities::new(false, false, true, false, true, false),
        // Codex `decision:"block"` here does not undo the command — it
        // replaces the tool result with the hook's feedback.
        (P::Codex, E::PostToolUse) => Capabilities::new(false, false, true, false, true, false),
        // Antigravity PostToolUse output is literally `{}`.
        (P::Antigravity, E::PostToolUse) => Capabilities::NONE,
        // Gemini AfterTool: `decision:"deny"` + reason replaces the result the
        // model sees; `hookSpecificOutput.additionalContext` appends to it.
        (P::Gemini, E::AfterTool) => Capabilities::new(false, false, true, false, true, false),

        // ------------------------------------------------------------------
        // PostToolUseFailure: the tool already ran and failed, so nothing is
        // undone either — but the Decision control table puts it in the
        // top-level `decision` group, so `decision:"block"` carries the
        // feedback. `additionalContext` is the documented injection channel.
        // ------------------------------------------------------------------
        // CodeBuddy / WorkBuddy 官方事件表(@tencent-ai/codebuddy-code 随包
        // hooks.md)不含 PostToolUseFailure,宿主不会触发该事件;不要为它
        // 声明能力,否则矩阵会暗示一个并不存在的门禁点。
        (P::ClaudeCode | P::Codex | P::OpenCode | P::Generic, E::PostToolUseFailure) => {
            Capabilities::new(true, false, true, false, false, false)
        }

        // ------------------------------------------------------------------
        // Prompt gate. The prompt-submit protocol has NO ask channel: its
        // blocking shape is the top-level `decision: "block"` only, so an
        // `ask` here would be ignored (fail-open) — confirms on this event
        // go through ai-hook's own GUI instead.
        // ------------------------------------------------------------------
        (P::ClaudeCode | P::CodeBuddy | P::WorkBuddy | P::OpenCode, E::UserPromptSubmit) => {
            Capabilities::new(true, false, true, false, false, false)
        }
        (P::Codex, E::UserPromptSubmit) => {
            Capabilities::new(true, false, true, false, false, false)
        }
        // Gemini BeforeAgent: `hookSpecificOutput.additionalContext` is
        // appended to the prompt; `decision:"deny"` blocks the turn.
        (P::Gemini, E::BeforeAgent) => Capabilities::new(true, false, true, false, false, false),
        (P::Generic, E::UserPromptSubmit) => {
            Capabilities::new(true, false, true, false, false, false)
        }

        // ------------------------------------------------------------------
        // Turn end: the only decision is "keep going".
        // Gemini has no Stop event; AfterAgent's `decision:"deny"` rejects the
        // response and forces a retry, which is the same "keep going" intent.
        // ------------------------------------------------------------------
        // Claude Code 官方决策控制表原文:Stop / SubagentStop 走顶层
        // `decision:"block"`,且 "**also accept** hookSpecificOutput.additionalContext
        // for non-error feedback that continues the conversation" —— 所以这两个
        // 事件是有 inject 通道的(与 `decision:"block"` 的区别只是会不会被标成
        // hook error)。OpenCode 桥转发 CC 形态,同此。
        (P::ClaudeCode | P::OpenCode, E::Stop | E::SubagentStop) => {
            Capabilities::new(false, false, true, false, false, true)
        }
        // Codex 官方 Stop 只记载 `decision:"block"` + `reason`;CodeBuddy 官方
        // Stop/SubagentStop 只记载 `continue:false` + `reason`。两者都没有
        // additionalContext 通道。
        (P::Codex | P::CodeBuddy | P::WorkBuddy | P::Generic, E::Stop | E::SubagentStop) => {
            Capabilities::new(false, false, false, false, false, true)
        }
        (P::Antigravity, E::Stop | E::SubagentStop) => {
            Capabilities::new(false, false, false, false, false, true)
        }
        (P::Gemini, E::AfterAgent) => Capabilities::new(false, false, false, false, false, true),

        // ------------------------------------------------------------------
        // Session start: advisory context only (never blocks).
        // ------------------------------------------------------------------
        (
            P::ClaudeCode
            | P::Codex
            | P::CodeBuddy
            | P::WorkBuddy
            | P::OpenCode
            | P::Gemini
            | P::Generic,
            E::SessionStart,
        ) => Capabilities::new(false, false, true, false, false, false),
        // SessionEnd has "no decision control" on the Claude family; Gemini
        // still accepts a `systemMessage` shown during shutdown.
        (P::Gemini, E::SessionEnd) => Capabilities::new(false, false, true, false, false, false),
        // SubagentStart: context injection only (official event lists of Claude
        // Code, Codex and CodeBuddy all include it, and all three document
        // `hookSpecificOutput.additionalContext` for it).
        (
            P::ClaudeCode | P::Codex | P::CodeBuddy | P::WorkBuddy | P::OpenCode | P::Generic,
            E::SubagentStart,
        ) => Capabilities::new(false, false, true, false, false, false),
        // PostCompact 刻意**不给** inject:
        // - Claude Code 官方决策控制表把它和 Setup / Notification / SessionEnd
        //   并列为 "None. No decision control."
        // - Codex 官方只记载 `continue: false`(Common output fields)
        // - CodeBuddy / WorkBuddy 官方没有 PostCompact 的决策控制节
        // 三处都没有 additionalContext 通道,声明它只会让规则以为注入成功了。
        // Setup has NO capability row on any host. Claude Code's official
        // Setup decision control is explicit: "On every exit code, Claude
        // Code discards a Setup hook's JSON output fields, such as
        // systemMessage, continue, and hookSpecificOutput.additionalContext."
        // CodeBuddy lists Setup among its events but documents no output
        // channel for it, so nothing is claimed there either. Rules may still
        // observe Setup through ctx.event; decisions on it fall through the
        // wildcard below (NONE).

        // ------------------------------------------------------------------
        // Antigravity invocation hooks: the only place it accepts context
        // (`injectSteps`). Pre/Post cannot be told apart — the official stdin
        // schema is identical for both (`invocationNum` + `initialNumSteps`),
        // and payloads carry no event name, so `input.rs` classifies both as
        // `PreInvocation`.
        //
        // PostInvocation's `terminationBehavior` (`force_continue` /
        // `terminate`) is therefore deliberately NOT modelled as `flow`:
        // emitting it requires knowing the event is PostInvocation, which is
        // impossible from the payload, and `PreInvocation` does not document
        // that field — sending it there is undefined behaviour. The AGY form
        // of "keep going" (`decision:"continue"`) belongs to `Stop` only.
        // ------------------------------------------------------------------
        (P::Antigravity, E::PreInvocation | E::PostInvocation) => {
            Capabilities::new(false, false, true, false, false, false)
        }

        // Gemini PreCompress is advisory: `systemMessage` only.
        (P::Gemini, E::PreCompress) => Capabilities::new(false, false, true, false, false, false),

        // ------------------------------------------------------------------
        // Permission request: allow / deny the pending approval prompt.
        // ------------------------------------------------------------------
        // CodeBuddy / WorkBuddy 官方事件表不含 PermissionRequest(见
        // PostToolUseFailure 处的说明),不为其声明能力。
        (P::ClaudeCode | P::Codex | P::OpenCode, E::PermissionRequest) => {
            Capabilities::new(true, false, true, false, false, false)
        }

        // ------------------------------------------------------------------
        // Compaction gate
        // ------------------------------------------------------------------
        // gate 为 true,但**各宿主的阻断形态不同**,由 output.rs 分别渲染:
        // - Claude Code:官方决策控制表把 PreCompact 列入顶层 `decision:"block"` 组
        // - Codex:官方原文只给出 `continue: false`("Codex stops before compacting")
        // - CodeBuddy / WorkBuddy:官方只记载退出码 2 阻止压缩
        (P::ClaudeCode | P::CodeBuddy | P::WorkBuddy | P::Codex, E::PreCompact) => {
            Capabilities::new(true, false, false, false, false, false)
        }

        // Anything unmodelled: observing is fine, deciding is not.
        _ => Capabilities::NONE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_ask_is_closed_because_it_fails_open() {
        // Official (learn.chatgpt.com/docs/hooks): `permissionDecision:"ask"`
        // is "parsed but not supported yet. Codex marks the hook run as
        // failed, reports the error, and continues the tool call." Emitting an
        // ask would silently ALLOW the very call the rule wanted reviewed.
        assert!(!capabilities(Platform::Codex, HookEvent::PreToolUse).ask);
        // The gate itself still works: deny + non-empty reason is honored.
        assert!(capabilities(Platform::Codex, HookEvent::PreToolUse).gate);
        // UserPromptSubmit has no protocol ask on any host (top-level
        // `decision: "block"` is its only blocking shape).
        assert!(!capabilities(Platform::Codex, HookEvent::UserPromptSubmit).ask);
        assert!(!capabilities(Platform::ClaudeCode, HookEvent::UserPromptSubmit).ask);
        // Claude Code / CodeBuddy / WorkBuddy do honor ask, even in bypass
        // mode: official PreToolUse decision control says `"ask" prompts the
        // user to confirm`, and that "A hook's `"ask"` also forces a permission
        // prompt in auto mode" (both sentences verified present on
        // https://code.claude.com/docs/en/hooks as of 2026-09-07).
        assert!(capabilities(Platform::ClaudeCode, HookEvent::PreToolUse).ask);
        assert!(capabilities(Platform::CodeBuddy, HookEvent::PreToolUse).ask);
        assert!(capabilities(Platform::WorkBuddy, HookEvent::PreToolUse).ask);
        // Gemini has no ask in its protocol at all.
        assert!(!capabilities(Platform::Gemini, HookEvent::BeforeTool).ask);
    }

    #[test]
    fn post_tool_use_failure_is_modelled() {
        // Claude Code lists PostToolUseFailure in the top-level `decision`
        // group and documents `hookSpecificOutput.additionalContext` for it.
        let caps = capabilities(Platform::ClaudeCode, HookEvent::PostToolUseFailure);
        assert!(caps.gate);
        assert!(caps.inject);
        assert!(!caps.replace_output);
        // PostToolUse itself still cannot gate.
        assert!(!capabilities(Platform::ClaudeCode, HookEvent::PostToolUse).gate);
    }

    #[test]
    fn gemini_after_tool_and_after_agent_are_modelled() {
        let after_tool = capabilities(Platform::Gemini, HookEvent::AfterTool);
        assert!(after_tool.inject);
        assert!(after_tool.replace_output);
        assert!(!after_tool.gate);
        // AfterAgent: `decision:"deny"` rejects the response and forces a
        // retry — the Gemini form of "keep going".
        assert!(capabilities(Platform::Gemini, HookEvent::AfterAgent).control_flow);
        // BeforeAgent accepts additionalContext alongside the prompt.
        assert!(capabilities(Platform::Gemini, HookEvent::BeforeAgent).inject);
    }

    #[test]
    fn post_tool_use_cannot_gate() {
        assert!(!capabilities(Platform::ClaudeCode, HookEvent::PostToolUse).gate);
        assert!(!capabilities(Platform::Codex, HookEvent::PostToolUse).gate);
        assert!(!capabilities(Platform::Antigravity, HookEvent::PostToolUse).gate);
    }

    #[test]
    fn antigravity_has_no_additional_context() {
        assert!(!capabilities(Platform::Antigravity, HookEvent::PreToolUse).inject);
        assert!(capabilities(Platform::Antigravity, HookEvent::PreInvocation).inject);
    }

    #[test]
    fn unmodelled_events_are_inert() {
        assert_eq!(
            capabilities(Platform::ClaudeCode, HookEvent::Other),
            Capabilities::NONE
        );
    }
}
