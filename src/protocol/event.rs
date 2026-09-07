use serde::{Deserialize, Serialize};

/// Canonical lifecycle event of a host hook invocation.
///
/// Only events ai-hook can actually **render** get their own variant: an
/// event that has no renderer path would let rule authors write rules that
/// silently do nothing. Everything else collapses into [`HookEvent::Other`]
/// and is still forwarded to rules through `ctx.event` (the raw host string),
/// so a new host event is never lost — it just cannot drive a decision yet.
/// (One deliberate exception: a payload that carries a Claude-Code tool
/// envelope but an unknown event name falls back to [`HookEvent::PreToolUse`]
/// in `input.rs`, because the tool envelope itself proves a gate is in
/// progress; the unknown name stays visible as `ctx.eventRaw`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HookEvent {
    // --- Tool lifecycle (Claude Code / Codex / CodeBuddy / WorkBuddy) ---
    PreToolUse,
    PostToolUse,
    PostToolUseFailure,
    PermissionRequest,
    // --- Prompt / turn ---
    UserPromptSubmit,
    Stop,
    SubagentStart,
    SubagentStop,
    PreCompact,
    PostCompact,
    // --- Session ---
    SessionStart,
    SessionEnd,
    Setup,
    // --- Antigravity ---
    PreInvocation,
    PostInvocation,
    // --- Gemini CLI ---
    BeforeTool,
    AfterTool,
    BeforeAgent,
    AfterAgent,
    /// Gemini CLI's pre-compaction event. Advisory only: the official docs say
    /// it "cannot block or modify the compression process", so it is neither a
    /// gate nor a post event.
    PreCompress,
    /// A host event ai-hook does not model yet (`ctx.event` still carries the
    /// raw name). Rules may observe it but cannot decide on it.
    Other,
}

impl HookEvent {
    /// Maps a host-supplied event name onto the canonical enum.
    ///
    /// Hosts disagree on casing and naming (Codex/CodeBuddy mirror Claude
    /// Code's `hook_event_name`, Antigravity sends no event name at all,
    /// Gemini CLI uses `BeforeTool`/`AfterTool`), so the lookup is a plain
    /// literal match and everything unknown stays `Other`.
    #[must_use]
    pub fn from_name(name: Option<&str>) -> Self {
        let Some(name) = name.map(str::trim) else {
            return Self::Other;
        };
        match name {
            "PreToolUse" => Self::PreToolUse,
            "PostToolUse" => Self::PostToolUse,
            "PostToolUseFailure" => Self::PostToolUseFailure,
            "PermissionRequest" => Self::PermissionRequest,
            "UserPromptSubmit" => Self::UserPromptSubmit,
            "Stop" => Self::Stop,
            "SubagentStart" => Self::SubagentStart,
            "SubagentStop" => Self::SubagentStop,
            "PreCompact" => Self::PreCompact,
            "PostCompact" => Self::PostCompact,
            "SessionStart" => Self::SessionStart,
            "SessionEnd" => Self::SessionEnd,
            "Setup" => Self::Setup,
            "PreInvocation" => Self::PreInvocation,
            "PostInvocation" => Self::PostInvocation,
            "BeforeTool" => Self::BeforeTool,
            "AfterTool" => Self::AfterTool,
            "BeforeAgent" => Self::BeforeAgent,
            "AfterAgent" => Self::AfterAgent,
            "PreCompress" => Self::PreCompress,
            _ => Self::Other,
        }
    }

    /// Canonical name, or `""` for [`HookEvent::Other`] (callers should fall
    /// back to the raw host event string in that case).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
            Self::PostToolUseFailure => "PostToolUseFailure",
            Self::PermissionRequest => "PermissionRequest",
            Self::UserPromptSubmit => "UserPromptSubmit",
            Self::Stop => "Stop",
            Self::SubagentStart => "SubagentStart",
            Self::SubagentStop => "SubagentStop",
            Self::PreCompact => "PreCompact",
            Self::PostCompact => "PostCompact",
            Self::SessionStart => "SessionStart",
            Self::SessionEnd => "SessionEnd",
            Self::Setup => "Setup",
            Self::PreInvocation => "PreInvocation",
            Self::PostInvocation => "PostInvocation",
            Self::BeforeTool => "BeforeTool",
            Self::AfterTool => "AfterTool",
            Self::BeforeAgent => "BeforeAgent",
            Self::AfterAgent => "AfterAgent",
            Self::PreCompress => "PreCompress",
            Self::Other => "",
        }
    }

    /// Host-independent event name exposed to rules as `ctx.event`.
    ///
    /// This is the Claude-Code spelling every hook-compatible host is measured
    /// against, so `ctx.event === "PostToolUse"` works identically on Gemini
    /// (`AfterTool`) and everywhere else. Only events with a clear 1:1
    /// counterpart are folded; host-specific events (Antigravity's
    /// invocation hooks) keep their own name rather than being force-mapped.
    /// The host's original spelling stays available as `ctx.eventRaw`, and
    /// the wire output keeps using [`Self::as_str`] because hosts validate
    /// `hookEventName` against the event they actually fired.
    #[must_use]
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::BeforeTool => "PreToolUse",
            Self::AfterTool => "PostToolUse",
            Self::BeforeAgent => "UserPromptSubmit",
            Self::AfterAgent => "Stop",
            Self::PreCompress => "PreCompact",
            other => other.as_str(),
        }
    }

    /// True for events whose decision is a gate over a tool call or prompt.
    #[must_use]
    pub fn is_gate_event(self) -> bool {
        matches!(
            self,
            Self::PreToolUse
                | Self::UserPromptSubmit
                | Self::PreCompact
                | Self::PermissionRequest
                | Self::BeforeTool
                | Self::BeforeAgent
        )
    }

    /// True for events that hand the tool result back (nothing can be undone).
    #[must_use]
    pub fn is_post_event(self) -> bool {
        matches!(
            self,
            Self::PostToolUse
                | Self::PostToolUseFailure
                | Self::PostInvocation
                | Self::AfterTool
                | Self::AfterAgent
        )
    }

    /// True for Stop-like events where the only decision is "keep going".
    #[must_use]
    pub fn is_turn_end_event(self) -> bool {
        matches!(self, Self::Stop | Self::SubagentStop | Self::AfterAgent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_name_maps_known_events() {
        assert_eq!(
            HookEvent::from_name(Some("PreToolUse")),
            HookEvent::PreToolUse
        );
        assert_eq!(
            HookEvent::from_name(Some("BeforeTool")),
            HookEvent::BeforeTool
        );
        assert_eq!(HookEvent::from_name(None), HookEvent::Other);
        assert_eq!(
            HookEvent::from_name(Some("TaskCompleted")),
            HookEvent::Other
        );
    }

    #[test]
    fn classification_is_consistent() {
        assert!(HookEvent::PreToolUse.is_gate_event());
        assert!(HookEvent::PostToolUse.is_post_event());
        assert!(HookEvent::Stop.is_turn_end_event());
        assert!(HookEvent::AfterAgent.is_turn_end_event());
        assert!(!HookEvent::Stop.is_gate_event());
    }
}
