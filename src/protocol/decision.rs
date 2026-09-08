use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Non-gating changes a rule can ask for on top of "let it through".
///
/// All four are optional and can be combined; the renderer drops the ones the
/// host cannot express and reports the rest through stderr.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Mutation {
    /// Text handed to **the model** (`additionalContext` / `injectSteps`).
    pub inject: Option<String>,
    /// Text shown to **the user only** (`systemMessage`), never fed to the
    /// model. Used when a rule asked to inject context on an event whose only
    /// text channel is the user-facing one (Gemini `SessionEnd` /
    /// `PreCompress`, for example).
    pub notify: Option<String>,
    /// Replacement tool arguments (`updatedInput` / `modifiedInput`).
    pub mutate_input: Option<Value>,
    /// Replacement tool result (`updatedToolOutput` / feedback).
    ///
    /// A `Value::String` is what text-block hosts expect (CodeBuddy wraps it).
    /// Structured values (object/array) let a rule match a host's tool-output
    /// shape — Claude Code ignores an `updatedToolOutput` whose value does not
    /// match the tool's output schema (Bash is `{stdout, stderr, interrupted,
    /// isImage}`), so only a structured value can replace those results.
    pub replace_output: Option<Value>,
}

impl Mutation {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inject.is_none()
            && self.notify.is_none()
            && self.mutate_input.is_none()
            && self.replace_output.is_none()
    }
}

/// A rule's decision, expressed **without** any host protocol knowledge.
///
/// The renderer (`protocol::output`) is the only place that knows that
/// "ask" is `permissionDecision:"ask"` on Claude Code but `{"decision":
/// "force_ask"}` on Antigravity, and that Codex fails open when it receives an
/// `ask` it cannot honour.
#[derive(Debug, Clone, PartialEq)]
pub enum HookDecision {
    /// No objection: let the action through.
    Allow,
    /// Ask the user (host prompt or ai-hook's own GUI dialog).
    Confirm {
        reason: String,
        title: Option<String>,
        gui: Option<bool>,
        timeout: Option<u32>,
        force_gui: Option<bool>,
    },
    /// Stop the action.
    Deny { reason: String },
    /// Let it through while injecting context / rewriting arguments / replacing
    /// the tool result.
    Modify(Mutation),
    /// Stop-like events: keep the agent going with this feedback.
    KeepGoing { reason: String },
}
