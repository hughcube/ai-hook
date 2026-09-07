use super::event::HookEvent;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Antigravity,
    Codex,
    ClaudeCode,
    CodeBuddy,
    /// WorkBuddy Desktop / CLI: same engine as CodeBuddy (the package ships no
    /// `workbuddy` binary) but a separate config dir and a distinct host id.
    WorkBuddy,
    /// Gemini CLI (`BeforeTool` / `AfterTool` / ... event names).
    Gemini,
    /// Reached through a community bridge (opencode-claude-hooks) that
    /// forwards Claude-Code-shaped envelopes to a child process.
    OpenCode,
    Generic,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Antigravity => write!(f, "antigravity"),
            Platform::Codex => write!(f, "codex"),
            Platform::ClaudeCode => write!(f, "claude_code"),
            Platform::CodeBuddy => write!(f, "codebuddy"),
            Platform::WorkBuddy => write!(f, "workbuddy"),
            Platform::Gemini => write!(f, "gemini"),
            Platform::OpenCode => write!(f, "opencode"),
            Platform::Generic => write!(f, "generic"),
        }
    }
}

/// What a file-oriented tool intends to do with the target file. Normalized
/// across hosts from the tool name (see `normalize_file_operation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FileAction {
    Read,
    Write,
    Edit,
    Delete,
    List,
    #[default]
    Other,
}

impl FileAction {
    pub fn as_str(self) -> &'static str {
        match self {
            FileAction::Read => "read",
            FileAction::Write => "write",
            FileAction::Edit => "edit",
            FileAction::Delete => "delete",
            FileAction::List => "list",
            FileAction::Other => "other",
        }
    }
}

/// What a web-oriented tool intends to do: fetch a URL or run a search.
/// Normalized across hosts (Claude Code / Codex `WebFetch`/`WebSearch`,
/// Antigravity `search_web`/`read_url_content`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum WebAction {
    Fetch,
    Search,
    #[default]
    Other,
}

impl WebAction {
    pub fn as_str(self) -> &'static str {
        match self {
            WebAction::Fetch => "fetch",
            WebAction::Search => "search",
            WebAction::Other => "other",
        }
    }
}

/// What a code-search tool does: match file paths (glob) or file contents
/// (grep).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SearchKind {
    #[default]
    Glob,
    Grep,
}

impl SearchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SearchKind::Glob => "glob",
            SearchKind::Grep => "grep",
        }
    }
}

/// What a delegation tool does: spawn a subagent, run a workflow, or create
/// a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum AgentKind {
    #[default]
    Agent,
    Workflow,
    Task,
}

impl AgentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentKind::Agent => "agent",
            AgentKind::Workflow => "workflow",
            AgentKind::Task => "task",
        }
    }
}

/// Normalized view of an MCP tool invocation. Tool names differ per host
/// (`mcp__server__tool` on Claude Code / Codex / CodeBuddy, `mcp_server_tool`
/// on Gemini CLI), so the pair is split out host-free; the parameters are
/// server-defined and stay in `ctx.args` verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpContext {
    pub server: Option<String>,
    pub tool: Option<String>,
}

/// Normalized view of a web fetch / search invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebContext {
    pub action: WebAction,
    pub url: Option<String>,
    pub query: Option<String>,
}

/// Normalized view of a code-search (glob / grep) invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchContext {
    pub kind: SearchKind,
    pub path: Option<String>,
    pub pattern: Option<String>,
}

/// Normalized view of a delegation (subagent / workflow / task) invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContext {
    pub kind: AgentKind,
    /// The delegated job's goal — `description` on Claude Code `Agent` /
    /// Codex `Agent`, `name` on `Workflow`.
    pub description: Option<String>,
    /// Instructions handed to the delegate, when the host provides one.
    pub prompt: Option<String>,
}

/// Session identity handed to the hook by the host (when provided).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationInfo {
    pub id: Option<String>,
    /// Absolute path of the full conversation transcript (JSONL) — rules may
    /// read it via `sys.fs.readText()` for context-aware decisions.
    pub transcript_path: Option<String>,
}

/// Normalized view of a file-touching tool invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContext {
    pub path: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub action: FileAction,
}

/// Fully parsed and normalized hook context (one semantic per property —
/// no aliases). `raw` / `rawInput` always carry the complete original payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    pub platform: Platform,
    /// Host permission mode verbatim, e.g. "default" | "plan" | "acceptEdits"
    /// | "dontAsk" | "bypassPermissions" (hosts that provide it).
    pub permission_mode: Option<String>,
    /// True when the host will not ask for confirmation
    /// (permission_mode bypassPermissions/dontAsk, or AGY skip flag).
    pub is_yolo: bool,
    pub conversation: Option<ConversationInfo>,
    /// Working directory of the command / session.
    pub cwd: String,
    pub model: Option<String>,
    /// Canonical host tool name (e.g. "Bash", "run_command", "Write", "Edit").
    pub tool_name: String,
    /// Normalized command line — only for command tools (e.g. Bash,
    /// run_command); `None` for every other tool.
    pub cmd: Option<String>,
    /// Normalized file view — only for file tools; `None` otherwise.
    pub file: Option<FileContext>,
    /// Normalized MCP view — only for `mcp__…` / `mcp_…` tools; `None`
    /// otherwise. Parameters stay in `ctx.args` (server-defined).
    pub mcp: Option<McpContext>,
    /// Normalized web fetch/search view — only for web tools; `None` otherwise.
    pub web: Option<WebContext>,
    /// Normalized code-search view — only for glob/grep tools; `None`
    /// otherwise.
    pub search: Option<SearchContext>,
    /// Normalized delegation view — only for subagent/workflow/task tools;
    /// `None` otherwise.
    pub agent: Option<AgentContext>,
    /// Tool arguments exactly as the host provided them.
    pub args: serde_json::Value,
    /// Lifecycle event name (e.g. "PreToolUse", "PostToolUse", "UserPromptSubmit").
    pub event: Option<String>,
    /// The host's own event spelling, verbatim — `None` when the host does not
    /// send one (Antigravity). Exposed to rules as `ctx.eventRaw`; must NOT be
    /// back-filled with the inferred canonical name, or rules would mistake
    /// the inference for a host spelling.
    pub event_raw: Option<String>,
    /// Canonical event derived from `event`, or from the envelope shape when
    /// the host (Antigravity) sends no event name at all.
    pub event_enum: HookEvent,
    /// User prompt verbatim — only for prompt-oriented events (e.g. UserPromptSubmit).
    pub prompt: Option<String>,
    /// Raw payload as text and as parsed JSON (always available).
    pub raw_input: String,
    pub raw_value: serde_json::Value,
    /// True when the raw payload could not be parsed as JSON at all. No tool
    /// semantics are available in that case; callers should ask the operator
    /// instead of silently running rules against an empty view.
    pub parse_failed: bool,
}

/// Single source of truth for boolean environment flags, so CLI and env
/// detection never diverge: accepts `1`/`true` (case-insensitive), trimmed.
pub fn env_flag_true(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

fn current_dir_string() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn get_str<'a>(val: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(v) = val.get(*k).and_then(|v| v.as_str()) {
            return Some(v);
        }
    }
    None
}

/// Resolves the canonical event, falling back to `fallback` when the host sent
/// no event name or an unmodelled one. Antigravity never sends an event name,
/// so its envelope is classified by shape instead (see
/// [`antigravity_event`]).
fn event_or(event: Option<&str>, fallback: HookEvent) -> HookEvent {
    match HookEvent::from_name(event) {
        HookEvent::Other => fallback,
        known => known,
    }
}

/// Classifies an Antigravity payload by shape.
///
/// Official stdin carries no event name — the documented common fields are
/// only `conversationId` / `workspacePaths` / `transcriptPath` /
/// `artifactDirectoryPath` / `modelName` — so the event must be inferred:
///
/// - `executionNum` / `terminationReason` / `fullyIdle` → `Stop`
///   (all three are official Stop-only stdin fields; checking the trio
///   instead of one key keeps a partially-populated Stop payload classifiable)
/// - `invocationNum` / `initialNumSteps` → `PreInvocation`
///   (the official PostInvocation schema is byte-identical to PreInvocation's
///   and both render as `injectSteps`, so Pre/Post are deliberately merged)
/// - everything else (including `toolCall`) → `PreToolUse`
///
/// `PostToolUse` is deliberately NOT inferred from the `error` key: its
/// presence is not documented for PreToolUse, and a misclassification would
/// drop the gate capability — i.e. fail **open**. AGY's PostToolUse output is
/// `{}` anyway, so nothing is lost by staying on PreToolUse.
fn antigravity_event(val: &serde_json::Value) -> HookEvent {
    if val.get("executionNum").is_some()
        || val.get("fullyIdle").is_some()
        || val.get("terminationReason").is_some()
    {
        HookEvent::Stop
    } else if val.get("invocationNum").is_some() {
        HookEvent::PreInvocation
    } else {
        HookEvent::PreToolUse
    }
}

/// Gemini CLI uses its own event vocabulary; these names are unambiguous
/// (`SessionStart` / `SessionEnd` / `Notification` are shared with the Claude
/// family, so they are deliberately not used for detection).
const GEMINI_EVENTS: &[&str] = &[
    "BeforeTool",
    "AfterTool",
    "BeforeAgent",
    "AfterAgent",
    "BeforeModel",
    "AfterModel",
    "BeforeToolSelection",
    "PreCompress",
];

/// Detects which Claude-Code-shaped host produced this payload.
///
/// Claude Code, Codex, CodeBuddy and WorkBuddy all send the same envelope
/// shape, so the product has to be told apart by side channels. Ordered by
/// reliability: payload marker > string sniffing > product-identity env.
/// Session-scoped env vars are not usable as a signal (see the note at the
/// `CODEBUDDY_HOST` check below), so the last resort is always Claude Code.
///
/// The payload sniff is deliberately limited to `transcript_path`: it is a
/// host-controlled field whose location carries the real product name
/// (`~/.claude/projects/…` vs `~/.codebuddy/…` vs `~/.workbuddy/…` vs
/// `~/.gemini/…`). Scanning the whole JSON would let attacker-controlled
/// content (e.g. a Bash command containing the word "codebuddy") flip the
/// detected platform, so it is not done.
fn detect_cc_family(val: &serde_json::Value, _raw_json: &str) -> Platform {
    // `turn_id` is a documented Codex-only extension.
    if val.get("turn_id").is_some() {
        return Platform::Codex;
    }
    if let Some(name) = val.get("hook_event_name").and_then(|v| v.as_str())
        && GEMINI_EVENTS.contains(&name)
    {
        return Platform::Gemini;
    }
    // OpenCode has no process hook protocol of its own; the community bridge
    // (opencode-claude-hooks) forwards Claude Code envelopes and marks them.
    if env_flag_true("OPENCODE_COMPAT") {
        return Platform::OpenCode;
    }
    // Transcript path sniff (host-controlled; see the function doc).
    if let Some(tp) = get_str(val, &["transcript_path", "transcriptPath"]) {
        let tp = tp.to_ascii_lowercase();
        if tp.contains("workbuddy") {
            return Platform::WorkBuddy;
        }
        if tp.contains("codebuddy") {
            return Platform::CodeBuddy;
        }
        if tp.contains(".claude") {
            return Platform::ClaudeCode;
        }
        if tp.contains(".codex") {
            return Platform::Codex;
        }
        if tp.contains(".gemini") {
            return Platform::Gemini;
        }
    }

    // `CODEBUDDY_HOST` carries the product identity itself
    // ("workbuddy-desktop" / "web-ui" / "cli"), so it is the only environment
    // signal strong enough to tell CodeBuddy from Claude Code.
    //
    // `CODEBUDDY_SESSION_ID` / `CODEBUDDY_PROJECT_DIR` are deliberately NOT
    // used as a signal: they are ordinary session/path variables that stay in
    // the environment of anything launched from a CodeBuddy session — including
    // a Claude Code session started from that same shell. Trusting them
    // mis-detects Claude Code as CodeBuddy, which flips Stop / UserPromptSubmit
    // rendering to `{"continue": false}`. On Claude Code `continue: false`
    // means "stop processing entirely" (official: "Takes precedence over any
    // event-specific decision fields") — the exact opposite of the `keepGoing`
    // a rule asked for. The two mistakes are not symmetric, so when the host
    // cannot be told apart the fallback is Claude Code, whose
    // `decision:"block"` degrades to a deprecated-but-honoured shape on
    // CodeBuddy instead of an inverted one on Claude Code.
    //
    // Real payloads do not need this guess: `transcript_path` is a documented
    // common input field and its location names the product
    // (`…/.claude/…`, `…/.codebuddy/…`, `…/.workbuddy/…`).
    if let Ok(host) = std::env::var("CODEBUDDY_HOST") {
        if host.eq_ignore_ascii_case("workbuddy-desktop") {
            return Platform::WorkBuddy;
        }
        if !host.trim().is_empty() {
            return Platform::CodeBuddy;
        }
    }
    Platform::ClaudeCode
}

/// YOLO = host runs without confirmation prompts.
fn permission_mode_is_yolo(mode: &str) -> bool {
    let m = mode.to_ascii_lowercase();
    m.contains("bypass") || m.contains("dontask")
}

/// True for the Google Antigravity envelope.
///
/// Antigravity sends no event name, so it is recognised by its payload shape.
/// The documented common fields are `conversationId` / `workspacePaths` /
/// `transcriptPath` / `artifactDirectoryPath` / `modelName`; tool events add
/// `toolCall`, and `Stop` / `PreInvocation` / `PostInvocation` add
/// `executionNum` / `invocationNum` instead.
///
/// `conversationId` alone is only accepted when the Claude-Code-family markers
/// are absent, so a Gemini CLI or Claude Code payload (which always carries
/// `hook_event_name`) is never misclassified.
fn is_antigravity_envelope(val: &serde_json::Value) -> bool {
    if val.get("toolCall").is_some() {
        return true;
    }
    val.get("conversationId").is_some()
        && val.get("hook_event_name").is_none()
        && val.get("tool_input").is_none()
        && val.get("tool_name").is_none()
}

/// True for hosts that mirror the Claude Code envelope
/// (`hook_event_name` + `tool_name` + `tool_input`).
fn has_claude_envelope(val: &serde_json::Value) -> bool {
    val.get("tool_input").is_some()
        || val.get("toolInput").is_some()
        || val.get("tool_name").is_some()
        || val.get("toolName").is_some()
}

/// Extracts all target paths (and their actions) from a Codex
/// `apply_patch` patch body. Only the header lines are inspected:
///
/// ```text
/// *** Begin Patch
/// *** Update File: src/lib.rs
/// ```
///
/// `Update` maps to [`FileAction::Edit`], `Add` to Write and `Delete` to
/// Delete. Returns all targets found, preserving order without duplicates.
fn extract_patch_targets(patch: &str) -> Vec<(String, FileAction)> {
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in patch.lines() {
        let t = line.trim_start();
        let (raw_target, action) = if let Some(rest) = t.strip_prefix("*** Update File:") {
            (rest.trim(), FileAction::Edit)
        } else if let Some(rest) = t.strip_prefix("*** Add File:") {
            (rest.trim(), FileAction::Write)
        } else if let Some(rest) = t.strip_prefix("*** Delete File:") {
            (rest.trim(), FileAction::Delete)
        } else {
            continue;
        };
        if !raw_target.is_empty() && seen.insert(raw_target.to_string()) {
            targets.push((raw_target.to_string(), action));
        }
    }
    targets
}

/// Classifies command/file tools and extracts the normalized payload for the
/// tool the host is about to invoke.
/// The result of normalizing one tool invocation: at most one of the six
/// semantic views is populated (command / file / mcp / web / search / agent);
/// tools we do not model leave all of them empty and stay reachable through
/// `ctx.tool` / `ctx.args` / `ctx.raw`.
#[derive(Debug, Clone, Default)]
struct Normalized {
    cmd: Option<String>,
    file: Option<FileContext>,
    mcp: Option<McpContext>,
    web: Option<WebContext>,
    search: Option<SearchContext>,
    agent: Option<AgentContext>,
}

/// Splits an MCP tool name into server and tool parts, host-agnostically.
///
/// Claude Code / Codex / CodeBuddy use `mcp__server__tool` (double
/// underscore), Gemini CLI uses `mcp_server_tool` (single underscore) — both
/// officially documented name forms. The double-underscore form is tried
/// first; both halves must be non-empty.
fn split_mcp_name(name: &str) -> Option<(String, String)> {
    if let Some(rest) = name.strip_prefix("mcp__")
        && let Some((server, tool)) = rest.split_once("__")
        && !server.is_empty()
        && !tool.is_empty()
    {
        return Some((server.to_string(), tool.to_string()));
    }
    // Single-underscore form (Gemini CLI): mcp_<server>_<tool>. Split at the
    // FIRST underscore after the prefix — the tool half may itself contain
    // underscores (official examples carry tools like search_repositories),
    // exactly as the double-underscore form splits at the first "__".
    if let Some(rest) = name.strip_prefix("mcp_")
        && let Some((server, tool)) = rest.split_once('_')
        && !server.is_empty()
        && !tool.is_empty()
    {
        return Some((server.to_string(), tool.to_string()));
    }
    None
}

/// Classifies command/file/mcp/web/search/agent tools and extracts the
/// normalized payload for the tool the host is about to invoke.
fn normalize_semantics(
    platform: Platform,
    tool_name: &str,
    args: Option<&serde_json::Value>,
) -> Normalized {
    let lower = tool_name.to_ascii_lowercase();
    let args = match args {
        Some(a) if a.is_object() => a,
        _ => return Normalized::default(),
    };

    // 1. Command tools: a single shell command string.
    let command_keys = match platform {
        Platform::Antigravity => &["CommandLine", "command", "cmd"][..],
        _ => &["command", "CommandLine", "cmd"][..],
    };
    // "run_shell_command" is Gemini CLI's registered shell tool name
    // (official Tools reference, geminicli.com/docs/reference/tools); without
    // it every command rule and the fast path are dead on Gemini.
    let command_tools = [
        "bash",
        "run_command",
        "run_shell_command",
        "shell",
        "powershell",
        "command",
        "terminal",
    ];
    if command_tools.contains(&lower.as_str()) {
        return Normalized {
            cmd: get_str(args, command_keys).map(str::to_string),
            ..Normalized::default()
        };
    }

    // 2. MCP tools: `mcp__server__tool` / `mcp_server_tool`. Matched before
    //    the file table so a server-provided file tool is never mistaken for
    //    a host-native one. The parameters are server-defined and are NOT
    //    normalized — `ctx.args` keeps them verbatim.
    if (lower.starts_with("mcp__") || lower.starts_with("mcp_"))
        && let Some((server, tool)) = split_mcp_name(&lower)
    {
        return Normalized {
            mcp: Some(McpContext {
                server: Some(server),
                tool: Some(tool),
            }),
            ..Normalized::default()
        };
    }

    // 3. Web tools: fetch a URL or search the web.
    //    Claude Code / Codex: WebFetch {url, prompt} / WebSearch {query}.
    //    Antigravity (official tool schema): search_web {query},
    //    read_url_content {Url}.
    let web_action = match lower.as_str() {
        "webfetch" | "read_url_content" | "fetch_url" | "url_content" => Some(WebAction::Fetch),
        "websearch" | "search_web" | "web_search" => Some(WebAction::Search),
        _ => None,
    };
    if let Some(action) = web_action {
        let (url, query) = if action == WebAction::Fetch {
            (
                get_str(args, &["url", "Url", "URL"]).map(str::to_string),
                None,
            )
        } else {
            (None, get_str(args, &["query", "Query"]).map(str::to_string))
        };
        return Normalized {
            web: Some(WebContext { action, url, query }),
            ..Normalized::default()
        };
    }

    // 4. Code-search tools: glob (path patterns) / grep (content search).
    //    Claude Code / Codex: Glob {pattern, path}, Grep {pattern, path}.
    //    Antigravity (official tool schema): grep_search {SearchPath, Query}.
    if lower == "grep_search" {
        return Normalized {
            search: Some(SearchContext {
                kind: SearchKind::Grep,
                path: get_str(args, &["SearchPath", "path"]).map(str::to_string),
                pattern: get_str(args, &["Query", "query", "pattern"]).map(str::to_string),
            }),
            ..Normalized::default()
        };
    }
    let search_kind = match lower.as_str() {
        "glob" => Some(SearchKind::Glob),
        "grep" => Some(SearchKind::Grep),
        _ => None,
    };
    if let Some(kind) = search_kind {
        return Normalized {
            search: Some(SearchContext {
                kind,
                path: get_str(args, &["path", "Path"]).map(str::to_string),
                pattern: get_str(args, &["pattern", "Pattern", "query", "Query"])
                    .map(str::to_string),
            }),
            ..Normalized::default()
        };
    }

    // 5. Delegation tools: subagent / workflow / task.
    //    Claude Code: Agent {description, prompt?, subagent_type?},
    //    Workflow {name?, prompt?}. Codex: Agent {description, prompt}.
    //    CodeBuddy: Task {description, prompt?}.
    let agent_kind = match lower.as_str() {
        "agent" | "spawn_agent" | "subagent" | "start_agent" => Some(AgentKind::Agent),
        "workflow" | "run_workflow" => Some(AgentKind::Workflow),
        "task" | "create_task" | "new_task" => Some(AgentKind::Task),
        _ => None,
    };
    if let Some(kind) = agent_kind {
        let description =
            get_str(args, &["description", "Description", "name", "Name"]).map(str::to_string);
        let prompt = get_str(args, &["prompt", "Prompt", "instructions"]).map(str::to_string);
        // A workflow/task without an explicit description often carries the
        // goal in `name`; keep the pair host-free either way.
        let description = description.or_else(|| prompt.clone());
        return Normalized {
            agent: Some(AgentContext {
                kind,
                description,
                prompt,
            }),
            ..Normalized::default()
        };
    }

    // 6. File tools: normalize {path, action} from the tool name.
    // Real Antigravity argument names (official tool schema): view_file /
    // view_file_outline use AbsolutePath; write/replace use TargetFile;
    // list_dir uses DirectoryPath. Gemini CLI (official Tools reference):
    // read_file / write_file / replace use file_path, list_directory uses
    // dir_path. Claude Code / Codex use file_path / path.
    let path_keys: &[&str] = &[
        "file_path",
        "filePath",
        "FilePath",
        "TargetFile",
        "AbsolutePath",
        "DirectoryPath",
        "path",
        "dir_path",
        "file",
    ];

    // Codex `apply_patch` carries its targets inside the patch text
    // ("*** Update File: path") instead of a path argument. Extracting the
    // first target here is what keeps `ctx.file.path` meaningful for it —
    // otherwise every rule that guards file writes has to regex the raw
    // payload itself.
    if lower == "apply_patch"
        && let Some(patch) = get_str(args, &["patchText", "patch_text", "patch", "command"])
    {
        let targets = extract_patch_targets(patch);
        if !targets.is_empty() {
            let (first_path, first_action) = targets[0].clone();
            let all_paths: Vec<String> = targets.into_iter().map(|(p, _)| p).collect();
            return Normalized {
                file: Some(FileContext {
                    path: Some(first_path),
                    paths: all_paths,
                    action: first_action,
                }),
                ..Normalized::default()
            };
        }
    }

    let action = match lower.as_str() {
        // Read ("view" is Claude Code's native file inspection tool;
        // "read_many_files" is Gemini CLI's multi-file reader — it has
        // no single path argument, so the action is set but path stays null)
        "read" | "view" | "view_file" | "read_file" | "read_many_files" => FileAction::Read,
        // Write / create.
        // `write_to_file` is Antigravity's registered name; `write_file` is
        // Gemini CLI's (official Tools reference: args `file_path` + `content`).
        // Modeling only one of them leaves `ctx.file` null on the other host and
        // silently disables every write-protection rule there.
        "write" | "write_file" | "write_to_file" | "create_file" | "overwrite_file" => {
            FileAction::Write
        }
        // Edit (in place) — "replace" is Gemini CLI's registered edit tool
        "edit"
        | "multi_edit"
        | "notebookedit"
        | "apply_patch"
        | "replace"
        | "replace_file_content"
        | "multi_replace_file_content"
        | "edit_file"
        | "modify_file" => FileAction::Edit,
        // Delete
        "delete" | "delete_file" | "remove_file" | "rm" | "remove" | "unlink" | "unlink_file" => {
            FileAction::Delete
        }
        // List directory ("list_directory" is Gemini CLI's registered name)
        "list_dir" | "list_directory" | "list" | "read_dir" => FileAction::List,
        _ => return Normalized::default(), // not a tool we model
    };
    let path = get_str(args, path_keys).map(str::to_string);
    let paths = path.as_ref().map(|p| vec![p.clone()]).unwrap_or_default();
    Normalized {
        file: Some(FileContext {
            path,
            paths,
            action,
        }),
        ..Normalized::default()
    }
}

impl HookContext {
    pub fn parse(raw_json: &str) -> Self {
        let trimmed = raw_json.trim();
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                return Self {
                    platform: Platform::Generic,
                    permission_mode: None,
                    is_yolo: false,
                    conversation: None,
                    cwd: current_dir_string(),
                    model: None,
                    tool_name: String::new(),
                    cmd: None,
                    file: None,
                    mcp: None,
                    web: None,
                    search: None,
                    agent: None,
                    args: serde_json::Value::Null,
                    event: None,
                    event_raw: None,
                    event_enum: HookEvent::Other,
                    prompt: None,
                    raw_input: raw_json.to_string(),
                    raw_value: serde_json::Value::Null,
                    parse_failed: true,
                };
            }
        };

        let event =
            get_str(&val, &["hook_event_name", "hookEventName", "event"]).map(str::to_string);
        let prompt = get_str(&val, &["prompt", "user_prompt", "userPrompt"]).map(str::to_string);

        // ---- 1. Google Antigravity: no event name, classified by shape ----
        if is_antigravity_envelope(&val) {
            let tool_call = val.get("toolCall");
            let tool_name = tool_call
                .and_then(|tc| get_str(tc, &["name", "toolName"]))
                .unwrap_or("")
                .to_string();
            let args = tool_call.and_then(|tc| tc.get("args").or_else(|| tc.get("parameters")));
            let norm = normalize_semantics(Platform::Antigravity, &tool_name, args);

            let conversation = ConversationInfo {
                id: get_str(&val, &["conversationId", "conversation_id"]).map(str::to_string),
                transcript_path: get_str(&val, &["transcriptPath", "transcript_path"])
                    .map(str::to_string),
            };
            let conversation =
                if conversation.id.is_none() && conversation.transcript_path.is_none() {
                    None
                } else {
                    Some(conversation)
                };

            let event_enum = match HookEvent::from_name(event.as_deref()) {
                HookEvent::Other => antigravity_event(&val),
                known => known,
            };

            return Self {
                platform: Platform::Antigravity,
                permission_mode: None,
                is_yolo: if let Some(flag) = val.get("is_yolo").and_then(|v| v.as_bool()) {
                    flag
                } else {
                    env_flag_true("AGY_DANGEROUSLY_SKIP_PERMISSIONS")
                        || get_str(&val, &["permissionMode", "permission_mode"])
                            .map(permission_mode_is_yolo)
                            .unwrap_or(false)
                },
                conversation,
                cwd: args
                    .and_then(|a| get_str(a, &["Cwd", "cwd"]))
                    .map(str::to_string)
                    .or_else(|| {
                        val.get("workspacePaths")
                            .and_then(|v| v.as_array())
                            .and_then(|arr| arr.first())
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(current_dir_string),
                model: get_str(&val, &["modelName"]).map(str::to_string),
                tool_name,
                cmd: norm.cmd,
                file: norm.file,
                mcp: norm.mcp,
                web: norm.web,
                search: norm.search,
                agent: norm.agent,
                args: args.cloned().unwrap_or(serde_json::Value::Null),
                // Antigravity sends no event name; the envelope shape decides
                // which of its five events this is.
                event_enum,
                // `event` keeps the inferred canonical name so rules can
                // dispatch on it; `event_raw` stays None because Antigravity
                // genuinely sends no event name.
                event: Some(event.unwrap_or_else(|| event_enum.as_str().to_string())),
                event_raw: None,
                prompt,
                raw_input: raw_json.to_string(),
                raw_value: val,
                parse_failed: false,
            };
        }

        // ---- 2. Claude-Code-shaped hosts: Codex / Claude Code / CodeBuddy ----
        if has_claude_envelope(&val) {
            let tool_name = get_str(&val, &["tool_name", "toolName"])
                .unwrap_or("")
                .to_string();
            let tool_input = val.get("tool_input").or_else(|| val.get("toolInput"));
            let norm = normalize_semantics(
                Platform::ClaudeCode, // shape is identical for these hosts
                &tool_name,
                tool_input,
            );

            let permission_mode =
                get_str(&val, &["permission_mode", "permissionMode"]).map(str::to_string);
            let is_codex = val.get("turn_id").is_some() || val.get("turnId").is_some();
            let is_yolo = if let Some(flag) = val
                .get("is_yolo")
                .or_else(|| val.get("isYolo"))
                .and_then(|v| v.as_bool())
            {
                flag
            } else {
                (is_codex && env_flag_true("CODEX_DANGEROUSLY_SKIP_PERMISSIONS"))
                    || permission_mode
                        .as_deref()
                        .map(permission_mode_is_yolo)
                        .unwrap_or(false)
            };

            let conversation = ConversationInfo {
                id: get_str(&val, &["session_id", "sessionId"]).map(str::to_string),
                transcript_path: get_str(&val, &["transcript_path", "transcriptPath"])
                    .map(str::to_string),
            };
            let conversation =
                if conversation.id.is_none() && conversation.transcript_path.is_none() {
                    None
                } else {
                    Some(conversation)
                };

            let platform = detect_cc_family(&val, raw_json);

            return Self {
                platform,
                permission_mode,
                is_yolo,
                conversation,
                cwd: get_str(&val, &["cwd", "Cwd"])
                    .map(str::to_string)
                    .unwrap_or_else(current_dir_string),
                model: get_str(&val, &["model", "modelName"]).map(str::to_string),
                tool_name,
                cmd: norm.cmd,
                file: norm.file,
                mcp: norm.mcp,
                web: norm.web,
                search: norm.search,
                agent: norm.agent,
                args: tool_input.cloned().unwrap_or(serde_json::Value::Null),
                event_enum: event_or(event.as_deref(), HookEvent::PreToolUse),
                event: event.clone().or_else(|| Some("PreToolUse".to_string())),
                event_raw: event,
                prompt,
                raw_input: raw_json.to_string(),
                raw_value: val,
                parse_failed: false,
            };
        }

        // ---- 3. UserPromptSubmit envelope ----
        if prompt.is_some() || event.as_deref() == Some("UserPromptSubmit") {
            // Same product disambiguation as the tool envelope: payload
            // markers > string sniffing > product-identity env
            // (`CODEBUDDY_HOST`; session-scoped vars such as
            // `CODEBUDDY_SESSION_ID` are not a reliable signal — see
            // `detect_cc_family`).
            let platform = detect_cc_family(&val, raw_json);

            let conversation = ConversationInfo {
                id: get_str(&val, &["session_id", "sessionId"]).map(str::to_string),
                transcript_path: get_str(&val, &["transcript_path", "transcriptPath"])
                    .map(str::to_string),
            };
            let conversation =
                if conversation.id.is_none() && conversation.transcript_path.is_none() {
                    None
                } else {
                    Some(conversation)
                };

            let permission_mode =
                get_str(&val, &["permission_mode", "permissionMode"]).map(str::to_string);
            return Self {
                platform,
                permission_mode: permission_mode.clone(),
                is_yolo: (platform == Platform::Codex
                    && env_flag_true("CODEX_DANGEROUSLY_SKIP_PERMISSIONS"))
                    || (platform == Platform::Antigravity
                        && env_flag_true("AGY_DANGEROUSLY_SKIP_PERMISSIONS"))
                    || permission_mode
                        .as_deref()
                        .map(permission_mode_is_yolo)
                        .unwrap_or(false),
                conversation,
                cwd: get_str(&val, &["cwd", "Cwd"])
                    .map(str::to_string)
                    .unwrap_or_else(current_dir_string),
                model: get_str(&val, &["model", "modelName"]).map(str::to_string),
                tool_name: String::new(),
                cmd: None,
                file: None,
                mcp: None,
                web: None,
                search: None,
                agent: None,
                args: serde_json::Value::Null,
                event_enum: event_or(event.as_deref(), HookEvent::UserPromptSubmit),
                event: Some(
                    event
                        .clone()
                        .unwrap_or_else(|| "UserPromptSubmit".to_string()),
                ),
                event_raw: event,
                prompt,
                raw_input: raw_json.to_string(),
                raw_value: val,
                parse_failed: false,
            };
        }

        // ---- 4. Non-tool shapes: Stop / SessionStart / PreCompact / ... ----
        // These payloads carry no tool fields, but they still come from a
        // concrete host. When the host told us the event name we can reuse the
        // same product detection as the tool envelope — otherwise Stop /
        // SessionStart / PreCompact payloads would report platform "generic"
        // and lose the host-specific capability rows (e.g. CodeBuddy's
        // `continue:false` Stop shape, Codex's PreCompact gate). Truly
        // unknown hosts (no hook_event_name) stay Generic.
        let platform = if val.get("hook_event_name").is_some() || val.get("hookEventName").is_some()
        {
            detect_cc_family(&val, raw_json)
        } else {
            Platform::Generic
        };
        let permission_mode =
            get_str(&val, &["permission_mode", "permissionMode"]).map(str::to_string);
        let is_yolo = permission_mode
            .as_deref()
            .map(permission_mode_is_yolo)
            .unwrap_or(false);

        // Session identity and model ARE present on these payloads: the
        // Claude-family common input fields carry session_id / transcript_path
        // on every event, and SessionStart additionally carries `model`
        // (official: it "can be omitted, for example after /clear"). Earlier
        // revisions left both None here, so rules on SessionStart / Stop /
        // PreCompact could never read ctx.session / ctx.model.
        let conversation = ConversationInfo {
            id: get_str(&val, &["session_id", "sessionId"]).map(str::to_string),
            transcript_path: get_str(&val, &["transcript_path", "transcriptPath"])
                .map(str::to_string),
        };
        let conversation = if conversation.id.is_none() && conversation.transcript_path.is_none() {
            None
        } else {
            Some(conversation)
        };

        Self {
            platform,
            permission_mode,
            is_yolo,
            conversation,
            cwd: get_str(&val, &["cwd", "Cwd"])
                .map(str::to_string)
                .unwrap_or_else(current_dir_string),
            model: get_str(&val, &["model", "modelName"]).map(str::to_string),
            tool_name: String::new(),
            cmd: None,
            file: None,
            mcp: None,
            web: None,
            search: None,
            agent: None,
            args: serde_json::Value::Null,
            event_enum: event_or(event.as_deref(), HookEvent::Other),
            event_raw: event.clone(),
            event,
            prompt,
            raw_input: raw_json.to_string(),
            raw_value: val,
            parse_failed: false,
        }
    }

    /// 宿主×模式是否具备「协议 ask」能力(官网出处:
    /// - Claude Code `https://code.claude.com/docs/en/hooks`
    ///   原文(PreToolUse decision control):`"ask" prompts the user to
    ///   confirm`;免确认(bypass)模式下 ask 仍弹出亦有官网原文支撑 ——
    ///   同段紧随其后:"A hook's `\"ask\"` also forces a permission prompt in
    ///   auto mode: the classifier can still deny the tool call, but it can't
    ///   approve the call silently."(2026-09-07 第四轮 curl 全文复核确认该句
    ///   仍在现行页;此前一度误记为其已消失,见
    ///   docs/REVIEW_CROSSCHECK_2026-09-06.md §1.9.2)。
    /// - Codex `https://learn.chatgpt.com/docs/hooks`
    ///   原文:"`permissionDecision: "ask"` … are parsed but not supported yet.
    ///   Codex marks the hook run as failed, reports the error, and continues
    ///   the tool call." → 协议 ask 不可用(输出即 fail open),confirm 一律
    ///   走 ai-hook GUI 弹窗,无 GUI 时 fail-closed 拒绝。
    /// - CodeBuddy `@tencent-ai/codebuddy-code` 随包文档
    ///   `dist/web-ui/docs/cn/cli/hooks.md`:`permissionDecision` 取值
    ///   `allow`/`deny`/`ask`,`permissionDecisionReason` 显示在确认对话框。
    /// - Antigravity `https://antigravity.google/docs/hooks/`:`decision` 取值含
    ///   `ask`(尊重 "Always Allow")与 `force_ask`(忽略缓存)。
    /// - Gemini CLI `https://geminicli.com/docs/hooks/reference/`:
    ///   `decision` 仅 `allow`/`deny`(别名 `block`),协议无 ask。
    #[must_use]
    pub fn can_ask(&self) -> bool {
        match self.platform {
            Platform::ClaudeCode
            | Platform::CodeBuddy
            | Platform::WorkBuddy
            | Platform::OpenCode => true,
            // Codex 全模式均无协议 ask(输出 ask = 静默放行),故恒 false。
            Platform::Codex => false,
            Platform::Antigravity => !self.is_yolo,
            Platform::Gemini | Platform::Generic => false,
        }
    }

    /// Canonical event of this invocation (derived from `event`, or from the
    /// envelope shape when the host sends no event name at all).
    #[must_use]
    pub fn event_kind(&self) -> HookEvent {
        self.event_enum
    }

    /// Capability matrix lookup for the current (platform, event) pair.
    #[must_use]
    pub fn capabilities(&self) -> crate::protocol::Capabilities {
        crate::protocol::capabilities(self.platform, self.event_enum)
    }
}
