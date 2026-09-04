use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Antigravity,
    Codex,
    ClaudeCode,
    CodeBuddy,
    Generic,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Antigravity => write!(f, "antigravity"),
            Platform::Codex => write!(f, "codex"),
            Platform::ClaudeCode => write!(f, "claude_code"),
            Platform::CodeBuddy => write!(f, "codebuddy"),
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
    pub action: FileAction,
}

/// Fully parsed and normalized hook context (v2, one semantic per property —
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
    /// Tool arguments exactly as the host provided them.
    pub tool_args: serde_json::Value,
    /// Lifecycle event name (e.g. "PreToolUse", "PostToolUse", "UserPromptSubmit").
    pub event: Option<String>,
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

/// YOLO = host runs without confirmation prompts.
fn permission_mode_is_yolo(mode: &str) -> bool {
    let m = mode.to_ascii_lowercase();
    m.contains("bypass") || m.contains("dontask")
}

/// True for hosts that mirror the Claude Code envelope
/// (`hook_event_name` + `tool_name` + `tool_input`).
fn has_claude_envelope(val: &serde_json::Value) -> bool {
    val.get("tool_input").is_some() || val.get("tool_name").is_some()
}

/// Case-insensitive ASCII substring search that does not allocate a lowercased
/// copy of the haystack (hook payloads can carry megabytes of transcript).
fn contains_ascii_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if h.len() < n.len() {
        return false;
    }
    h.windows(n.len()).any(|w| {
        w.iter()
            .zip(n.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// Classifies command/file tools and extracts the normalized payload for the
/// tool the host is about to invoke.
fn normalize_semantics(
    platform: Platform,
    tool_name: &str,
    args: Option<&serde_json::Value>,
) -> (Option<String>, Option<FileContext>) {
    let lower = tool_name.to_ascii_lowercase();
    let args = match args {
        Some(a) if a.is_object() => a,
        _ => return (None, None),
    };

    // 1. Command tools: a single shell command string.
    let command_keys = match platform {
        Platform::Antigravity => &["CommandLine", "command", "cmd"][..],
        _ => &["command", "CommandLine", "cmd"][..],
    };
    let command_tools = [
        "bash",
        "run_command",
        "shell",
        "powershell",
        "command",
        "terminal",
    ];
    if command_tools.contains(&lower.as_str()) {
        return (get_str(args, command_keys).map(str::to_string), None);
    }

    // 2. File tools: normalize {path, action} from the tool name.
    // Real Antigravity argument names (official tool schema): view_file /
    // view_file_outline use AbsolutePath; write/replace use TargetFile;
    // list_dir uses DirectoryPath.
    let path_keys: &[&str] = match platform {
        Platform::Antigravity => &[
            "file_path",
            "FilePath",
            "TargetFile",
            "AbsolutePath",
            "DirectoryPath",
            "path",
            "file",
        ],
        _ => &["file_path", "filePath", "path", "TargetFile", "file"],
    };
    let action = match lower.as_str() {
        // Read
        "read" | "view_file" | "read_file" => FileAction::Read,
        // Write / create
        "write" | "write_to_file" | "create_file" | "overwrite_file" => FileAction::Write,
        // Edit (in place)
        "edit"
        | "multi_edit"
        | "notebookedit"
        | "apply_patch"
        | "replace_file_content"
        | "multi_replace_file_content"
        | "edit_file"
        | "modify_file" => FileAction::Edit,
        // Delete
        "delete" | "delete_file" | "remove_file" | "rm" => FileAction::Delete,
        // List directory
        "list_dir" | "list" | "read_dir" => FileAction::List,
        _ => return (None, None), // not a file tool we model
    };
    let path = get_str(args, path_keys).map(str::to_string);
    (None, Some(FileContext { path, action }))
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
                    tool_args: serde_json::Value::Null,
                    event: None,
                    prompt: None,
                    raw_input: raw_json.to_string(),
                    raw_value: serde_json::Value::Null,
                    parse_failed: true,
                };
            }
        };

        let event = get_str(&val, &["hook_event_name", "hookEventName", "event"]).map(str::to_string);
        let prompt = get_str(&val, &["prompt", "user_prompt", "userPrompt"]).map(str::to_string);

        // ---- 1. Google Antigravity: `toolCall` envelope ----
        if val.get("toolCall").is_some() {
            let tool_call = val.get("toolCall").cloned().unwrap_or_default();
            let tool_name = get_str(&tool_call, &["name", "toolName"])
                .unwrap_or("")
                .to_string();
            let args = tool_call
                .get("args")
                .or_else(|| tool_call.get("parameters"));
            let (cmd, file) = normalize_semantics(Platform::Antigravity, &tool_name, args);
            let tool_args = args.cloned().unwrap_or(serde_json::Value::Null);

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

            return Self {
                platform: Platform::Antigravity,
                permission_mode: None,
                is_yolo: env_flag_true("AGY_DANGEROUSLY_SKIP_PERMISSIONS")
                    || get_str(&val, &["permissionMode", "permission_mode"])
                        .map(permission_mode_is_yolo)
                        .unwrap_or(false),
                conversation,
                cwd: args
                    .and_then(|a| get_str(a, &["Cwd", "cwd"]))
                    .map(str::to_string)
                    .unwrap_or_else(current_dir_string),
                model: get_str(&val, &["modelName"]).map(str::to_string),
                tool_name,
                cmd,
                file,
                tool_args,
                event: event.or_else(|| Some("PreToolUse".to_string())),
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
            let tool_input = val.get("tool_input");
            let (cmd, file) = normalize_semantics(
                Platform::ClaudeCode, // shape is identical for these hosts
                &tool_name,
                tool_input,
            );
            let tool_args = tool_input.cloned().unwrap_or(serde_json::Value::Null);

            let permission_mode = get_str(&val, &["permission_mode"]).map(str::to_string);
            let is_codex = val.get("turn_id").is_some();
            let is_yolo = (is_codex && env_flag_true("CODEX_DANGEROUSLY_SKIP_PERMISSIONS"))
                || permission_mode
                    .as_deref()
                    .map(permission_mode_is_yolo)
                    .unwrap_or(false);

            let conversation = ConversationInfo {
                id: get_str(&val, &["session_id"]).map(str::to_string),
                transcript_path: get_str(&val, &["transcript_path"]).map(str::to_string),
            };
            let conversation =
                if conversation.id.is_none() && conversation.transcript_path.is_none() {
                    None
                } else {
                    Some(conversation)
                };

            let scan_end = raw_json.floor_char_boundary(raw_json.len().min(64 * 1024));
            let is_codebuddy = std::env::var("CODEBUDDY").is_ok()
                || std::env::var("CODEBUDDY_CLI").is_ok()
                || contains_ascii_ignore_case(&raw_json[..scan_end], "codebuddy");

            let platform = if val.get("turn_id").is_some() {
                Platform::Codex
            } else if is_codebuddy {
                Platform::CodeBuddy
            } else {
                Platform::ClaudeCode
            };

            return Self {
                platform,
                permission_mode,
                is_yolo,
                conversation,
                cwd: get_str(&val, &["cwd"])
                    .map(str::to_string)
                    .unwrap_or_else(current_dir_string),
                model: get_str(&val, &["model"]).map(str::to_string),
                tool_name,
                cmd,
                file,
                tool_args,
                event: event.or_else(|| Some("PreToolUse".to_string())),
                prompt,
                raw_input: raw_json.to_string(),
                raw_value: val,
                parse_failed: false,
            };
        }

        // ---- 3. UserPromptSubmit envelope ----
        if prompt.is_some() || event.as_deref() == Some("UserPromptSubmit") {
            let scan_end = raw_json.floor_char_boundary(raw_json.len().min(64 * 1024));
            let is_codebuddy = std::env::var("CODEBUDDY").is_ok()
                || std::env::var("CODEBUDDY_CLI").is_ok()
                || contains_ascii_ignore_case(&raw_json[..scan_end], "codebuddy");
            let platform = if val.get("turn_id").is_some() {
                Platform::Codex
            } else if is_codebuddy {
                Platform::CodeBuddy
            } else {
                Platform::ClaudeCode
            };

            let conversation = ConversationInfo {
                id: get_str(&val, &["session_id"]).map(str::to_string),
                transcript_path: get_str(&val, &["transcript_path"]).map(str::to_string),
            };
            let conversation =
                if conversation.id.is_none() && conversation.transcript_path.is_none() {
                    None
                } else {
                    Some(conversation)
                };

            return Self {
                platform,
                permission_mode: get_str(&val, &["permission_mode"]).map(str::to_string),
                is_yolo: (platform == Platform::Codex && env_flag_true("CODEX_DANGEROUSLY_SKIP_PERMISSIONS"))
                    || (platform == Platform::Antigravity && env_flag_true("AGY_DANGEROUSLY_SKIP_PERMISSIONS"))
                    || get_str(&val, &["permission_mode"])
                        .map(permission_mode_is_yolo)
                        .unwrap_or(false),
                conversation,
                cwd: get_str(&val, &["cwd"])
                    .map(str::to_string)
                    .unwrap_or_else(current_dir_string),
                model: get_str(&val, &["model"]).map(str::to_string),
                tool_name: String::new(),
                cmd: None,
                file: None,
                tool_args: serde_json::Value::Null,
                event: Some(event.unwrap_or_else(|| "UserPromptSubmit".to_string())),
                prompt,
                raw_input: raw_json.to_string(),
                raw_value: val,
                parse_failed: false,
            };
        }

        // ---- 4. Unknown shape: keep raw, expose nothing normalized ----
        Self {
            platform: Platform::Generic,
            permission_mode: None,
            is_yolo: false,
            conversation: None,
            cwd: get_str(&val, &["cwd"])
                .map(str::to_string)
                .unwrap_or_else(current_dir_string),
            model: None,
            tool_name: String::new(),
            cmd: None,
            file: None,
            tool_args: serde_json::Value::Null,
            event,
            prompt,
            raw_input: raw_json.to_string(),
            raw_value: val,
            parse_failed: false,
        }
    }

    /// 宿主×模式是否具备「协议 ask」能力(2026-09-05 约定,与 tutorial 宿主矩阵配套):
    /// - Claude Code / CodeBuddy:恒可——官方设计 hook 层 ask 拥有最高决策优先级,
    ///   即使 bypass/YOLO 模式也能唤起终端交互确认;
    /// - Codex:0.152+ 普通模式支持 PreToolUse ask;bypass(YOLO)模式不支持;
    /// - Antigravity:普通交互模式走 force_ask;YOLO 下 ask/force_ask 被静默放行,不可;
    /// - Generic(未知宿主):无 ask 协议,不可。
    #[must_use]
    pub fn can_ask(&self) -> bool {
        match self.platform {
            Platform::ClaudeCode | Platform::CodeBuddy => true,
            Platform::Codex => !self.is_yolo,
            Platform::Antigravity => !self.is_yolo,
            Platform::Generic => false,
        }
    }
}
