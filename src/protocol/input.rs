use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Antigravity,
    Codex,
    ClaudeCode,
    Generic,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Antigravity => write!(f, "antigravity"),
            Platform::Codex => write!(f, "codex"),
            Platform::ClaudeCode => write!(f, "claude_code"),
            Platform::Generic => write!(f, "generic"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    pub platform: Platform,
    pub tool_name: String,
    pub cmd: String,
    pub target_file: String,
    pub raw_input: String,
    pub is_yolo: bool,
    pub cwd: String,
    pub conversation_id: Option<String>,
}

impl HookContext {
    pub fn parse(raw_json: &str) -> Self {
        let trimmed = raw_json.trim();
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                return Self {
                    platform: Platform::Generic,
                    tool_name: String::new(),
                    cmd: String::new(),
                    target_file: String::new(),
                    raw_input: raw_json.to_string(),
                    is_yolo: false,
                    cwd: std::env::current_dir()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    conversation_id: None,
                };
            }
        };

        // 1. Antigravity: contains "toolCall" object or "conversationId"
        if val.get("toolCall").is_some() || val.get("conversationId").is_some() {
            let tool_name = val
                .get("toolName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args = val.get("toolCall").and_then(|t| t.get("args"));
            let cmd = args
                .and_then(|a| a.get("CommandLine"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target_file = args
                .and_then(|a| a.get("TargetFile").or_else(|| a.get("file_path")))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let conversation_id = val
                .get("conversationId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let is_yolo = std::env::var("AGY_DANGEROUSLY_SKIP_PERMISSIONS")
                .map(|v| v == "1")
                .unwrap_or(false);

            let cwd = args
                .and_then(|a| a.get("Cwd"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    std::env::current_dir()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default()
                });

            return Self {
                platform: Platform::Antigravity,
                tool_name,
                cmd,
                target_file,
                raw_input: raw_json.to_string(),
                is_yolo,
                cwd,
                conversation_id,
            };
        }

        // 2. Codex: has "turn_id"
        if val.get("turn_id").is_some() {
            let tool_name = val
                .get("tool_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let tool_input = val.get("tool_input");
            let cmd = tool_input
                .and_then(|i| i.get("command"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let target_file = tool_input
                .and_then(|i| i.get("file_path").or_else(|| i.get("TargetFile")))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let is_yolo = val
                .get("permission_mode")
                .and_then(|v| v.as_str())
                .map(|s| s.contains("bypass"))
                .unwrap_or(false);

            return Self {
                platform: Platform::Codex,
                tool_name,
                cmd,
                target_file,
                raw_input: raw_json.to_string(),
                is_yolo,
                cwd: std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default(),
                conversation_id: None,
            };
        }

        // 3. Claude Code / CodeBuddy: contains tool_input
        let tool_name = val
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tool_input = val.get("tool_input");
        let cmd = tool_input
            .and_then(|i| i.get("command"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target_file = tool_input
            .and_then(|i| i.get("file_path").or_else(|| i.get("TargetFile")))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let is_yolo = val
            .get("permission_mode")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("bypass"))
            .unwrap_or(false);

        Self {
            platform: Platform::ClaudeCode,
            tool_name,
            cmd,
            target_file,
            raw_input: raw_json.to_string(),
            is_yolo,
            cwd: std::env::current_dir()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            conversation_id: None,
        }
    }
}
