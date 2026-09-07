use crate::engine::runner::{local_date_str, local_now_str, utc_date_ymd};
use crate::protocol::{HookContext, HookDecision};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default maximum number of debug log files kept per agent.
pub const DEFAULT_MAX_LOG_FILES: usize = 14;

/// Resolves the retention limit for debug log files (defaults to 14).
/// Configurable via `AI_HOOK_LOG_MAX_FILES` or `AI_HOOK_DEBUG_MAX_FILES`.
pub fn resolve_max_log_files() -> usize {
    if let Ok(val) =
        std::env::var("AI_HOOK_LOG_MAX_FILES").or_else(|_| std::env::var("AI_HOOK_DEBUG_MAX_FILES"))
        && let Ok(parsed) = val.trim().parse::<usize>()
    {
        return parsed;
    }
    DEFAULT_MAX_LOG_FILES
}

/// Checks whether debug mode is enabled.
/// Supported via CLI `--debug` or environment variable `AI_HOOK_DEBUG=1|true|on`.
pub fn is_debug_enabled(cli_debug: bool) -> bool {
    cli_debug || crate::protocol::input::env_flag_true("AI_HOOK_DEBUG")
}

/// Fast-path trace in debug log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FastPathTrace {
    pub hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_prefix: Option<String>,
}

/// Rule execution entry in debug log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTrace {
    pub id: String,
    pub path: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// User interaction / GUI confirmation trace in debug log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InteractionTrace {
    pub confirm_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gui_approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialog_duration_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_action: Option<String>,
}

/// Detailed trace of how an ask/confirmation was routed and requested by ai-hook.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AskTrace {
    /// Channel used: "DesktopPopup" | "HostTerminalInline" | "NoneAutoDeny" | "NoneHardDeny" | "NoneBypass"
    pub channel: String,
    /// Reason/origin triggering the ask:
    /// "GuiFallbackYolo" | "HostNativeProtocol" | "GuiFallbackNoHostAsk" | "GuiForcedByRule" | "GuiForcedByCli" | "AutoDenyNoGuiAvailable" | "RuleDecision" | "FastPath" | "UnparseablePayload" | "None"
    pub trigger_reason: String,
    /// Native host protocol operator if applicable (e.g. "ask", "confirm", "permission_request")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_op: Option<String>,
    /// Dialog/prompt title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Prompt reason displayed to user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Target command or resource prompted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Action description (e.g. "执行命令", "修改文件", "读取文件")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Tool name (e.g. "run_command", "replace_file_content")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Rendered prompt formatted for terminal/dialog
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Timeout in seconds configured for user prompt
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_sec: Option<u32>,
}

/// Trace of how the user or host responded physically to the prompt.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserActionTrace {
    /// Action taken: "Approved" | "Denied" | "EscCancelled" | "TimedOut" | "PendingHostPrompt" | "NotApplicable" | "Error"
    pub action: String,
    /// Duration of interaction in milliseconds (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// Human-friendly description of user's physical action
    pub description: String,
}

/// Consolidated disposition summary in debug log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DispositionTrace {
    /// Action determined by engine: "Allow" | "Deny" | "Confirm" | "Modify" | "KeepGoing" | "FastPath" | "Bypass"
    pub engine_action: String,
    /// Final physical effect: "Allowed" | "Blocked" | "Asked" | "Mutated" | "Injected"
    pub final_effect: String,
    /// Detailed ask routing trace (if an ask was attempted or evaluated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<AskTrace>,
    /// Detailed user/host physical action trace
    pub user: UserActionTrace,
    /// One-line human-readable summary
    pub summary: String,
}

/// Final decision and delivery result in debug log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResultTrace {
    pub rule_decision: serde_json::Value,
    pub rendered_output: String,
    pub exit_code: i32,
}

/// Breakdown of execution timings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimingTrace {
    pub read_stdin_ms: f64,
    pub parse_payload_ms: f64,
    pub rules_eval_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gui_interaction_ms: Option<f64>,
    pub total_process_ms: f64,
}

/// Truncates string fields in a JSON value if they exceed `max_chars`.
pub fn sanitize_large_json_values(val: &serde_json::Value, max_chars: usize) -> serde_json::Value {
    match val {
        serde_json::Value::String(s) => {
            if s.chars().count() > max_chars {
                let prefix: String = s.chars().take(max_chars).collect();
                serde_json::Value::String(format!(
                    "{} ...[truncated, total {} chars]",
                    prefix,
                    s.chars().count()
                ))
            } else {
                serde_json::Value::String(s.clone())
            }
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|item| sanitize_large_json_values(item, max_chars))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(k.clone(), sanitize_large_json_values(v, max_chars));
            }
            serde_json::Value::Object(new_map)
        }
        other => other.clone(),
    }
}

/// Normalized view of the hook context exposed to rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextView {
    pub platform: String,
    pub event: Option<String>,
    pub event_raw: Option<String>,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<serde_json::Value>,
    pub args: serde_json::Value,
    pub cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<serde_json::Value>,
    pub is_yolo: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
}

impl From<&HookContext> for ContextView {
    fn from(ctx: &HookContext) -> Self {
        const MAX_ARG_CHARS: usize = 512;
        let sanitized_args = sanitize_large_json_values(&ctx.args, MAX_ARG_CHARS);
        let sanitized_cmd = ctx.cmd.as_ref().map(|c| {
            if c.chars().count() > 1024 {
                let prefix: String = c.chars().take(1024).collect();
                format!(
                    "{} ...[truncated, total {} chars]",
                    prefix,
                    c.chars().count()
                )
            } else {
                c.clone()
            }
        });
        Self {
            platform: ctx.platform.to_string(),
            event: ctx.event.clone(),
            event_raw: ctx.event_raw.clone(),
            tool: ctx.tool_name.clone(),
            cmd: sanitized_cmd,
            // Semantic views are built by hand (instead of serde on the context
            // structs) so that enum spellings match the JS rule contract:
            // runner.rs injects `action`/`kind` via `as_str()` (lowercase
            // "read" | "write" | "fetch" | "glob" | "agent" | ...), while the
            // derived Serialize would emit the Rust variant name ("Read",
            // "Fetch", ...). The debug log is the place people compare against
            // the tutorial ctx schema, so it must show exactly what rules see.
            file: ctx.file.as_ref().map(|f| {
                serde_json::json!({
                    "path": f.path,
                    "paths": f.paths,
                    "action": f.action.as_str(),
                })
            }),
            mcp: ctx.mcp.as_ref().and_then(|m| serde_json::to_value(m).ok()),
            web: ctx.web.as_ref().map(|w| {
                serde_json::json!({
                    "action": w.action.as_str(),
                    "url": w.url,
                    "query": w.query,
                })
            }),
            search: ctx.search.as_ref().map(|s| {
                serde_json::json!({
                    "kind": s.kind.as_str(),
                    "path": s.path,
                    "pattern": s.pattern,
                })
            }),
            agent: ctx.agent.as_ref().map(|a| {
                serde_json::json!({
                    "kind": a.kind.as_str(),
                    "description": a.description,
                    "prompt": a.prompt,
                })
            }),
            args: sanitized_args,
            cwd: ctx.cwd.clone(),
            model: ctx.model.clone(),
            session: ctx
                .conversation
                .as_ref()
                .and_then(|c| serde_json::to_value(c).ok()),
            is_yolo: ctx.is_yolo,
            mode: ctx.permission_mode.clone(),
            prompt: ctx.prompt.as_ref().map(|p| {
                if p.chars().count() > 512 {
                    let prefix: String = p.chars().take(512).collect();
                    format!(
                        "{} ...[truncated, total {} chars]",
                        prefix,
                        p.chars().count()
                    )
                } else {
                    p.clone()
                }
            }),
        }
    }
}

/// A comprehensive debug log entry recorded on each hook invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugLogEntry {
    pub time: String,
    pub date: String,
    pub timestamp: u128,
    pub agent: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub pid: u32,
    pub version: String,
    pub cli_args: Vec<String>,
    pub raw_input: String,
    pub parse_failed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<ContextView>,
    pub fast_path: FastPathTrace,
    pub rules_evaluated: Vec<RuleTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction: Option<InteractionTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition: Option<DispositionTrace>,
    pub result: ResultTrace,
    pub timing_ms: TimingTrace,
}

/// Converts a HookDecision into a structured JSON representation for debug logs.
pub fn decision_to_value(decision: &HookDecision) -> serde_json::Value {
    match decision {
        HookDecision::Allow => serde_json::json!({ "type": "Allow" }),
        HookDecision::Deny { reason } => {
            serde_json::json!({ "type": "Deny", "reason": reason })
        }
        HookDecision::Confirm {
            reason,
            title,
            gui,
            timeout,
            force_gui,
        } => serde_json::json!({
            "type": "Confirm",
            "reason": reason,
            "title": title,
            "gui": gui,
            "timeout": timeout,
            "force_gui": force_gui,
        }),
        HookDecision::Modify(m) => serde_json::json!({
            "type": "Modify",
            "inject": m.inject,
            "mutate_input": m.mutate_input,
            "replace_output": m.replace_output,
        }),
        HookDecision::KeepGoing { reason } => {
            serde_json::json!({ "type": "KeepGoing", "reason": reason })
        }
    }
}

/// Resolves the debug log file path for a given agent.
/// Defaults to `~/.ai-hook/logs/ai-hook-debug-{agent}-{YYYYMMDD}.log`.
/// Can be overridden via `AI_HOOK_DEBUG_FILE`.
pub fn resolve_debug_log_path(agent: &str) -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("AI_HOOK_DEBUG_FILE") {
        let custom = custom.trim();
        if !custom.is_empty() {
            return Some(PathBuf::from(custom));
        }
    }
    let home = crate::paths::home_dir()?;
    Some(home.join(".ai-hook").join("logs").join(format!(
        "ai-hook-debug-{}-{}.log",
        agent,
        utc_date_ymd()
    )))
}

/// Prunes old log files in `dir` that match `prefix`, retaining only the newest `max_files`.
pub fn prune_old_log_files(dir: &Path, prefix: &str, max_files: usize) {
    if max_files == 0 || !dir.is_dir() {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|name| {
                    if prefix.starts_with("ai-hook-debug-")
                        || prefix.starts_with("ai-hook-inbound-")
                    {
                        name.starts_with(prefix) && name.contains(".log")
                    } else {
                        // Standard rule log: exclude debug files to guarantee complete namespace isolation
                        name.starts_with(prefix)
                            && !name.contains("-debug-")
                            && name.contains(".log")
                    }
                })
                .unwrap_or(false)
        })
        .collect();

    if files.len() <= max_files {
        return;
    }

    // Sort by file modification time (or file path as fallback).
    // Older files appear first.
    files.sort_by(|a, b| {
        let meta_a = a.metadata().and_then(|m| m.modified()).ok();
        let meta_b = b.metadata().and_then(|m| m.modified()).ok();
        match (meta_a, meta_b) {
            (Some(ta), Some(tb)) => ta.cmp(&tb),
            _ => a.cmp(b),
        }
    });

    let excess = files.len() - max_files;
    for file in files.into_iter().take(excess) {
        let _ = std::fs::remove_file(file);
    }
}

/// Records a debug log entry to disk (appends a single JSONL line).
/// Performs rotation (>20MB) when oversized; no automatic pruning is done in the hot path.
pub fn record_debug_log(agent: &str, entry: &DebugLogEntry) {
    let log_path = resolve_debug_log_path(agent);
    let Some(path) = log_path else {
        return;
    };

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Rotate once if oversized (>20MB)
    const MAX_LOG_BYTES: u64 = 20 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > MAX_LOG_BYTES
        && let Some(name) = path.file_name()
    {
        let rotated_path = path.with_file_name(format!("{}.1", name.to_string_lossy()));
        let _ = std::fs::rename(&path, &rotated_path);
    }

    let line = match serde_json::to_string(entry) {
        Ok(l) => l,
        Err(_) => return,
    };

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{}", line);
    }
}

/// Category breakdown in a log cleanup report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryReport {
    pub prefix: String,
    pub total: usize,
    pub deleted: usize,
    pub retained: usize,
}

/// Comprehensive report of a log cleanup operation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanReport {
    pub logs_dir: PathBuf,
    pub total_scanned: usize,
    pub files_deleted: usize,
    pub files_retained: usize,
    pub bytes_freed: u64,
    pub deleted_files: Vec<String>,
    pub categories: Vec<CategoryReport>,
}

/// Extracts the category prefix (e.g. `ai-hook-claude_code-`, `ai-hook-debug-antigravity-`, `ai-hook-inbound-`)
/// from a log filename.
pub fn extract_log_category(file_name: &str) -> Option<String> {
    if !file_name.contains(".log") {
        return None;
    }
    let base = file_name.strip_suffix(".1").unwrap_or(file_name);
    let base = base.strip_suffix(".log").unwrap_or(base);

    if let Some(last_dash) = base.rfind('-') {
        let (prefix_without_dash, suffix) = base.split_at(last_dash);
        let date_part = &suffix[1..];
        if date_part.chars().all(|c| c.is_ascii_digit()) && date_part.len() >= 4 {
            return Some(format!("{}-", prefix_without_dash));
        }
    }
    Some(base.to_string())
}

/// Cleans old log files across all categories in `dir`, retaining up to `max_files`
/// newest files per category. If `dry_run` is true, files are not deleted.
pub fn clean_all_logs(dir: &Path, max_files: usize, dry_run: bool) -> CleanReport {
    let mut report = CleanReport {
        logs_dir: dir.to_path_buf(),
        ..Default::default()
    };

    if !dir.is_dir() {
        return report;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return report,
    };

    use std::collections::BTreeMap;
    let mut groups: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();

    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| t.is_file()) {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && let Some(cat) = extract_log_category(name)
            {
                groups.entry(cat).or_default().push(path);
            }
        }
    }

    for (prefix, mut files) in groups {
        let total = files.len();
        report.total_scanned += total;

        // Sort by file modification time (oldest first)
        files.sort_by(|a, b| {
            let meta_a = a.metadata().and_then(|m| m.modified()).ok();
            let meta_b = b.metadata().and_then(|m| m.modified()).ok();
            match (meta_a, meta_b) {
                (Some(ta), Some(tb)) => ta.cmp(&tb),
                _ => a.cmp(b),
            }
        });

        let (to_delete, to_keep) = if files.len() > max_files {
            let excess = files.len() - max_files;
            (&files[..excess], &files[excess..])
        } else {
            (&[][..], &files[..])
        };

        for f in to_delete {
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            report.bytes_freed += size;
            if let Some(fname) = f.file_name().and_then(|n| n.to_str()) {
                report.deleted_files.push(fname.to_string());
            }
            if !dry_run {
                let _ = std::fs::remove_file(f);
            }
        }

        let deleted_count = to_delete.len();
        let retained_count = to_keep.len();

        report.files_deleted += deleted_count;
        report.files_retained += retained_count;

        report.categories.push(CategoryReport {
            prefix,
            total,
            deleted: deleted_count,
            retained: retained_count,
        });
    }

    report
}

/// Helper collector for accumulating traces during a single hook dispatch.
pub struct DebugCollector {
    pub t_start: std::time::Instant,
    pub t_read_done: Option<std::time::Instant>,
    pub t_parse_done: Option<std::time::Instant>,
    pub t_rules_done: Option<std::time::Instant>,
    pub cli_args: Vec<String>,
    pub raw_input: String,
    pub parse_failed: bool,
    pub fast_path_hit: bool,
    pub fast_path_prefix: Option<String>,
    pub rules_evaluated: Vec<RuleTrace>,
    pub hit_rule: Option<String>,
    pub interaction: Option<InteractionTrace>,
    pub disposition: Option<DispositionTrace>,
}

impl Default for DebugCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugCollector {
    pub fn new() -> Self {
        Self {
            t_start: std::time::Instant::now(),
            t_read_done: None,
            t_parse_done: None,
            t_rules_done: None,
            cli_args: std::env::args().collect(),
            raw_input: String::new(),
            parse_failed: false,
            fast_path_hit: false,
            fast_path_prefix: None,
            rules_evaluated: Vec::new(),
            hit_rule: None,
            interaction: None,
            disposition: None,
        }
    }

    pub fn record(
        self,
        agent: &str,
        ctx: Option<&HookContext>,
        decision: &HookDecision,
        rendered_output: &str,
        exit_code: i32,
    ) {
        let total_ms = self.t_start.elapsed().as_secs_f64() * 1000.0;
        let read_ms = self
            .t_read_done
            .map(|t| t.duration_since(self.t_start).as_secs_f64() * 1000.0)
            .unwrap_or(0.0);
        let parse_ms = match (self.t_read_done, self.t_parse_done) {
            (Some(r), Some(p)) => p.duration_since(r).as_secs_f64() * 1000.0,
            _ => 0.0,
        };
        let rules_ms = match (self.t_parse_done, self.t_rules_done) {
            (Some(p), Some(rd)) => rd.duration_since(p).as_secs_f64() * 1000.0,
            _ => 0.0,
        };

        let gui_ms = self.interaction.as_ref().and_then(|i| i.dialog_duration_ms);

        let disposition = self.disposition.or_else(|| {
            // Intelligent fallback disposition if not explicitly set
            let (engine_action, final_effect, summary) = match decision {
                HookDecision::Allow => (
                    "Allow",
                    "Allowed",
                    "操作通过安全检查，已允许执行".to_string(),
                ),
                HookDecision::Deny { reason } => {
                    ("Deny", "Blocked", format!("操作被规则阻断: {}", reason))
                }
                HookDecision::Confirm { reason, .. } => {
                    ("Confirm", "Asked", format!("操作触发确认提示: {}", reason))
                }
                HookDecision::Modify(_) => {
                    ("Modify", "Mutated", "操作参数已由规则改写".to_string())
                }
                HookDecision::KeepGoing { .. } => {
                    ("KeepGoing", "Allowed", "规则评估后放行继续".to_string())
                }
            };
            Some(DispositionTrace {
                engine_action: engine_action.to_string(),
                final_effect: final_effect.to_string(),
                ask: None,
                user: UserActionTrace {
                    action: "NotApplicable".to_string(),
                    duration_ms: None,
                    description: "无需用户物理交互".to_string(),
                },
                summary,
            })
        });

        let entry = DebugLogEntry {
            time: local_now_str(),
            date: local_date_str(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            agent: agent.to_string(),
            r#type: "debug".to_string(),
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            cli_args: self.cli_args,
            raw_input: if self.raw_input.chars().count() > 1024 {
                let prefix: String = self.raw_input.chars().take(1024).collect();
                format!(
                    "{} ...[truncated, total {} chars]",
                    prefix,
                    self.raw_input.chars().count()
                )
            } else {
                self.raw_input
            },
            parse_failed: self.parse_failed,
            context: ctx.map(ContextView::from),
            fast_path: FastPathTrace {
                hit: self.fast_path_hit,
                matched_prefix: self.fast_path_prefix,
            },
            rules_evaluated: self.rules_evaluated,
            hit_rule: self.hit_rule,
            interaction: self.interaction,
            disposition,
            result: ResultTrace {
                rule_decision: decision_to_value(decision),
                rendered_output: rendered_output.to_string(),
                exit_code,
            },
            timing_ms: TimingTrace {
                read_stdin_ms: read_ms,
                parse_payload_ms: parse_ms,
                rules_eval_ms: rules_ms,
                gui_interaction_ms: gui_ms,
                total_process_ms: total_ms,
            },
        };

        record_debug_log(agent, &entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_prunes_excess_files() {
        let temp_dir =
            std::env::temp_dir().join(format!("ai_hook_test_retention_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let prefix = "ai-hook-debug-test-";
        // Create 20 mock log files
        for i in 1..=20 {
            let file_path = temp_dir.join(format!("ai-hook-debug-test-202609{:02}.log", i));
            std::fs::write(&file_path, format!("log entry {}", i)).unwrap();
            // Sleep slightly or touch to ensure different timestamp if needed
        }

        assert_eq!(
            std::fs::read_dir(&temp_dir)
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .path()
                    .to_string_lossy()
                    .contains(prefix))
                .count(),
            20
        );

        // Prune to 14 files
        prune_old_log_files(&temp_dir, prefix, 14);

        let remaining = std::fs::read_dir(&temp_dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .to_string_lossy()
                    .contains(prefix)
            })
            .count();
        assert_eq!(remaining, 14);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_debug_enabled_and_log_path() {
        // AI_HOOK_DEBUG_FILE alone does not enable debug mode
        unsafe {
            std::env::remove_var("AI_HOOK_DEBUG");
            std::env::set_var("AI_HOOK_DEBUG_FILE", "1");
        }
        assert!(!is_debug_enabled(false));

        // AI_HOOK_DEBUG=1 enables debug mode
        unsafe {
            std::env::set_var("AI_HOOK_DEBUG", "1");
        }
        assert!(is_debug_enabled(false));

        // Test custom log path
        let custom_file = std::env::temp_dir().join("my-custom-debug.log");
        unsafe {
            std::env::set_var(
                "AI_HOOK_DEBUG_FILE",
                custom_file.to_string_lossy().to_string(),
            );
        }
        let path = resolve_debug_log_path("claude_code").unwrap();
        assert_eq!(path, custom_file);

        // Test default path when AI_HOOK_DEBUG_FILE is absent
        unsafe {
            std::env::remove_var("AI_HOOK_DEBUG_FILE");
            std::env::remove_var("AI_HOOK_DEBUG");
        }
        let default_path = resolve_debug_log_path("claude_code").unwrap();
        assert!(
            default_path
                .to_string_lossy()
                .contains("ai-hook-debug-claude_code-")
        );
    }

    #[test]
    fn test_sanitize_large_json_values_truncates_long_strings() {
        let long_str = "A".repeat(1000);
        let val = serde_json::json!({
            "short": "hello",
            "long": long_str,
            "nested": {
                "nested_long": "B".repeat(600)
            }
        });
        let sanitized = sanitize_large_json_values(&val, 512);
        assert_eq!(sanitized["short"], "hello");
        assert!(
            sanitized["long"]
                .as_str()
                .unwrap()
                .contains("...[truncated, total 1000 chars]")
        );
        assert!(
            sanitized["nested"]["nested_long"]
                .as_str()
                .unwrap()
                .contains("...[truncated, total 600 chars]")
        );
    }

    #[test]
    fn test_disposition_trace_serialization_and_recording() {
        let entry = DebugLogEntry {
            time: "2026-09-07 18:00:00".to_string(),
            date: "2026-09-07".to_string(),
            timestamp: 1788770000000,
            agent: "antigravity".to_string(),
            r#type: "debug".to_string(),
            pid: 12345,
            version: "3.0.4".to_string(),
            cli_args: vec!["ai-hook".to_string()],
            raw_input: "test_input".to_string(),
            parse_failed: false,
            context: None,
            fast_path: FastPathTrace::default(),
            rules_evaluated: Vec::new(),
            hit_rule: None,
            interaction: None,
            disposition: Some(DispositionTrace {
                engine_action: "Confirm".to_string(),
                final_effect: "Allowed".to_string(),
                ask: Some(AskTrace {
                    channel: "DesktopPopup".to_string(),
                    trigger_reason: "GuiFallbackYolo".to_string(),
                    protocol_op: Some("allow".to_string()),
                    title: Some("安全授权".to_string()),
                    reason: Some("测试敏感命令".to_string()),
                    target: Some("rm -rf /".to_string()),
                    action: Some("执行命令".to_string()),
                    tool: Some("run_command".to_string()),
                    prompt: Some("【ai-hook 安全确认】安全授权\n原因: 测试敏感命令\n操作: 执行命令 (run_command)\n目标: rm -rf /".to_string()),
                    timeout_sec: Some(60),
                }),
                user: UserActionTrace {
                    action: "Approved".to_string(),
                    duration_ms: Some(1523.5),
                    description: "用户在弹窗中确认允许执行".to_string(),
                },
                summary: "桌面置顶弹窗确认: 用户在 1524ms 内确认允许执行，操作已放行".to_string(),
            }),
            result: ResultTrace {
                rule_decision: serde_json::json!({ "type": "Allow" }),
                rendered_output: "{}".to_string(),
                exit_code: 0,
            },
            timing_ms: TimingTrace::default(),
        };

        let json_str = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["type"], "debug");
        assert_eq!(parsed["disposition"]["engine_action"], "Confirm");
        assert_eq!(parsed["disposition"]["final_effect"], "Allowed");
        assert_eq!(parsed["disposition"]["ask"]["channel"], "DesktopPopup");
        assert_eq!(
            parsed["disposition"]["ask"]["trigger_reason"],
            "GuiFallbackYolo"
        );
        assert_eq!(parsed["disposition"]["user"]["action"], "Approved");
        assert_eq!(
            parsed["disposition"]["user"]["description"],
            "用户在弹窗中确认允许执行"
        );
        assert!(
            parsed["disposition"]["summary"]
                .as_str()
                .unwrap()
                .contains("操作已放行")
        );
    }
}
