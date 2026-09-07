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

/// Normalized view of the hook context exposed to rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextView {
    pub platform: String,
    pub event: Option<String>,
    pub event_raw: Option<String>,
    pub tool: String,
    pub cmd: Option<String>,
    pub file: Option<serde_json::Value>,
    pub mcp: Option<serde_json::Value>,
    pub web: Option<serde_json::Value>,
    pub search: Option<serde_json::Value>,
    pub agent: Option<serde_json::Value>,
    pub args: serde_json::Value,
    pub cwd: String,
    pub model: Option<String>,
    pub session: Option<serde_json::Value>,
    pub is_yolo: bool,
    pub mode: Option<String>,
    pub prompt: Option<String>,
}

impl From<&HookContext> for ContextView {
    fn from(ctx: &HookContext) -> Self {
        Self {
            platform: ctx.platform.to_string(),
            event: ctx.event.clone(),
            event_raw: ctx.event_raw.clone(),
            tool: ctx.tool_name.clone(),
            cmd: ctx.cmd.clone(),
            file: ctx.file.as_ref().and_then(|f| serde_json::to_value(f).ok()),
            mcp: ctx.mcp.as_ref().and_then(|m| serde_json::to_value(m).ok()),
            web: ctx.web.as_ref().and_then(|w| serde_json::to_value(w).ok()),
            search: ctx
                .search
                .as_ref()
                .and_then(|s| serde_json::to_value(s).ok()),
            agent: ctx
                .agent
                .as_ref()
                .and_then(|a| serde_json::to_value(a).ok()),
            args: ctx.args.clone(),
            cwd: ctx.cwd.clone(),
            model: ctx.model.clone(),
            session: ctx
                .conversation
                .as_ref()
                .and_then(|c| serde_json::to_value(c).ok()),
            is_yolo: ctx.is_yolo,
            mode: ctx.permission_mode.clone(),
            prompt: ctx.prompt.clone(),
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
    pub context: Option<ContextView>,
    pub fast_path: FastPathTrace,
    pub rules_evaluated: Vec<RuleTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hit_rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction: Option<InteractionTrace>,
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
            raw_input: self.raw_input,
            parse_failed: self.parse_failed,
            context: ctx.map(ContextView::from),
            fast_path: FastPathTrace {
                hit: self.fast_path_hit,
                matched_prefix: self.fast_path_prefix,
            },
            rules_evaluated: self.rules_evaluated,
            hit_rule: self.hit_rule,
            interaction: self.interaction,
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
}
