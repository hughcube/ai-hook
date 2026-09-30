use crate::engine::runner::{local_date_str, local_now_str};
use crate::engine::{RuleExecutionResult, RuleSource};
use crate::logging::{AuditLevel, Outcome};
use crate::protocol::{HookContext, HookDecision};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Keeps `~/.agents/…` rule paths readable while leaving other absolute paths
/// (a plugin clone, a temp dir) whole.
fn compact_rule_path(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    match s.find("/.agents/") {
        Some(pos) => format!("~{}", &s[pos..]),
        None => s,
    }
}

/// Default maximum number of debug log files kept per agent.
pub const DEFAULT_MAX_LOG_FILES: usize = 14;

/// Maximum characters of the raw hook payload stored in one audit record.
/// 32 KiB keeps a normal tool call fully recoverable while bounding the line
/// size for a transcript-heavy payload (which is capped and marked).
const MAX_RAW_INPUT_CHARS: usize = 32 * 1024;

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

/// Fast-path trace in debug log.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FastPathTrace {
    pub hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_prefix: Option<String>,
}

/// One rule's fate in an audit record.
///
/// Every rule the invocation *loaded* gets an entry — not just the ones that
/// ran. `evaluate_all` short-circuits on the first decisive rule, so the tail
/// carries `executed: false` with no decision: one record then explains the
/// whole rule set instead of silently stopping at the rule that fired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTrace {
    pub id: String,
    pub path: String,
    pub executed: bool,
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

/// True when `name` is a log file of exactly category `prefix`.
///
/// The category is `<prefix>{YYYYMMDD}.log` (optionally rotated to `.log.1`).
/// A plain `starts_with(prefix)` is NOT enough: `ai-hook-` is a prefix of
/// `ai-hook-console-…` and `ai-hook-audit-…`, so prefix matching would make
/// each category prune its siblings.
pub fn log_file_matches(name: &str, prefix: &str) -> bool {
    let Some(rest) = name.strip_prefix(prefix) else {
        return false;
    };
    let Some(stem) = rest
        .strip_suffix(".log")
        .or_else(|| rest.strip_suffix(".log.1"))
    else {
        return false;
    };
    !stem.is_empty() && stem.chars().all(|c| c.is_ascii_digit())
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
                .map(|name| log_file_matches(name, prefix))
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

/// Serializes one audit entry, tags it with its outcome class, and appends it
/// to the audit log. Rotation/creation is handled by `logging::audit_write`.
fn write_audit_entry(agent: &str, entry: &DebugLogEntry, outcome: Outcome) {
    let mut value = match serde_json::to_value(entry) {
        Ok(v) => v,
        Err(_) => return,
    };
    if let serde_json::Value::Object(ref mut map) = value {
        map.insert(
            "outcome".to_string(),
            serde_json::Value::String(outcome.as_str().to_string()),
        );
    }
    crate::logging::audit_write(agent, &value);
}

/// Classifies an invocation from its final decision, disposition and whether a
/// user interaction (ask/popup) took place.
fn classify_outcome(
    decision: &HookDecision,
    disposition: Option<&DispositionTrace>,
    interaction: Option<&InteractionTrace>,
) -> Outcome {
    let effect = disposition.map(|d| d.final_effect.as_str()).unwrap_or("");
    match decision {
        HookDecision::Deny { .. } => Outcome::Block,
        HookDecision::Modify(_) | HookDecision::KeepGoing { .. } => Outcome::Review,
        // A confirm is a block only when it ended in a deny (user refusal,
        // timeout or auto-deny); a approved/pending ask is a review.
        HookDecision::Confirm { .. } => {
            if effect == "Blocked" {
                Outcome::Block
            } else {
                Outcome::Review
            }
        }
        // A plain allow is only a "review" when it went through an interaction
        // (e.g. an unparseable payload the operator approved).
        HookDecision::Allow => {
            if interaction.is_some() {
                Outcome::Review
            } else {
                Outcome::Allow
            }
        }
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
    /// Audit recording scope resolved from the environment; the collector is
    /// only built when it is not `Off`, and `record` drops invocations the
    /// level does not cover (checked *before* the snapshot is serialized).
    pub audit: AuditLevel,
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
        Self::new(AuditLevel::Off)
    }
}

impl DebugCollector {
    pub fn new(audit: AuditLevel) -> Self {
        Self {
            audit,
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

    /// Records the invocation's full rule set: every rule that ran (with its
    /// own decision/error/timing), then every rule `evaluate_all` never reached
    /// because an earlier one was decisive, marked `executed: false`.
    ///
    /// `ran` is always a prefix of `loaded` — the engine walks the slice in
    /// order and returns on the first decisive outcome — so the unreached tail
    /// is exactly `loaded[ran.len()..]`.
    pub fn record_rules(&mut self, loaded: &[RuleSource], ran: &[RuleExecutionResult]) {
        for r in ran {
            self.rules_evaluated.push(RuleTrace {
                id: r.rule_id.clone(),
                path: compact_rule_path(&r.rule_path),
                executed: true,
                duration_ms: r.duration.as_secs_f64() * 1000.0,
                decision: r.decision.as_ref().map(decision_to_value),
                error: r.error.clone(),
            });
        }

        for r in loaded.iter().skip(ran.len()) {
            self.rules_evaluated.push(RuleTrace {
                id: r.id.clone(),
                path: compact_rule_path(&r.path),
                executed: false,
                duration_ms: 0.0,
                decision: None,
                error: None,
            });
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

        // Decide whether this invocation is worth a line BEFORE assembling the
        // snapshot: a non-triggering call pays no serialization cost at all.
        let outcome = classify_outcome(decision, disposition.as_ref(), self.interaction.as_ref());
        if !crate::logging::audit_allows(self.audit, outcome) {
            return;
        }

        let entry = DebugLogEntry {
            time: local_now_str(),
            date: local_date_str(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            agent: agent.to_string(),
            r#type: "audit".to_string(),
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            cli_args: self.cli_args,
            // The full raw payload is what makes a false-positive block
            // diagnosable, but a multi-megabyte transcript must not balloon
            // the line — cap it and mark the truncation.
            raw_input: if self.raw_input.chars().count() > MAX_RAW_INPUT_CHARS {
                let prefix: String = self.raw_input.chars().take(MAX_RAW_INPUT_CHARS).collect();
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

        write_audit_entry(agent, &entry, outcome);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record must explain the whole rule set: rules the engine never
    /// reached (short-circuited by an earlier decisive rule) still get an
    /// entry, marked `executed: false`.
    #[test]
    fn record_rules_lists_the_unreached_tail_as_not_executed() {
        let loaded: Vec<RuleSource> = ["a", "b", "c"]
            .iter()
            .map(|id| RuleSource {
                id: id.to_string(),
                path: PathBuf::from(format!("/plug/hooks/{id}.js")),
                code: String::new(),
            })
            .collect();
        let ran = vec![RuleExecutionResult {
            rule_id: "a".to_string(),
            rule_path: PathBuf::from("/plug/hooks/a.js"),
            decision: Some(HookDecision::Deny {
                reason: "nope".to_string(),
            }),
            duration: std::time::Duration::from_micros(400),
            error: None,
        }];

        let mut col = DebugCollector::new(AuditLevel::All);
        col.record_rules(&loaded, &ran);

        assert_eq!(col.rules_evaluated.len(), 3, "all loaded rules are listed");
        assert!(col.rules_evaluated[0].executed);
        assert_eq!(col.rules_evaluated[0].id, "a");
        assert!(col.rules_evaluated[0].decision.is_some());
        for skipped in &col.rules_evaluated[1..] {
            assert!(!skipped.executed, "{} never ran", skipped.id);
            assert!(skipped.decision.is_none());
            assert!(skipped.error.is_none());
        }
    }

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
    fn test_classify_outcome_matrix() {
        let deny = HookDecision::Deny {
            reason: "x".to_string(),
        };
        assert_eq!(classify_outcome(&deny, None, None), Outcome::Block);

        let allow = HookDecision::Allow;
        assert_eq!(classify_outcome(&allow, None, None), Outcome::Allow);
        // An allow that went through an ask/popup (e.g. an approved
        // unparseable payload) is a review, not a plain allow.
        assert_eq!(
            classify_outcome(&allow, None, Some(&InteractionTrace::default())),
            Outcome::Review
        );

        let confirm = HookDecision::Confirm {
            reason: "x".to_string(),
            title: None,
            gui: None,
            timeout: None,
            force_gui: None,
        };
        let blocked = DispositionTrace {
            final_effect: "Blocked".to_string(),
            ..Default::default()
        };
        assert_eq!(
            classify_outcome(&confirm, Some(&blocked), None),
            Outcome::Block
        );
        let asked = DispositionTrace {
            final_effect: "Asked".to_string(),
            ..Default::default()
        };
        assert_eq!(
            classify_outcome(&confirm, Some(&asked), None),
            Outcome::Review
        );

        assert_eq!(
            classify_outcome(
                &HookDecision::Modify(crate::protocol::Mutation::default()),
                None,
                None
            ),
            Outcome::Review
        );
        assert_eq!(
            classify_outcome(
                &HookDecision::KeepGoing {
                    reason: "x".to_string()
                },
                None,
                None
            ),
            Outcome::Review
        );
    }

    #[test]
    fn test_log_file_category_exact_match() {
        assert!(log_file_matches("ai-hook-20261001.log", "ai-hook-"));
        assert!(log_file_matches("ai-hook-20261001.log.1", "ai-hook-"));
        assert!(log_file_matches(
            "ai-hook-console-20261001.log",
            "ai-hook-console-"
        ));
        // The `ai-hook-` prefix must NOT swallow console/audit siblings —
        // that is exactly the collision that startswith() caused.
        assert!(!log_file_matches(
            "ai-hook-console-20261001.log",
            "ai-hook-"
        ));
        assert!(!log_file_matches(
            "ai-hook-audit-codebuddy-20261001.log",
            "ai-hook-"
        ));
        // Audit keeps the agent in the name: its category is prefix+agent.
        assert!(log_file_matches(
            "ai-hook-audit-codebuddy-20261001.log",
            "ai-hook-audit-codebuddy-"
        ));
        assert!(!log_file_matches("ai-hook-2026100x.log", "ai-hook-"));
        assert!(!log_file_matches("random.log", "ai-hook-"));
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
            r#type: "audit".to_string(),
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
        assert_eq!(parsed["type"], "audit");
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
