//! Unified logging surface.
//!
//! Three file sinks under `~/.log/ai-hook/`, one environment variable each,
//! **names-only values** (no digits — `1` was ambiguous across the historical
//! `1/true/on` vs `0/false/off` conventions):
//!
//! | # | file                                | produced by     | variable                 | default |
//! |---|-------------------------------------|-----------------|--------------------------|---------|
//! | 1 | `ai-hook-{date}.log`                | the Rust framework | `AI_HOOK_LOG_FRAMEWORK` | `on`  |
//! | 2 | `ai-hook-console-{date}.log`        | JS rules (`console.log` / `sys.log`) | `AI_HOOK_LOG_CONSOLE` | `on` |
//! | 3 | `ai-hook-audit-{agent}-{date}.log`  | per-invocation snapshot | `AI_HOOK_LOG_AUDIT` | `off` |
//!
//! Sink 3 is the graded one. Its level is a **recording scope**, not a
//! severity: `off` ⊂ `block` ⊂ `review` ⊂ `all`. Whenever an invocation is
//! recorded, the line is the *complete* snapshot (raw input, context, rule
//! chain, decision) — the level only decides *which* invocations are worth a
//! line, never trims fields.
//!
//! Path overrides: `AI_HOOK_LOG_{FRAMEWORK,CONSOLE,AUDIT}_FILE`. The legacy
//! `AI_HOOK_LOG_FILE` (console) and `AI_HOOK_DEBUG_FILE` (audit) still apply,
//! as do the legacy boolean switches `AI_HOOK_LOG`, `AI_HOOK_DEBUG` and
//! `AI_HOOK_LOG_EXTERNAL`, so existing setups keep working.

use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Per-file rotation threshold (rename to `<name>.1` once exceeded).
const MAX_LOG_BYTES: u64 = 20 * 1024 * 1024;

/// How much of the invocation stream the audit sink records. Ordered: a
/// higher level records strictly more (`block` ⊂ `review` ⊂ `all`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditLevel {
    Off,
    Block,
    Review,
    All,
}

/// The class of one invocation's outcome, used to gate the audit sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing gated the action: plain allow, fast-path hit, no rules.
    Allow,
    /// The action was surfaced for a decision (ask/confirm) or its input was
    /// rewritten, but the action still proceeds on approval.
    Review,
    /// The action was stopped: hard deny, auto-deny, user-denied, fail-closed.
    Block,
}

impl AuditLevel {
    /// Parses `off|block|review|all` (case-insensitive). Digits are rejected
    /// on purpose — see the module docs.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "block" => Some(Self::Block),
            "review" => Some(Self::Review),
            "all" => Some(Self::All),
            _ => None,
        }
    }

    /// True when an invocation with this outcome should be recorded.
    pub fn allows(self, outcome: Outcome) -> bool {
        match self {
            Self::Off => false,
            Self::Block => outcome == Outcome::Block,
            Self::Review => matches!(outcome, Outcome::Block | Outcome::Review),
            Self::All => true,
        }
    }

    pub fn is_off(self) -> bool {
        self == Self::Off
    }
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Review => "review",
            Self::Block => "block",
        }
    }
}

// ---------------------------------------------------------------------------
// Switch parsing
// ---------------------------------------------------------------------------

/// Reads a non-empty, trimmed environment variable.
fn var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Parses an on/off switch by **name only** (`on`/`true`/`yes` vs
/// `off`/`false`/`no`). Digits are deliberately not accepted.
fn on_off(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" => Some(true),
        "off" | "false" | "no" => Some(false),
        _ => None,
    }
}

/// The pre-existing boolean convention (`1`/`0` …), used **only** to keep the
/// legacy variables working. New variables never accept digits.
fn legacy_on(raw: &str) -> bool {
    matches!(
        raw.to_ascii_lowercase().as_str(),
        "1" | "true" | "on" | "yes"
    )
}

/// Sink #1 (framework): `AI_HOOK_LOG_FRAMEWORK`, default on.
pub fn framework_enabled() -> bool {
    var("AI_HOOK_LOG_FRAMEWORK").is_none_or(|v| on_off(&v).unwrap_or(true))
}

/// Sink #2 (rule console): `AI_HOOK_LOG_CONSOLE`, default on; the legacy
/// `AI_HOOK_LOG=0|false|no|off` still disables it.
pub fn console_enabled() -> bool {
    if let Some(v) = var("AI_HOOK_LOG_CONSOLE") {
        return on_off(&v).unwrap_or(true);
    }
    if let Some(v) = var("AI_HOOK_LOG")
        && matches!(
            v.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    {
        return false;
    }
    true
}

/// Sink #3 (audit): `AI_HOOK_LOG_AUDIT`, default off.
///
/// `cli_debug` is the `--debug` flag; it and the legacy `AI_HOOK_DEBUG` /
/// `AI_HOOK_LOG_EXTERNAL` switches all mean "record everything" (`all`).
pub fn audit_level(cli_debug: bool) -> AuditLevel {
    if let Some(v) = var("AI_HOOK_LOG_AUDIT")
        && let Some(level) = AuditLevel::parse(&v)
    {
        return level;
    }
    if cli_debug
        || var("AI_HOOK_DEBUG").is_some_and(|v| legacy_on(&v))
        || var("AI_HOOK_LOG_EXTERNAL").is_some_and(|v| legacy_on(&v))
    {
        return AuditLevel::All;
    }
    AuditLevel::Off
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn date() -> String {
    crate::engine::runner::utc_date_ymd()
}

/// First non-empty value among `names`, as a path.
fn path_override(names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|n| var(n).map(PathBuf::from))
}

/// The explicit path override for `source` (`"audit" | "console" |
/// "framework"`), if one is set. `ai-hook logs` reads this file when present
/// so it always inspects the same path the sink actually writes.
pub fn override_path_for(source: &str) -> Option<PathBuf> {
    match source {
        "audit" => path_override(&["AI_HOOK_LOG_AUDIT_FILE", "AI_HOOK_DEBUG_FILE"]),
        "console" => path_override(&["AI_HOOK_LOG_CONSOLE_FILE", "AI_HOOK_LOG_FILE"]),
        "framework" => path_override(&["AI_HOOK_LOG_FRAMEWORK_FILE"]),
        _ => None,
    }
}

pub fn framework_path() -> Option<PathBuf> {
    path_override(&["AI_HOOK_LOG_FRAMEWORK_FILE"])
        .or_else(|| Some(crate::paths::log_dir()?.join(format!("ai-hook-{}.log", date()))))
}

pub fn console_path() -> Option<PathBuf> {
    path_override(&["AI_HOOK_LOG_CONSOLE_FILE", "AI_HOOK_LOG_FILE"])
        .or_else(|| Some(crate::paths::log_dir()?.join(format!("ai-hook-console-{}.log", date()))))
}

pub fn audit_path(agent: &str) -> Option<PathBuf> {
    path_override(&["AI_HOOK_LOG_AUDIT_FILE", "AI_HOOK_DEBUG_FILE"]).or_else(|| {
        Some(crate::paths::log_dir()?.join(format!("ai-hook-audit-{}-{}.log", agent, date())))
    })
}

// ---------------------------------------------------------------------------
// Sink primitive
// ---------------------------------------------------------------------------

/// Renames `path` to `<path>.1` once it exceeds [`MAX_LOG_BYTES`].
pub fn rotate_if_oversized(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path)
        && meta.len() > MAX_LOG_BYTES
        && let Some(name) = path.file_name()
    {
        let rotated = path.with_file_name(format!("{}.1", name.to_string_lossy()));
        let _ = std::fs::rename(path, &rotated);
    }
}

/// Appends one JSONL line, creating the parent directory on demand. Never
/// fails the caller: logging must not break the decision path.
pub fn append_jsonl(path: &Path, value: &Value) {
    rotate_if_oversized(path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{}", value);
    }
}

/// `(local time, local date, epoch millis)` — the envelope every line shares.
fn stamp() -> (String, String, u128) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    (
        crate::engine::runner::local_now_str(),
        crate::engine::runner::local_date_str(),
        ts,
    )
}

// ---------------------------------------------------------------------------
// Sink #1 — framework
// ---------------------------------------------------------------------------

/// Records one framework-internal diagnostic.
///
/// `level` is a free-form tag (`error` / `warn` / `info`); the framework log
/// is not graded — it is the safety net for ai-hook's own failures.
pub fn framework(level: &str, msg: &str) {
    if !framework_enabled() {
        return;
    }
    let Some(path) = framework_path() else {
        return;
    };
    let (time, d, ts) = stamp();
    let line = json!({
        "time": time,
        "date": d,
        "ts": ts,
        "level": level,
        "type": "framework",
        "pid": std::process::id(),
        "version": env!("CARGO_PKG_VERSION"),
        "msg": msg,
    });
    append_jsonl(&path, &line);
}

// ---------------------------------------------------------------------------
// Sink #2 — rule console / sys.log
// ---------------------------------------------------------------------------

/// Records one rule-side `console.log` / `sys.log` line.
pub fn console(agent: &str, session_id: Option<&str>, rule_id: &str, level: &str, msg: &str) {
    if !console_enabled() {
        return;
    }
    let Some(path) = console_path() else {
        return;
    };
    let (time, d, ts) = stamp();
    let line = json!({
        "time": time,
        "date": d,
        "ts": ts,
        "level": level,
        "type": "console",
        "agent": agent,
        "sessionId": session_id,
        "rule": rule_id,
        "msg": msg,
    });
    append_jsonl(&path, &line);
}

// ---------------------------------------------------------------------------
// Sink #3 — audit
// ---------------------------------------------------------------------------

/// True when an invocation with `outcome` should be written at `level`. The
/// caller checks this **before** assembling the (potentially large) snapshot,
/// so a non-triggering invocation pays no serialization cost.
pub fn audit_allows(level: AuditLevel, outcome: Outcome) -> bool {
    level.allows(outcome)
}

/// Writes one complete invocation snapshot to the audit file.
pub fn audit_write(agent: &str, entry: &Value) {
    if let Some(path) = audit_path(agent) {
        append_jsonl(&path, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_level_ordering_and_parse() {
        assert_eq!(AuditLevel::parse("off"), Some(AuditLevel::Off));
        assert_eq!(AuditLevel::parse(" Block "), Some(AuditLevel::Block));
        assert_eq!(AuditLevel::parse("REVIEW"), Some(AuditLevel::Review));
        assert_eq!(AuditLevel::parse("all"), Some(AuditLevel::All));
        // Digits are not a level: `1` must not silently mean block or all.
        assert_eq!(AuditLevel::parse("1"), None);
        assert_eq!(AuditLevel::parse("0"), None);

        assert!(AuditLevel::Off < AuditLevel::Block);
        assert!(AuditLevel::Block < AuditLevel::Review);
        assert!(AuditLevel::Review < AuditLevel::All);
    }

    #[test]
    fn audit_gate_matrix() {
        use Outcome::{Allow, Block, Review};
        // off records nothing.
        for o in [Allow, Review, Block] {
            assert!(!AuditLevel::Off.allows(o));
        }
        // block records only blocks.
        assert!(AuditLevel::Block.allows(Block));
        assert!(!AuditLevel::Block.allows(Review));
        assert!(!AuditLevel::Block.allows(Allow));
        // review records blocks + reviews.
        assert!(AuditLevel::Review.allows(Block));
        assert!(AuditLevel::Review.allows(Review));
        assert!(!AuditLevel::Review.allows(Allow));
        // all records everything.
        for o in [Allow, Review, Block] {
            assert!(AuditLevel::All.allows(o));
        }
    }

    #[test]
    fn on_off_names_only() {
        assert_eq!(on_off("on"), Some(true));
        assert_eq!(on_off("OFF"), Some(false));
        assert_eq!(on_off("true"), Some(true));
        assert_eq!(on_off("no"), Some(false));
        // Digits are rejected by the names-only contract.
        assert_eq!(on_off("1"), None);
        assert_eq!(on_off("0"), None);
    }
}
