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
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// Per-file rotation threshold (rename to `<name>.1` once exceeded).
const MAX_LOG_BYTES: u64 = 20 * 1024 * 1024;

/// Test-only override of [`MAX_LOG_BYTES`], so the rotation path can be
/// exercised without writing 20 MiB in a unit test.
#[cfg(test)]
static ROTATE_AT_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(MAX_LOG_BYTES);

/// The rotation threshold in effect (constant in production).
fn rotate_threshold() -> u64 {
    #[cfg(test)]
    {
        ROTATE_AT_BYTES.load(Ordering::Relaxed)
    }
    #[cfg(not(test))]
    {
        MAX_LOG_BYTES
    }
}

/// Audit-sink kill switch.
///
/// `ai-hook test` synthesizes an invocation to exercise rules, so recording it
/// as a real audit entry would pollute the audit trail. `main()` arms this for
/// that subcommand only — the console and framework sinks keep working, since
/// seeing a rule's own `console.log` output is the point of `test`.
static AUDIT_SUPPRESSED: AtomicBool = AtomicBool::new(false);

/// Stops the audit sink from recording for the rest of this process. Other
/// sinks are unaffected.
pub fn suppress_audit() {
    AUDIT_SUPPRESSED.store(true, Ordering::Relaxed);
}

fn audit_suppressed() -> bool {
    AUDIT_SUPPRESSED.load(Ordering::Relaxed)
}

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
    if audit_suppressed() {
        return AuditLevel::Off;
    }
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
    crate::engine::runner::local_date_ymd()
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

/// Rotation slots kept per log file. Beyond this the oldest slot is reused.
const MAX_ROTATION_SLOTS: u32 = 9;

/// Renames `path` to the first free `<path>.<slot>`.
///
/// A fixed `.1` target would **overwrite** the previous rotation on POSIX and
/// therefore silently drop records; taking the first free slot keeps every
/// rotation until retention prunes it (`debug::log_file_matches` accepts any
/// `.log.<digits>`).
fn rotate(path: &Path) {
    let Some(name) = path.file_name() else {
        return;
    };
    let name = name.to_string_lossy();
    for slot in 1..=MAX_ROTATION_SLOTS {
        let candidate = path.with_file_name(format!("{name}.{slot}"));
        if !candidate.exists() {
            let _ = std::fs::rename(path, &candidate);
            return;
        }
    }
    // Every slot taken: reuse the oldest rather than let the live file grow
    // without bound. Retention prunes whole slots long before this is reached.
    let _ = std::fs::rename(path, path.with_file_name(format!("{name}.1")));
}

/// Renames `path` to `<path>.1` once it exceeds the rotation threshold.
pub fn rotate_if_oversized(path: &Path) {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > rotate_threshold()) {
        rotate(path);
    }
}

/// Creates the parent directory **once per process** instead of once per
/// record: `create_dir_all` costs a `mkdir` plus a `stat` on its happy path, and
/// the hot path only ever targets one or two log directories.
fn ensure_parent_dir(path: &Path) {
    static DONE: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

    let Some(parent) = path.parent() else {
        return;
    };
    if parent.as_os_str().is_empty() {
        return;
    }

    let done = DONE.get_or_init(|| Mutex::new(HashSet::new()));
    if let Ok(done) = done.lock()
        && done.contains(parent)
    {
        return;
    }
    if std::fs::create_dir_all(parent).is_ok()
        && let Ok(mut done) = done.lock()
    {
        done.insert(parent.to_path_buf());
    }
}

/// Appends one JSONL line. Never fails the caller — logging must not break the
/// decision path — but a failure is reported on stderr rather than swallowed.
///
/// The record is serialized into a single buffer and appended with **one**
/// `write_all` call. `writeln!(f, "{}", value)` would route through
/// `io::Write::write_fmt`, which emits one `write` syscall per formatting
/// fragment — and ai-hook runs many processes concurrently (one per rule,
/// several rules per tool call). Those partial writes interleave and tear whole
/// JSONL lines apart, which is exactly how the audit trail becomes unparseable.
/// A single `write_all` on an `O_APPEND` handle is atomic with respect to the
/// other appenders, and a *short* write is retried to completion rather than
/// being dropped, so no record is lost to a partial append.
///
/// The size probe that drives rotation is taken from the handle already held
/// (an `fstat`) instead of a path-based `stat`, which on Windows would add a
/// whole `CreateFile`/`Close` pair to every record.
pub fn append_jsonl(path: &Path, value: &Value) {
    ensure_parent_dir(path);

    let mut line = match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    line.push(b'\n');

    // At most two attempts: the second only happens right after a rotation.
    for attempt in 0..2 {
        let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        else {
            report_io_failure(path, "open");
            return;
        };

        if attempt == 0 && file.metadata().is_ok_and(|m| m.len() > rotate_threshold()) {
            drop(file);
            rotate(path);
            continue;
        }

        if file.write_all(&line).is_err() {
            report_io_failure(path, "write");
        }
        return;
    }
}

/// Logging never breaks the decision path, but it must not vanish silently
/// either: surface the failure where the hosting agent already collects output.
fn report_io_failure(path: &Path, op: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "[ai-hook] log {op} failed for {} (record not written)",
        path.display()
    );
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

    /// These tests share process-global state (the rotation threshold), so they
    /// must not overlap with each other.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn fresh_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ai-hook-log-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Every JSONL line produced for `path`, including any rotation slot
    /// (`<path>.1` … `<path>.9`) written while the test was running.
    fn all_lines(path: &Path) -> Vec<String> {
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let mut targets = vec![path.to_path_buf()];
        for slot in 1..=MAX_ROTATION_SLOTS {
            targets.push(path.with_file_name(format!("{name}.{slot}")));
        }
        let mut out = Vec::new();
        for p in targets {
            if let Ok(text) = std::fs::read_to_string(&p) {
                out.extend(text.lines().filter(|l| !l.is_empty()).map(str::to_string));
            }
        }
        out
    }

    /// The audit sink is appended by many ai-hook processes concurrently (one
    /// process per rule, several rules per tool call). Every append must land as
    /// one intact JSONL line — and **no record may be lost or duplicated**.
    #[test]
    fn append_jsonl_concurrent_writes_lose_nothing_and_never_interleave() {
        use std::sync::Arc;

        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = fresh_dir("concurrent");
        let path = Arc::new(dir.join("audit.log"));

        const THREADS: u64 = 24;
        const PER_THREAD: u64 = 40;
        // A payload large enough that a fragmented append would be split by a
        // concurrent writer.
        let filler = "x".repeat(2000);

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let path = Arc::clone(&path);
                let filler = filler.clone();
                std::thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        append_jsonl(&path, &json!({ "thread": t, "seq": i, "filler": filler }));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let lines = all_lines(&path);
        assert_eq!(
            lines.len() as u64,
            THREADS * PER_THREAD,
            "no record may be lost"
        );

        let mut seen = HashSet::new();
        for line in &lines {
            let value: Value = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!(
                    "torn/interleaved JSONL line ({e}): {}",
                    &line[..line.len().min(160)]
                )
            });
            let key = (
                value["thread"].as_u64().unwrap(),
                value["seq"].as_u64().unwrap(),
            );
            assert!(seen.insert(key), "record {key:?} was appended twice");
        }
        assert_eq!(seen.len() as u64, THREADS * PER_THREAD, "every record arrives once");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rotation moves records aside; it must never drop them.
    #[test]
    fn append_jsonl_rotation_keeps_every_record() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = fresh_dir("rotate");
        let path = dir.join("audit.log");

        let previous = ROTATE_AT_BYTES.swap(200, Ordering::Relaxed);
        for i in 0..12 {
            append_jsonl(&path, &json!({ "seq": i, "filler": "y".repeat(64) }));
        }
        ROTATE_AT_BYTES.store(previous, Ordering::Relaxed);

        assert!(
            path.with_file_name("audit.log.1").exists(),
            "an oversized file must be rotated aside"
        );
        let lines = all_lines(&path);
        assert_eq!(lines.len(), 12, "rotation must not lose records");
        for line in &lines {
            serde_json::from_str::<Value>(line).expect("rotated records stay parseable");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Informational: sustained single-writer append cost. Asserted only for
    /// completeness — run with `--nocapture` to read the printed rate.
    #[test]
    fn append_jsonl_throughput_probe() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = fresh_dir("throughput");
        let path = dir.join("audit.log");
        let record = json!({ "kind": "probe", "filler": "z".repeat(1000) });

        const N: usize = 5_000;
        let started = std::time::Instant::now();
        for _ in 0..N {
            append_jsonl(&path, &record);
        }
        let elapsed = started.elapsed();
        println!(
            "[probe] {N} appends in {elapsed:?} ({:.2} µs/append, {:.0} appends/s)",
            elapsed.as_secs_f64() * 1e6 / N as f64,
            N as f64 / elapsed.as_secs_f64()
        );

        assert_eq!(all_lines(&path).len(), N, "probe must not lose records");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
