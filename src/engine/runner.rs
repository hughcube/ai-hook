use super::sys::create_sys_object;
use super::{RuleSource, SysContext};
use crate::errln;
use crate::i18n::{Msg, t, tf};
use crate::protocol::{HookContext, HookDecision, Mutation};
use rquickjs::context::intrinsic::{Date, Eval, Json, MapSet, Promise, RegExp, RegExpCompiler};
use rquickjs::{Coerced, Context, Function, Object, Runtime, Value};
use std::io::Write;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Default per-rule execution budget. Rules are synchronous QuickJS scripts;
/// without this bound a buggy infinite loop would hang the whole hook.
pub const DEFAULT_RULE_TIMEOUT: Duration = Duration::from_secs(5);

/// Builtins each rule context is created with.
///
/// `Context::full` registers every QuickJS intrinsic and measured 250-390 µs
/// per rule — more than half of a rule's total execution cost, paid again for
/// every rule. Rules are small synchronous scripts, so only what they can
/// realistically use is registered (measured ~40% cheaper context creation).
///
/// Kept: JSON (`ctx.args` is parsed through it; `ctx.raw` defers to a lazy
/// JS-side `JSON.parse` defined in the wrapper below), RegExp + compiler
/// (every example rule matches with a regex literal), Date, Eval, Promise
/// (async rules are rejected — but they must fail as a *detectable* thenable
/// rather than as a syntax error), MapSet (plausible in real rules).
/// Omitted: TypedArrays, Proxy, WeakRef, Performance — no rule shape needs
/// them, and each adds constructor objects to every single context.
type RuleIntrinsics = (Date, Eval, RegExpCompiler, RegExp, Json, Promise, MapSet);

/// Maximum size of the rule log file before it rotates to `<name>.1`.
const MAX_LOG_BYTES: u64 = 20 * 1024 * 1024;

/// Localized message for rules that return a Promise (async is unsupported).
fn async_rule_error() -> String {
    t(Msg::M000).to_string()
}

/// How to treat a rule that failed (syntax error, runtime exception,
/// timeout, async rule, ...). The engine is a security gate, so the
/// default is FailClosed: a broken rule must never silently allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorPolicy {
    /// Any rule error short-circuits to Deny (default).
    FailClosed,
    /// Errors are recorded and evaluation continues with the next rule.
    AllowOnError,
}

impl ErrorPolicy {
    pub fn from_flag(allow_on_error: bool) -> Self {
        if allow_on_error {
            Self::AllowOnError
        } else {
            Self::FailClosed
        }
    }
}

pub struct RuleRunner {
    runtime: Runtime,
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct RuleExecutionResult {
    pub rule_id: String,
    pub rule_path: std::path::PathBuf,
    pub decision: Option<HookDecision>,
    pub duration: Duration,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Rule log sink: stderr (default) + optional file channel.
//
// Design (per user decision):
// - Location:     ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log  (UTC day)
// - Aggregation:  one file per agent per day; every line is JSONL with
//                 ts/sessionId/rule/level/msg so one session's story can be
//                 reconstructed with `grep '"sessionId":"..."' file.log`.
// - Cost:         the file is only opened when a rule actually logs; rules
//                 that never log cost zero I/O.
// - Rotation:     >20MB renames to `<name>.1` (checked once per open).
// - Overrides:    AI_HOOK_LOG_FILE=<path>  custom file,
//                 AI_HOOK_LOG=0|false|off  disable file logging entirely.
// ---------------------------------------------------------------------------

fn log_file_disabled() -> bool {
    std::env::var("AI_HOOK_LOG")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "0" || v == "false" || v == "no" || v == "off"
        })
        .unwrap_or(false)
}

/// Returns the default (or AI_HOOK_LOG_FILE-overridden) log file path.
fn resolve_log_path(agent: &str) -> Option<std::path::PathBuf> {
    if let Ok(custom) = std::env::var("AI_HOOK_LOG_FILE") {
        let custom = custom.trim();
        if !custom.is_empty() {
            return Some(std::path::PathBuf::from(custom));
        }
    }
    let home = crate::paths::home_dir()?;
    Some(home.join(".ai-hook").join("logs").join(format!(
        "ai-hook-{}-{}.log",
        agent,
        utc_date_ymd()
    )))
}

/// Days since 1970-01-01 -> (y, m, d) in UTC (civil-from-days, Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Current UTC date as `YYYYMMDD` (file-name granularity; line timestamps are
/// epoch millis, so UTC-vs-local day boundaries only affect file splitting).
fn utc_date_ymd() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i128)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((ms / 86_400_000) as i64);
    format!("{y:04}{m:02}{d:02}")
}

/// Human-readable local time `YYYY-MM-DD HH:MM:SS` for log lines
/// (JSONL "time" field and stderr prefixes).
pub fn local_now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Appends one JSONL line to the rule log (opened on demand, then closed).
/// Never fails the caller: logging must not break rule evaluation.
fn append_rule_log(agent: &str, session_id: Option<&str>, rule_id: &str, level: &str, msg: &str) {
    if log_file_disabled() {
        return;
    }
    let Some(path) = resolve_log_path(agent) else {
        return;
    };

    // Rotate once if oversized (checked at open time — cheap).
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > MAX_LOG_BYTES
        && let Some(name) = path.file_name()
    {
        let rotated = path.with_file_name(format!("{}.1", name.to_string_lossy()));
        let _ = std::fs::rename(&path, &rotated);
    }

    let line = serde_json::json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        "time": local_now_str(),
        "agent": agent,
        "sessionId": session_id,
        "rule": rule_id,
        "level": level,
        "msg": msg,
    })
    .to_string();

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Append-only open: atomic for concurrent hook processes per line.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", line);
    }
}

// ---------------------------------------------------------------------------
// Inbound payload log (debug aid): AI_HOOK_LOG_EXTERNAL=1|true records the
// raw stdin payload every agent sent — captured BEFORE parsing, so payload
// shape / platform-detection / parse bugs can be diagnosed from the exact
// bytes the host delivered. Defaults to off; costs zero I/O when off.
//
// - File:    ~/.ai-hook/logs/ai-hook-inbound-{YYYYMMDD}.log
// - Format:  JSONL: {ts, bytes, truncated, payload}
// - Bounds:  payloads over 1 MiB store only their head (truncated: true) so
//            a huge transcript cannot balloon the log; 20MB rotation like the
//            rule log.
// ---------------------------------------------------------------------------
pub fn log_inbound_payload(raw: &str) {
    // Enabled only by 1/true, exactly as the tutorial documents
    // (AI_HOOK_LOG_EXTERNAL=1|true) — same convention as the other env flags.
    if !crate::protocol::env_flag_true("AI_HOOK_LOG_EXTERNAL") || raw.is_empty() {
        return;
    }

    const MAX_RAW_BYTES: usize = 1024 * 1024;
    let truncated = raw.len() > MAX_RAW_BYTES;
    let cut = raw.floor_char_boundary(MAX_RAW_BYTES);
    let stored = if truncated { &raw[..cut] } else { raw };

    let Some(home) = crate::paths::home_dir() else {
        return;
    };
    let path = home
        .join(".ai-hook")
        .join("logs")
        .join(format!("ai-hook-inbound-{}.log", utc_date_ymd()));

    // Rotate once if oversized (checked at open time — cheap).
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > MAX_LOG_BYTES
        && let Some(name) = path.file_name()
    {
        let rotated = path.with_file_name(format!("{}.1", name.to_string_lossy()));
        let _ = std::fs::rename(&path, &rotated);
    }

    let line = serde_json::json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        "time": local_now_str(),
        "bytes": raw.len(),
        "truncated": truncated,
        "payload": stored,
    })
    .to_string();

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Append-only open: atomic for concurrent hook processes per line.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", line);
    }
}

impl RuleRunner {
    pub fn new() -> rquickjs::Result<Self> {
        Self::with_timeout(DEFAULT_RULE_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> rquickjs::Result<Self> {
        let runtime = Runtime::new()?;
        // Memory limit 64MB, adequate for lightweight security rules
        runtime.set_memory_limit(64 * 1024 * 1024);
        // Max stack size 1MB
        runtime.set_max_stack_size(1024 * 1024);

        Ok(Self { runtime, timeout })
    }

    /// Evaluates a single rule in an isolated QuickJS context.
    pub fn execute_rule(&self, rule: &RuleSource, ctx: &HookContext) -> RuleExecutionResult {
        let start = Instant::now();

        // Temporary engine-internal profiler (AI_HOOK_ENGINE_PROFILE=1).
        // Cached in a OnceLock so the no-profile fast path never re-reads env.
        static EP: OnceLock<bool> = OnceLock::new();
        let ep = *EP.get_or_init(|| {
            std::env::var("AI_HOOK_ENGINE_PROFILE")
                .map(|v| {
                    let v = v.trim().to_ascii_lowercase();
                    v == "1" || v == "true" || v == "on"
                })
                .unwrap_or(false)
        });
        let mut marks: Vec<(&'static str, f64)> = Vec::new();
        macro_rules! emark {
            ($label:expr) => {
                if ep {
                    marks.push(($label, start.elapsed().as_secs_f64() * 1000.0));
                }
            };
        }

        let js_context = match Context::custom::<RuleIntrinsics>(&self.runtime) {
            Ok(c) => c,
            Err(e) => {
                return RuleExecutionResult {
                    rule_id: rule.id.clone(),
                    rule_path: rule.path.clone(),
                    decision: None,
                    duration: start.elapsed(),
                    error: Some(tf(Msg::M001, &[&e])),
                };
            }
        };
        emark!("context_custom");

        let sys_ctx = Rc::new(SysContext::new(&ctx.cwd));
        let mut decision = None;
        let mut error = None;

        // Interrupt handler: QuickJS invokes it periodically while running JS.
        // Returning true aborts execution (thrown as an "interrupted" error),
        // which bounds runaway/infinite rule scripts.
        let timeout = self.timeout;
        let deadline = Instant::now() + timeout;
        self.runtime
            .set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
        emark!("setup_interrupt");

        let platform_str = ctx.platform.to_string();
        let session_id = ctx.conversation.as_ref().and_then(|c| c.id.as_deref());

        let res = js_context.with(|js_ctx| -> rquickjs::Result<()> {
            // 1. Build the ctx object in-place directly on QuickJS (zero redundant Rust serialization).
            let ctx_obj = Object::new(js_ctx.clone())?;
            ctx_obj.set("platform", platform_str.as_str())?;
            // The engine already downgrades decisions the host cannot express
            // (protocol::output::to_op), so a rule never needs to hand-write
            // that fallback — and no capability-query API is exposed.
            if let Some(ref m) = ctx.permission_mode {
                ctx_obj.set("mode", m.as_str())?;
            } else {
                ctx_obj.set("mode", Value::new_null(js_ctx.clone()))?;
            }
            ctx_obj.set("isYolo", ctx.is_yolo)?;
            if let Some(ref c) = ctx.conversation {
                let session_obj = Object::new(js_ctx.clone())?;
                if let Some(ref id) = c.id {
                    session_obj.set("id", id.as_str())?;
                } else {
                    session_obj.set("id", Value::new_null(js_ctx.clone()))?;
                }
                if let Some(ref tp) = c.transcript_path {
                    session_obj.set("transcriptPath", tp.as_str())?;
                } else {
                    session_obj.set("transcriptPath", Value::new_null(js_ctx.clone()))?;
                }
                ctx_obj.set("session", session_obj)?;
            } else {
                ctx_obj.set("session", Value::new_null(js_ctx.clone()))?;
            }
            ctx_obj.set("cwd", ctx.cwd.as_str())?;
            if let Some(ref m) = ctx.model {
                ctx_obj.set("model", m.as_str())?;
            } else {
                ctx_obj.set("model", Value::new_null(js_ctx.clone()))?;
            }
            ctx_obj.set("tool", ctx.tool_name.as_str())?;
            if let Some(ref c) = ctx.cmd {
                ctx_obj.set("cmd", c.as_str())?;
            } else {
                ctx_obj.set("cmd", Value::new_null(js_ctx.clone()))?;
            }
            if let Some(ref f) = ctx.file {
                let file_obj = Object::new(js_ctx.clone())?;
                if let Some(ref p) = f.path {
                    file_obj.set("path", p.as_str())?;
                } else {
                    file_obj.set("path", Value::new_null(js_ctx.clone()))?;
                }
                file_obj.set("action", f.action.as_str())?;
                ctx_obj.set("file", file_obj)?;
            } else {
                ctx_obj.set("file", Value::new_null(js_ctx.clone()))?;
            }
            // MCP view: {server, tool} — host spellings mcp__s__t / mcp_s_t
            // both normalize here; parameters stay in ctx.args.
            if let Some(ref m) = ctx.mcp {
                let mcp_obj = Object::new(js_ctx.clone())?;
                if let Some(ref s) = m.server {
                    mcp_obj.set("server", s.as_str())?;
                } else {
                    mcp_obj.set("server", Value::new_null(js_ctx.clone()))?;
                }
                if let Some(ref t) = m.tool {
                    mcp_obj.set("tool", t.as_str())?;
                } else {
                    mcp_obj.set("tool", Value::new_null(js_ctx.clone()))?;
                }
                ctx_obj.set("mcp", mcp_obj)?;
            } else {
                ctx_obj.set("mcp", Value::new_null(js_ctx.clone()))?;
            }
            // Web view: {action: "fetch"|"search", url, query}.
            if let Some(ref w) = ctx.web {
                let web_obj = Object::new(js_ctx.clone())?;
                web_obj.set("action", w.action.as_str())?;
                if let Some(ref u) = w.url {
                    web_obj.set("url", u.as_str())?;
                } else {
                    web_obj.set("url", Value::new_null(js_ctx.clone()))?;
                }
                if let Some(ref q) = w.query {
                    web_obj.set("query", q.as_str())?;
                } else {
                    web_obj.set("query", Value::new_null(js_ctx.clone()))?;
                }
                ctx_obj.set("web", web_obj)?;
            } else {
                ctx_obj.set("web", Value::new_null(js_ctx.clone()))?;
            }
            // Code-search view: {kind: "glob"|"grep", path, pattern}.
            if let Some(ref s) = ctx.search {
                let search_obj = Object::new(js_ctx.clone())?;
                search_obj.set("kind", s.kind.as_str())?;
                if let Some(ref p) = s.path {
                    search_obj.set("path", p.as_str())?;
                } else {
                    search_obj.set("path", Value::new_null(js_ctx.clone()))?;
                }
                if let Some(ref pat) = s.pattern {
                    search_obj.set("pattern", pat.as_str())?;
                } else {
                    search_obj.set("pattern", Value::new_null(js_ctx.clone()))?;
                }
                ctx_obj.set("search", search_obj)?;
            } else {
                ctx_obj.set("search", Value::new_null(js_ctx.clone()))?;
            }
            // Delegation view: {kind: "agent"|"workflow"|"task",
            // description, prompt}.
            if let Some(ref a) = ctx.agent {
                let agent_obj = Object::new(js_ctx.clone())?;
                agent_obj.set("kind", a.kind.as_str())?;
                if let Some(ref d) = a.description {
                    agent_obj.set("description", d.as_str())?;
                } else {
                    agent_obj.set("description", Value::new_null(js_ctx.clone()))?;
                }
                if let Some(ref p) = a.prompt {
                    agent_obj.set("prompt", p.as_str())?;
                } else {
                    agent_obj.set("prompt", Value::new_null(js_ctx.clone()))?;
                }
                ctx_obj.set("agent", agent_obj)?;
            } else {
                ctx_obj.set("agent", Value::new_null(js_ctx.clone()))?;
            }
            let args_val: Value = if !ctx.args.is_null() {
                js_ctx
                    .json_parse(ctx.args.to_string().as_bytes())
                    .unwrap_or_else(|_| Value::new_null(js_ctx.clone()))
            } else {
                Value::new_null(js_ctx.clone())
            };
            ctx_obj.set("args", args_val)?;
            // ctx.event is the CANONICAL, host-independent event name: Gemini
            // fires "AfterTool" and Antigravity sends nothing at all, yet a
            // rule written as `ctx.event === "PostToolUse"` must work on every
            // host — that portability is the whole point of this engine. The
            // host's own spelling stays available as ctx.eventRaw.
            let event_canonical = {
                let s = ctx.event_enum.canonical_name();
                if s.is_empty() {
                    ctx.event.clone().unwrap_or_default()
                } else {
                    s.to_string()
                }
            };
            let event_raw = ctx.event_raw.clone().unwrap_or_default();
            if event_canonical.is_empty() {
                ctx_obj.set("event", Value::new_null(js_ctx.clone()))?;
            } else {
                ctx_obj.set("event", event_canonical.as_str())?;
            }
            if event_raw.is_empty() {
                ctx_obj.set("eventRaw", Value::new_null(js_ctx.clone()))?;
            } else {
                ctx_obj.set("eventRaw", event_raw.as_str())?;
            }
            if let Some(ref pr) = ctx.prompt {
                ctx_obj.set("prompt", pr.as_str())?;
            } else {
                ctx_obj.set("prompt", Value::new_null(js_ctx.clone()))?;
            }
            // ctx.raw is intentionally NOT parsed here. It is an escape hatch
            // (rules should prefer cmd/file/args) and payloads can be megabytes
            // of transcript; since the ctx object is rebuilt for every rule,
            // the parse is deferred to first access inside the wrapper.
            ctx_obj.set("rawInput", ctx.raw_input.as_str())?;
            emark!("ctx_object");

            // 1.5 Setup console.log -> stderr (+ optional file channel)
            let console_obj = Object::new(js_ctx.clone())?;
            let agent_for_log = platform_str.clone();
            let session_for_log = session_id.map(str::to_string);
            let rule_id_for_log = rule.id.clone();
            let log_fn = Function::new(
                js_ctx.clone(),
                move |args: rquickjs::function::Rest<Coerced<String>>| {
                    // Coerced<String>: console.log(1) / console.log(null) must
                    // coerce like plain JS ("1" / "null"). A bare String param
                    // is strict (FromJs accepts only real strings) and would
                    // throw TypeError, failing the whole rule fail-closed.
                    let msg = args.0.iter().map(|s| s.0.as_str()).collect::<Vec<_>>().join(" ");
                    errln!("[{}] [rule-debug] {}", local_now_str(), msg);
                    append_rule_log(
                        &agent_for_log,
                        session_for_log.as_deref(),
                        &rule_id_for_log,
                        "log",
                        &msg,
                    );
                },
            )?;
            console_obj.set("log", log_fn.clone())?;
            console_obj.set("error", log_fn)?;
            js_ctx.globals().set("console", console_obj)?;
            emark!("console_setup");

            // 2. Build sys object (fs/git/env/cwd) + sys.log(level, ...msg)
            let sys_obj = create_sys_object(&js_ctx, sys_ctx)?;
            {
                let agent_for_log = platform_str.clone();
                let session_for_log = session_id.map(str::to_string);
                let rule_id_for_log = rule.id.clone();
                let sys_log_fn = Function::new(
                    js_ctx.clone(),
                    move |args: rquickjs::function::Rest<Coerced<String>>| {
                        // Coerced<String> for the same reason as console.log:
                        // sys.log("info", 42) / sys.log(level, null) must not
                        // throw; JS coercion mirrors console.log semantics.
                        let mut parts = args.0.iter().map(|s| s.0.as_str());
                        let first = parts.next().unwrap_or_default();
                        let rest: Vec<&str> = parts.collect();
                        let (level, msg) = if rest.is_empty() {
                            ("log".to_string(), first.to_string())
                        } else {
                            (first.to_string(), rest.join(" "))
                        };
                        errln!("[{}] [rule-debug][{}] {}", local_now_str(), level, msg);
                        append_rule_log(
                            &agent_for_log,
                            session_for_log.as_deref(),
                            &rule_id_for_log,
                            &level,
                            &msg,
                        );
                    },
                )?;
                sys_obj.set("log", sys_log_fn)?;
            }

            // Rule-file location: one pair of names (sys.rulePath / sys.ruleDir)
            // so a rule never has to guess which spelling exists.
            let rule_dir = rule
                .path
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            sys_obj.set("rulePath", rule.path.to_string_lossy().to_string())?;
            sys_obj.set("ruleDir", rule_dir)?;
            emark!("sys_object");

            // 3. Prepare rule code: rewrite top-level `export` statements for
            //    execution inside `new Function` (comments/strings respected):
            //      export default <expr>            -> var __ai_default__ = <expr>
            //      export function NAME(...)       -> function NAME(...)
            //      export async function NAME(...) -> async function NAME(...)
            //    then append a tail returning the handler table so the wrapper
            //    can dispatch by the current event name.
            let (prepared_code, event_name) = {
                let mut s = rule.code.clone();
                let hits = find_exports(&s);
                let mut names: Vec<String> = Vec::new();
                let mut has_default = false;
                // Back to front so earlier offsets stay valid while splicing.
                for hit in hits.into_iter().rev() {
                    match hit {
                        ExportHit::Default { offset } => {
                            s.replace_range(offset..offset + 14, "var __ai_default__ = ");
                            has_default = true;
                        }
                        ExportHit::Handler { offset, name } => {
                            s.replace_range(offset..offset + "export ".len(), "");
                            names.push(name);
                        }
                    }
                }
                if has_default || !names.is_empty() {
                    // The leading newline terminates a trailing line comment:
                    // `... // note` + `;return {...}` would otherwise be
                    // swallowed by the comment and the rule would silently
                    // lose every handler.
                    let mut tail = String::from("\n;return { __fns__: {");
                    for name in &names {
                        tail.push_str(name);
                        tail.push_str(": typeof ");
                        tail.push_str(name);
                        tail.push_str(" !== 'undefined' ? ");
                        tail.push_str(name);
                        tail.push_str(" : undefined,");
                    }
                    tail.push_str(
                        "}, __default__: typeof __ai_default__ !== 'undefined' ? __ai_default__ : undefined };",
                    );
                    s.push_str(&tail);
                }
                // Handler dispatch must use the canonical name: a rule exports
                // `PostToolUse` because the tutorial documents canonical event
                // names, and Gemini fires "AfterTool" — dispatching by the raw
                // host name would silently never match there. The wrapper
                // still falls back to the host spelling (and ctx.eventRaw)
                // for robustness.
                let ev = ctx.event_enum.canonical_name();
                let ev = if ev.is_empty() {
                    ctx.event.as_deref().unwrap_or("")
                } else {
                    ev
                };
                (s, ev.to_string())
            };
            emark!("code_prepare");

            let wrapper = r#"
                (function(code, ctx, sys, eventName) {
                    function isThenable(v) {
                        return v != null &&
                               (typeof v === 'object' || typeof v === 'function') &&
                               typeof v.then === 'function';
                    }
                    try {
                        // Lazy ctx.raw: the raw payload can be megabytes of
                        // transcript and this context is rebuilt per rule, so
                        // parse only when a rule actually touches it. The
                        // parsed value is memoized on first access ("parsed
                        // on first access" per the docs) so repeated reads in
                        // one rule cost nothing; the cache dies with the
                        // per-rule context.
                        var __raw_cache;
                        Object.defineProperty(ctx, "raw", {
                            enumerable: true,
                            configurable: true,
                            get: function() {
                                if (__raw_cache === undefined) {
                                    try {
                                        __raw_cache = JSON.parse(ctx.rawInput);
                                    } catch (e) {
                                        // Parse failure is memoized as null
                                        // (matches the previous error
                                        // semantics and avoids re-parsing
                                        // known-bad input on every access).
                                        __raw_cache = null;
                                    }
                                }
                                return __raw_cache;
                            }
                        });
                        var factory = new Function("ctx", "sys", code);
                        var result = factory(ctx, sys);
                        var v;
                        if (result && typeof result === 'object' && result.__fns__) {
                            var handler = result.__fns__[eventName];
                            if (typeof handler !== 'function') handler = result.__fns__[ctx.event];
                            if (typeof handler !== 'function') handler = result.__fns__[ctx.eventRaw];
                            if (typeof handler !== 'function') handler = result.__default__;
                            v = (typeof handler === 'function') ? handler(ctx, sys) : undefined;
                        } else {
                            v = result;
                            if (typeof v === 'function') {
                                v = v(ctx, sys);
                            }
                        }
                        if (isThenable(v)) {
                            // Structured marker; the localized message is
                            // generated on the Rust side (language-agnostic).
                            return { __async_error: true };
                        }
                        return v;
                    } catch (err) {
                        // NOTE: the watchdog interrupt (deadline exceeded) also
                        // lands here as an opaque "Exception generated by
                        // QuickJS"; execute_rule classifies timeouts by elapsed
                        // time afterwards instead of parsing this text.
                        return { __error: String(err) };
                    }
                })
            "#;

            let eval_fn: Function = js_ctx.eval(wrapper)?;
            emark!("wrapper_eval");
            let raw_val: Value = eval_fn.call((prepared_code, ctx_obj, sys_obj, event_name))?;
            emark!("rule_exec");

            if let Some(obj) = raw_val.as_object() {
                if obj.get::<_, bool>("__async_error").unwrap_or(false) {
                    error = Some(async_rule_error());
                    return Ok(());
                }

                if let Ok(err_msg) = obj.get::<_, String>("__error") {
                    error = Some(normalize_rule_error(&err_msg));
                    return Ok(());
                }

                // ---- intent syntax --------------------------------------
                // Gate (exactly one wins): deny > ask > allow.
                // Modifiers (combinable): inject / mutateInput / replaceOutput.
                // Stop events: keepGoing.
                let deny = obj.get::<_, String>("deny").ok();
                let ask = obj.get::<_, String>("ask").ok();
                let allow = obj.get::<_, bool>("allow").ok();
                let keep_going = obj.get::<_, String>("keepGoing").ok();

                let mutation = Mutation {
                    inject: obj.get::<_, String>("inject").ok(),
                    mutate_input: obj
                        .get::<_, rquickjs::Value>("mutateInput")
                        .ok()
                        .and_then(|v| {
                            js_ctx
                                .json_stringify(v)
                                .ok()
                                .flatten()
                                .and_then(|s| s.to_string().ok())
                                .and_then(|s| serde_json::from_str(&s).ok())
                        }),
                    // replaceOutput accepts a string (the common case) or a
                    // structured value matching a tool's output shape — Claude
                    // Code ignores a shape-mismatched `updatedToolOutput`, so
                    // built-in tool replacement needs the object form.
                    replace_output: obj
                        .get::<_, rquickjs::Value>("replaceOutput")
                        .ok()
                        .and_then(|v| {
                            js_ctx
                                .json_stringify(v)
                                .ok()
                                .flatten()
                                .and_then(|s| s.to_string().ok())
                                .and_then(|s| serde_json::from_str(&s).ok())
                        }),
                };

                // A gate decision (deny/ask/keepGoing) shadows the modifiers
                // (inject/mutateInput/replaceOutput) below; that used to drop
                // the modifiers silently. Warn so the author sees it in the
                // stderr/log channel instead of debugging a no-op inject.
                if (deny.is_some() || ask.is_some() || keep_going.is_some())
                    && !mutation.is_empty()
                {
                    errln!("[ai-hook] {}", tf(Msg::M158, &[&rule.id]));
                }

                decision = if let Some(reason) = deny {
                    Some(HookDecision::Deny { reason })
                } else if let Some(reason) = ask {
                    Some(HookDecision::Confirm {
                        reason,
                        title: obj.get::<_, String>("title").ok(),
                        gui: obj.get::<_, bool>("gui").ok(),
                        timeout: obj.get::<_, u32>("timeout").ok(),
                        force_gui: obj.get::<_, bool>("forceGui").ok(),
                    })
                } else if let Some(reason) = keep_going {
                    Some(HookDecision::KeepGoing { reason })
                } else if !mutation.is_empty() {
                    Some(HookDecision::Modify(mutation))
                } else if allow == Some(true) {
                    Some(HookDecision::Allow)
                } else {
                    None
                };
            } else if let Some(b) = raw_val.as_bool()
                && !b
            {
                decision = Some(HookDecision::Deny {
                    reason: tf(Msg::M002, &[&rule.id]),
                });
            }

            // A rule that yielded neither a decision nor an error returned
            // something the engine cannot interpret: an unknown key, a bare
            // `true`, a number, ... Only an explicit null/undefined means
            // "no opinion". Anything else is a broken rule and MUST be
            // reported, otherwise the fail-closed check below sees
            // (decision=None, error=None) and silently lets the command
            // through.
            if decision.is_none() && error.is_none() && !is_no_opinion(&raw_val) {
                error = Some(tf(Msg::M134, &[&rule.id]));
            }

            Ok(())
        });

        // Always clear the interrupt handler so it cannot leak into later rules.
        self.runtime.set_interrupt_handler(None);
        emark!("clear_interrupt");

        let elapsed = start.elapsed();
        if ep {
            let mut prev = 0.0f64;
            errln!("[ai-hook-engine-profile] rule={}", rule.id);
            for (label, t) in &marks {
                errln!(
                    "  {:<18} cum {:7.3} ms   seg {:7.3} ms",
                    label,
                    t,
                    (t - prev).max(0.0)
                );
                prev = *t;
            }
            errln!(
                "  {:<18} cum {:7.3} ms   seg {:7.3} ms",
                "total",
                elapsed.as_secs_f64() * 1000.0,
                (elapsed.as_secs_f64() * 1000.0 - prev).max(0.0)
            );
        }

        if let Err(e) = res
            && error.is_none()
        {
            error = Some(normalize_rule_error(&e.to_string()));
        }

        // The watchdog interrupt fires once the deadline passes, whether it
        // surfaces as a Rust error or is swallowed by the wrapper's catch.
        // Execution that outlived the deadline without producing a decision is
        // a timeout and must be reported as such (not as an opaque engine
        // error), regardless of the interrupt's textual representation.
        if elapsed >= timeout && decision.is_none() {
            error = Some(tf(Msg::M003, &[&format!("{:?}", timeout)]));
        }

        RuleExecutionResult {
            rule_id: rule.id.clone(),
            rule_path: rule.path.clone(),
            decision,
            duration: start.elapsed(),
            error,
        }
    }

    /// Evaluates a list of rules sequentially. Short-circuits on the first
    /// decisive outcome (Confirm / Deny / Modify / KeepGoing). Under
    /// `ErrorPolicy::FailClosed`, a failing rule also short-circuits to Deny
    /// so a broken gate never opens silently.
    pub fn evaluate_all(
        &self,
        rules: &[RuleSource],
        ctx: &HookContext,
        policy: ErrorPolicy,
    ) -> (HookDecision, Vec<RuleExecutionResult>) {
        let mut results = Vec::new();

        for rule in rules {
            let res = self.execute_rule(rule, ctx);

            // A rule that failed without producing a decision must not be
            // treated as "pass" when the gate is fail-closed.
            if policy == ErrorPolicy::FailClosed
                && res.decision.is_none()
                && let Some(err) = res.error.clone()
            {
                results.push(res);
                let reason = tf(Msg::M004, &[&rule.id, &err]);
                return (HookDecision::Deny { reason }, results);
            }

            let hit = res.decision.clone();
            results.push(res);

            if let Some(dec) = hit {
                match dec {
                    HookDecision::Confirm { .. }
                    | HookDecision::Deny { .. }
                    | HookDecision::Modify(_)
                    | HookDecision::KeepGoing { .. } => {
                        return (dec, results);
                    }
                    HookDecision::Allow => {}
                }
            }
        }

        (HookDecision::Allow, results)
    }
}

/// Normalizes error text (rquickjs prefixes vary across versions).
fn normalize_rule_error(err: &str) -> String {
    err.trim().to_string()
}

/// True when a rule explicitly declined to state an opinion (`return null`),
/// the documented way to hand control to the next rule. `undefined` counts as
/// "no opinion" too: with per-event named exports a handler whose
/// guard does not match simply falls off the end, and that is the normal case
/// rather than a missing return. Any other unrecognizable value is still an
/// engine error (fail-closed), see the check at the call site.
fn is_no_opinion(val: &Value) -> bool {
    val.is_null() || val.is_undefined()
}

/// A top-level `export ...` occurrence found by [`find_exports`].
enum ExportHit {
    /// `export default <expr>`
    Default { offset: usize },
    /// `export [async] function NAME(...)`
    Handler { offset: usize, name: String },
}

/// Reads an ASCII identifier from the start of `s`.
fn take_ident(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '$')
        .collect()
}

/// Locates every top-level `export` occurrence that is NOT inside a comment or
/// a string literal, is preceded by a non-identifier boundary and is the first
/// code on its line.
///
/// This is deliberately conservative: candidates we cannot prove to be real
/// module exports are skipped (the code is then passed through as-is and any
/// real `export` inside `new Function` surfaces as a syntax error reported by
/// the wrapper instead of a silent mis-replace).
fn find_exports(code: &str) -> Vec<ExportHit> {
    const EXPORT: &str = "export ";
    let bytes = code.as_bytes();
    let n = bytes.len();
    let mut hits = Vec::new();
    let mut i = 0usize;

    while i < n {
        let b = bytes[i];
        match b {
            // Line comment
            b'/' if i + 1 < n && bytes[i + 1] == b'/' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // Block comment
            b'/' if i + 1 < n && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(n);
            }
            // String / template literals (with escape handling)
            b'\'' | b'"' | b'`' => {
                let quote = b;
                i += 1;
                while i < n {
                    if bytes[i] == b'\\' {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == quote {
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            _ => {
                if b == b'e' && bytes[i..].starts_with(EXPORT.as_bytes()) {
                    // Boundary: previous char must not be identifier-ish.
                    let prev_ok = i == 0
                        || !(bytes[i - 1].is_ascii_alphanumeric()
                            || bytes[i - 1] == b'_'
                            || bytes[i - 1] == b'$');
                    // Must be the first code on its line (only whitespace before).
                    let line_ok = code[..i]
                        .rfind('\n')
                        .map(|ls| code[ls + 1..i].chars().all(|c| c.is_whitespace()))
                        .unwrap_or_else(|| code[..i].chars().all(|c| c.is_whitespace()));

                    if prev_ok && line_ok {
                        let after = &code[i + EXPORT.len()..];
                        let after_trim = after.trim_start();
                        if after_trim.starts_with("default") {
                            // `export defaultValue = ...` is not the default export.
                            let d_end = i + EXPORT.len() + (after.len() - after_trim.len()) + 7;
                            let next_ok = d_end >= n
                                || !(bytes[d_end].is_ascii_alphanumeric()
                                    || bytes[d_end] == b'_'
                                    || bytes[d_end] == b'$');
                            if next_ok {
                                hits.push(ExportHit::Default { offset: i });
                            }
                        } else if let Some(rest) = after_trim.strip_prefix("function ") {
                            let name = take_ident(rest);
                            if !name.is_empty() {
                                hits.push(ExportHit::Handler { offset: i, name });
                            }
                        } else if let Some(rest) = after_trim.strip_prefix("async function ") {
                            let name = take_ident(rest);
                            if !name.is_empty() {
                                hits.push(ExportHit::Handler { offset: i, name });
                            }
                        }
                    }
                }
                i += 1;
            }
        }
    }
    hits
}
