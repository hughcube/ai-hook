use super::sys::create_sys_object;
use super::{RequestCache, RuleSource, SysContext};
use crate::i18n::{Msg, t, tf};
use crate::protocol::{HookContext, HookDecision};
use rquickjs::context::intrinsic::{Date, Eval, Json, MapSet, Promise, RegExp, RegExpCompiler};
use rquickjs::{Context, Function, Object, Runtime, Value};
use std::io::Write;
use std::rc::Rc;
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
/// Kept: JSON (`tool_args` / `raw` are parsed through it), RegExp + compiler
/// (every example rule matches with a regex literal), Date, Eval, Promise
/// (async rules are rejected — but they must fail as a *detectable* thenable
/// rather than as a syntax error), MapSet (plausible in real rules).
/// Dropped: TypedArrays, Proxy, WeakRef, Performance — no rule shape needs
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
    cache: RequestCache,
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
    let enabled = std::env::var("AI_HOOK_LOG_EXTERNAL")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v != "0" && v != "false" && v != "no" && v != "off"
        })
        .unwrap_or(false);
    if !enabled || raw.is_empty() {
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

        Ok(Self {
            runtime,
            cache: RequestCache::new(),
            timeout,
        })
    }

    /// Evaluates a single rule in an isolated QuickJS context.
    pub fn execute_rule(&self, rule: &RuleSource, ctx: &HookContext) -> RuleExecutionResult {
        let start = Instant::now();
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

        let sys_ctx = Rc::new(SysContext::new(&ctx.cwd, self.cache.clone()));
        let mut decision = None;
        let mut error = None;

        // Interrupt handler: QuickJS invokes it periodically while running JS.
        // Returning true aborts execution (thrown as an "interrupted" error),
        // which bounds runaway/infinite rule scripts.
        let timeout = self.timeout;
        let deadline = Instant::now() + timeout;
        self.runtime
            .set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));

        let agent_str = ctx.platform.to_string();
        let session_id = ctx.conversation.as_ref().and_then(|c| c.id.as_deref());

        let res = js_context.with(|js_ctx| -> rquickjs::Result<()> {
            // 1. Build the v2 ctx object in-place directly on QuickJS (zero redundant Rust serialization).
            let ctx_obj = Object::new(js_ctx.clone())?;
            ctx_obj.set("agent", agent_str.as_str())?;
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
            let args_val: Value = if !ctx.tool_args.is_null() {
                js_ctx
                    .json_parse(ctx.tool_args.to_string().as_bytes())
                    .unwrap_or_else(|_| Value::new_null(js_ctx.clone()))
            } else {
                Value::new_null(js_ctx.clone())
            };
            ctx_obj.set("args", args_val)?;
            if let Some(ref ev) = ctx.event {
                ctx_obj.set("event", ev.as_str())?;
            } else {
                ctx_obj.set("event", Value::new_null(js_ctx.clone()))?;
            }
            if let Some(ref pr) = ctx.prompt {
                ctx_obj.set("prompt", pr.as_str())?;
            } else {
                ctx_obj.set("prompt", Value::new_null(js_ctx.clone()))?;
            }
            let raw_val: Value = if !ctx.raw_input.is_empty() {
                js_ctx
                    .json_parse(ctx.raw_input.as_bytes())
                    .unwrap_or_else(|_| Value::new_null(js_ctx.clone()))
            } else {
                Value::new_null(js_ctx.clone())
            };
            ctx_obj.set("raw", raw_val)?;
            ctx_obj.set("rawInput", ctx.raw_input.as_str())?;

            // 1.5 Setup console.log -> stderr (+ optional file channel)
            let console_obj = Object::new(js_ctx.clone())?;
            let agent_for_log = agent_str.clone();
            let session_for_log = session_id.map(str::to_string);
            let rule_id_for_log = rule.id.clone();
            let log_fn = Function::new(
                js_ctx.clone(),
                move |args: rquickjs::function::Rest<String>| {
                    let msg = args.0.join(" ");
                    eprintln!("[{}] [rule-debug] {}", local_now_str(), msg);
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

            // 2. Build sys object (fs/git/env/cwd) + sys.log(level, ...msg)
            let sys_obj = create_sys_object(&js_ctx, sys_ctx)?;
            {
                let agent_for_log = agent_str.clone();
                let session_for_log = session_id.map(str::to_string);
                let rule_id_for_log = rule.id.clone();
                let sys_log_fn = Function::new(
                    js_ctx.clone(),
                    move |args: rquickjs::function::Rest<String>| {
                        let mut parts = args.0.into_iter();
                        let first = parts.next().unwrap_or_default();
                        let (level, msg) = if parts.len() == 0 {
                            ("log".to_string(), first)
                        } else {
                            (first, parts.collect::<Vec<_>>().join(" "))
                        };
                        eprintln!("[{}] [rule-debug][{}] {}", local_now_str(), level, msg);
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

            let rule_dir = rule
                .path
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let rule_path_str = rule.path.to_string_lossy().to_string();
            sys_obj.set("rulePath", rule_path_str.clone())?;
            sys_obj.set("ruleDir", rule_dir.clone())?;
            sys_obj.set("__filename", rule_path_str)?;
            sys_obj.set("__dirname", rule_dir)?;

            // 3. Prepare rule code: rewrite the top-level `export default`
            //    into a `return` statement (comments/strings are respected).
            let raw_code = rule.code.as_str();
            let prepared_code = match find_export_default(raw_code) {
                Some(pos) => {
                    let mut s = raw_code.to_string();
                    s.replace_range(pos..pos + EXPORT_DEFAULT_LEN, "return ");
                    s
                }
                None => raw_code.to_string(),
            };

            let wrapper = r#"
                (function(code, ctx, sys) {
                    function isThenable(v) {
                        return v != null &&
                               (typeof v === 'object' || typeof v === 'function') &&
                               typeof v.then === 'function';
                    }
                    try {
                        var factory = new Function("ctx", "sys", code);
                        var result = factory(ctx, sys);
                        if (typeof result === 'function') {
                            result = result(ctx, sys);
                        }
                        if (isThenable(result)) {
                            // Structured marker; the localized message is
                            // generated on the Rust side (language-agnostic).
                            return { __async_error: true };
                        }
                        return result;
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
            let raw_val: Value = eval_fn.call((prepared_code, ctx_obj, sys_obj))?;

            if let Some(obj) = raw_val.as_object() {
                if obj.get::<_, bool>("__async_error").unwrap_or(false) {
                    error = Some(async_rule_error());
                    return Ok(());
                }

                if let Ok(err_msg) = obj.get::<_, String>("__error") {
                    error = Some(normalize_rule_error(&err_msg));
                    return Ok(());
                }

                if let Ok(action) = obj.get::<_, String>("action") {
                    let reason = obj.get::<_, String>("reason").unwrap_or_default();
                    let title = obj.get::<_, String>("title").ok();
                    let gui = obj.get::<_, bool>("gui").ok();
                    let timeout = obj.get::<_, u32>("timeout").ok();
                    let explicit_force_gui = obj
                        .get::<_, bool>("force_gui")
                        .or_else(|_| obj.get::<_, bool>("forceGui"))
                        .ok();

                    let act = action.to_lowercase();
                    match act.as_str() {
                        "confirm" | "ask" | "prompt" => {
                            decision = Some(HookDecision::Confirm {
                                reason,
                                title,
                                gui,
                                timeout,
                                force_gui: explicit_force_gui,
                            });
                        }
                        "force_confirm" | "force_ask" | "force_gui" | "force_popup" => {
                            decision = Some(HookDecision::Confirm {
                                reason,
                                title,
                                gui: Some(true),
                                timeout,
                                force_gui: Some(true),
                            });
                        }
                        "block" => {
                            decision = Some(HookDecision::Block { reason });
                        }
                        "deny" | "reject" => {
                            decision = Some(HookDecision::Deny { reason });
                        }
                        "allow" | "pass" => {
                            decision = Some(HookDecision::Allow);
                        }
                        _ => {}
                    }
                }

                if decision.is_none() {
                    if let Ok(ctx_text) = obj
                        .get::<_, String>("additionalContext")
                        .or_else(|_| obj.get::<_, String>("additional_context"))
                    {
                        decision = Some(HookDecision::PostContext {
                            additional_context: ctx_text,
                        });
                    } else if let Ok(hook_output) = obj.get::<_, Object>("hookSpecificOutput")
                        && let Ok(ctx_text) = hook_output
                            .get::<_, String>("additionalContext")
                            .or_else(|_| hook_output.get::<_, String>("additional_context"))
                    {
                        decision = Some(HookDecision::PostContext {
                            additional_context: ctx_text,
                        });
                    }
                }
            } else if let Some(b) = raw_val.as_bool()
                && !b
            {
                decision = Some(HookDecision::Deny {
                    reason: tf(Msg::M002, &[&rule.id]),
                });
            }

            // A rule that yielded neither a decision nor an error returned
            // something the engine cannot interpret: a missing `return`, an
            // unknown `action` string, a bare `true`, a number, ... Only an
            // explicit null/undefined means "no opinion". Anything else is a
            // broken rule and MUST be reported, otherwise the fail-closed
            // check below sees (decision=None, error=None) and silently lets
            // the command through.
            if decision.is_none() && error.is_none() && !is_no_opinion(&raw_val) {
                error = Some(tf(Msg::M134, &[&rule.id]));
            }

            Ok(())
        });

        // Always clear the interrupt handler so it cannot leak into later rules.
        self.runtime.set_interrupt_handler(None);

        let elapsed = start.elapsed();

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
    /// Confirm or Deny. Under `ErrorPolicy::FailClosed`, a failing rule also
    /// short-circuits to Deny so a broken gate never opens silently.
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
                    | HookDecision::Block { .. }
                    | HookDecision::PostContext { .. } => {
                        return (dec, results);
                    }
                    HookDecision::Allow => {}
                }
            }
        }

        (HookDecision::Allow, results)
    }
}

/// Length of the literal `export default` (14 chars) replaced by `return `.
const EXPORT_DEFAULT_LEN: usize = "export default".len();

/// Normalizes error text (rquickjs prefixes vary across versions).
fn normalize_rule_error(err: &str) -> String {
    err.trim().to_string()
}

/// True when a rule explicitly declined to state an opinion (`return null`),
/// the documented way to hand control to the next rule.
///
/// `undefined` deliberately does NOT count: a function that simply falls off
/// the end is almost always a missing `return`, and a security gate must not
/// treat that as "this rule is fine with the command". Rules that want to pass
/// must say so with `return null`.
fn is_no_opinion(val: &Value) -> bool {
    val.is_null()
}

/// Locates the first top-level `export default` occurrence that is NOT inside a
/// comment or a string literal, is preceded by a non-identifier boundary and is
/// the first code on its line. Returns the byte offset of `export` in `code`.
///
/// This is deliberately conservative: if we cannot prove a candidate is the
/// real module export we return None (the code is then passed through as-is
/// and any real `export default` inside `new Function` surfaces as a syntax
/// error reported by the wrapper instead of a silent mis-replace).
fn find_export_default(code: &str) -> Option<usize> {
    let bytes = code.as_bytes();
    let n = bytes.len();
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
                if b == b'e' && bytes[i..].starts_with(b"export default") {
                    // Boundary: previous char must not be identifier-ish.
                    let prev_ok = i == 0
                        || !(bytes[i - 1].is_ascii_alphanumeric()
                            || bytes[i - 1] == b'_'
                            || bytes[i - 1] == b'$');
                    // Boundary: neither may the next char continue the
                    // identifier (`export defaultValue = 5` is not the default
                    // export; rewriting it would silently change semantics).
                    let next_idx = i + EXPORT_DEFAULT_LEN;
                    let next_ok = next_idx >= n
                        || !(bytes[next_idx].is_ascii_alphanumeric()
                            || bytes[next_idx] == b'_'
                            || bytes[next_idx] == b'$');
                    // Must be the first code on its line (only whitespace before).
                    let line_ok = code[..i]
                        .rfind('\n')
                        .map(|ls| code[ls + 1..i].chars().all(|c| c.is_whitespace()))
                        .unwrap_or_else(|| code[..i].chars().all(|c| c.is_whitespace()));
                    if prev_ok && line_ok && next_ok {
                        return Some(i);
                    }
                    i += "export".len();
                } else {
                    i += 1;
                }
            }
        }
    }
    None
}
