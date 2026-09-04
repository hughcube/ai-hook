use super::loader::RuleSource;
use super::sys::{create_sys_object, RequestCache, SysContext};
use crate::protocol::{HookContext, HookDecision};
use rquickjs::{Context, Function, Object, Runtime, Value};
use std::rc::Rc;
use std::time::{Duration, Instant};

pub struct RuleRunner {
    runtime: Runtime,
    cache: RequestCache,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuleExecutionResult {
    pub rule_id: String,
    pub rule_path: std::path::PathBuf,
    pub decision: Option<HookDecision>,
    pub duration: Duration,
    pub error: Option<String>,
}

impl RuleRunner {
    pub fn new() -> rquickjs::Result<Self> {
        let runtime = Runtime::new()?;
        // Memory limit 64MB, adequate for lightweight security rules
        runtime.set_memory_limit(64 * 1024 * 1024);
        // Max stack size 1MB
        runtime.set_max_stack_size(1024 * 1024);

        Ok(Self {
            runtime,
            cache: RequestCache::new(),
        })
    }

    /// Evaluates a single rule in an isolated QuickJS context.
    pub fn execute_rule(
        &self,
        rule: &RuleSource,
        ctx: &HookContext,
    ) -> RuleExecutionResult {
        let start = Instant::now();
        let js_context = match Context::full(&self.runtime) {
            Ok(c) => c,
            Err(e) => {
                return RuleExecutionResult {
                    rule_id: rule.id.clone(),
                    rule_path: rule.path.clone(),
                    decision: None,
                    duration: start.elapsed(),
                    error: Some(format!("Failed to create JS context: {}", e)),
                };
            }
        };

        let sys_ctx = Rc::new(SysContext::new(&ctx.cwd, self.cache.clone()));
        let mut decision = None;
        let mut error = None;

        let res = js_context.with(|js_ctx| -> rquickjs::Result<()> {
            // 1. Build ctx object
            let ctx_obj = Object::new(js_ctx.clone())?;

            let agent_str = ctx.platform.to_string();
            ctx_obj.set("agent", agent_str.clone())?;
            ctx_obj.set("agentType", agent_str.clone())?;
            ctx_obj.set("platform", agent_str)?;

            ctx_obj.set("cmd", ctx.cmd.clone())?;
            ctx_obj.set("tool", ctx.tool_name.clone())?;
            ctx_obj.set("toolName", ctx.tool_name.clone())?;
            ctx_obj.set("file", ctx.target_file.clone())?;
            ctx_obj.set("targetFile", ctx.target_file.clone())?;
            ctx_obj.set("cwd", ctx.cwd.clone())?;
            ctx_obj.set("rawInput", ctx.raw_input.clone())?;
            ctx_obj.set("isYolo", ctx.is_yolo)?;

            if let Some(ref cid) = ctx.conversation_id {
                ctx_obj.set("conversationId", cid.clone())?;
            }

            // Injected parsed raw payload
            if let Ok(raw_val) = js_ctx.json_parse(ctx.raw_input.as_bytes()) {
                ctx_obj.set("raw", raw_val)?;
            } else {
                ctx_obj.set("raw", ctx.raw_input.clone())?;
            }

            // Injected tool arguments
            let args_json_str = ctx.tool_args.to_string();
            if let Ok(args_val) = js_ctx.json_parse(args_json_str.as_bytes()) {
                ctx_obj.set("args", args_val)?;
            }

            // 1.5 Setup console.log
            let console_obj = Object::new(js_ctx.clone())?;
            let log_fn = Function::new(js_ctx.clone(), |args: rquickjs::function::Rest<String>| {
                eprintln!("[rule-debug] {}", args.0.join(" "));
            })?;
            console_obj.set("log", log_fn.clone())?;
            console_obj.set("error", log_fn)?;
            js_ctx.globals().set("console", console_obj)?;

            // 2. Build sys object
            let sys_obj = create_sys_object(&js_ctx, sys_ctx)?;

            let raw_code = rule.code.as_str();
            let re_export = regex::Regex::new(r"(?m)^\s*export\s+default\s+").unwrap();
            let prepared_code = if re_export.is_match(raw_code) {
                re_export.replace(raw_code, "return ").to_string()
            } else {
                raw_code.to_string()
            };

            let wrapper = r#"
                (function(code, ctx, sys) {
                    try {
                        var factory = new Function("ctx", "sys", code);
                        var result = factory(ctx, sys);
                        if (typeof result === 'function') {
                            return result(ctx, sys);
                        }
                        return result;
                    } catch (err) {
                        return { __error: String(err) };
                    }
                })
            "#;

            let eval_fn: Function = js_ctx.eval(wrapper)?;
            let raw_val: Value = eval_fn.call((prepared_code, ctx_obj, sys_obj))?;

            if let Some(obj) = raw_val.as_object() {
                if let Ok(err_msg) = obj.get::<_, String>("__error") {
                    error = Some(err_msg);
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
                        "deny" | "block" | "reject" => {
                            decision = Some(HookDecision::Deny { reason });
                        }
                        "allow" | "pass" => {
                            decision = Some(HookDecision::Allow);
                        }
                        _ => {}
                    }
                }
            } else if let Some(b) = raw_val.as_bool() {
                if !b {
                    decision = Some(HookDecision::Deny {
                        reason: format!("Rule {} returned false", rule.id),
                    });
                }
            }

            Ok(())
        });

        if let Err(e) = res {
            if error.is_none() {
                error = Some(e.to_string());
            }
        }

        RuleExecutionResult {
            rule_id: rule.id.clone(),
            rule_path: rule.path.clone(),
            decision,
            duration: start.elapsed(),
            error,
        }
    }

    /// Evaluates a list of rules sequentially. Short-circuits on first Confirm or Deny.
    pub fn evaluate_all(
        &self,
        rules: &[RuleSource],
        ctx: &HookContext,
    ) -> (HookDecision, Vec<RuleExecutionResult>) {
        let mut results = Vec::new();

        for rule in rules {
            let res = self.execute_rule(rule, ctx);
            let hit = res.decision.clone();
            results.push(res);

            if let Some(dec) = hit {
                match dec {
                    HookDecision::Confirm { .. } | HookDecision::Deny { .. } => {
                        return (dec, results);
                    }
                    HookDecision::Allow => {}
                }
            }
        }

        (HookDecision::Allow, results)
    }
}
