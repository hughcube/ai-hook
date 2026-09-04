use crate::protocol::{HookContext, HookDecision};

/// Extremely fast short-circuit check for common read-only commands.
/// If matched, returns Some(HookDecision::Allow) in < 0.01ms without loading the JS engine.
///
/// # Security model
/// Fast path is a security boundary: it must NEVER approve a command string that
/// could execute more than the single benign command the prefix claims. Therefore:
/// - Multi-statement / chaining syntax is rejected outright (newline, `;`, `|`,
///   `&`, `&&`, `||`, redirections, command substitution `$( )`, `${ }`,
///   backticks).
/// - After a safe prefix matches, the remainder must start with whitespace or be
///   empty (`git statusX` never matches `git status`) so prefixes cannot be
///   glued to attacker-controlled text.
/// - Anything not matched falls through to the JS rule engine.
pub fn check_fast_path(ctx: &HookContext) -> Option<HookDecision> {
    let cmd = ctx.cmd.as_deref()?;
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Reject control characters and shell metacharacters that allow
    //    multiple statements, chaining or substitution.
    if trimmed.contains(&['\n', '\r', ';', '|', '&', '>', '<', '`'][..]) {
        return None;
    }
    // Command substitution `$(...)` / `${...}`:
    // `echo $(evil)` would otherwise ride on the "echo " prefix.
    if trimmed.contains("$(") || trimmed.contains("${") {
        return None;
    }

    // 2. Dangerous token check (substring match is deliberately conservative:
    //    a false positive only skips the fast path, never blocks).
    let lower = trimmed.to_ascii_lowercase();
    let dangerous_tokens = [
        "prod", "drop", "truncate", "delete", "remove", "migrate", "flush", "rm ", "restart",
        "stop", "kill", "token", "password", "secret", "shutdown", "reboot", "mkfs",
    ];
    if dangerous_tokens.iter().any(|t| lower.contains(t)) {
        return None;
    }

    // 3. Safe read-only prefixes. A prefix matches only when followed by
    //    nothing (exact match) or by whitespace (regular arguments).
    //    Metacharacters were already rejected above, so anything after a
    //    matched prefix is a plain argument list of the benign command.
    let safe_prefixes = [
        "git status",
        "git diff",
        "git log",
        "git branch",
        "git show",
        "git remote",
        "git rev-parse",
        "ls",
        "pwd",
        "dir",
        "echo",
        "which",
        "where",
        "cat",
        "head",
        "tail",
    ];

    for prefix in safe_prefixes {
        if trimmed == prefix {
            return Some(HookDecision::Allow);
        }
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            // `git status--foo` must not match `git status`; require a boundary.
            if rest.starts_with(|c: char| c.is_whitespace()) {
                return Some(HookDecision::Allow);
            }
        }
    }

    None
}
