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

    // 1. Quick prefix check first! If the command doesn't start with any safe prefix,
    // bail immediately in nanoseconds without running any further checks or allocations.
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

    let mut matched = false;
    let mut matched_prefix = "";
    for prefix in safe_prefixes {
        if trimmed == prefix {
            matched = true;
            matched_prefix = prefix;
            break;
        }
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            // `git status--foo` must not match `git status`; require a boundary.
            if rest.starts_with(|c: char| c.is_whitespace()) {
                matched = true;
                matched_prefix = prefix;
                break;
            }
        }
    }

    if !matched {
        return None;
    }

    // 2. Reject control characters and shell metacharacters that allow
    //    multiple statements, chaining or substitution.
    if trimmed.contains(&['\n', '\r', ';', '|', '&', '>', '<', '`'][..]) {
        return None;
    }
    // Command substitution `$(...)` / `${...}`:
    // `echo $(evil)` would otherwise ride on the "echo " prefix.
    if trimmed.contains("$(") || trimmed.contains("${") {
        return None;
    }

    // 3. Dangerous flags & token check with zero-allocation ASCII comparison.
    // Additional safety: git branch deletion (-d, -D) or git diff/log write (--output).
    if matched_prefix == "git branch" && (trimmed.contains(" -d") || trimmed.contains(" -D")) {
        return None;
    }
    if (matched_prefix == "git diff" || matched_prefix == "git log") && trimmed.contains("--output")
    {
        return None;
    }

    let dangerous_tokens = [
        "prod", "drop", "truncate", "delete", "remove", "migrate", "flush", "rm ", "restart",
        "stop", "kill", "token", "password", "secret", "shutdown", "reboot", "mkfs",
    ];

    // Zero-allocation case-insensitive ASCII substring search
    let bytes = trimmed.as_bytes();
    for token in dangerous_tokens {
        let t_bytes = token.as_bytes();
        if bytes.len() >= t_bytes.len()
            && bytes.windows(t_bytes.len()).any(|w| {
                w.iter()
                    .zip(t_bytes.iter())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
        {
            return None;
        }
    }

    Some(HookDecision::Allow)
}
