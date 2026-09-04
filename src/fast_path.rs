use crate::protocol::{HookContext, HookDecision};

/// Extremely fast short-circuit check for common read-only commands.
/// If matched, returns Some(HookDecision::Allow) in < 0.01ms without loading the JS engine.
pub fn check_fast_path(ctx: &HookContext) -> Option<HookDecision> {
    if ctx.cmd.is_empty() {
        return None;
    }

    let trimmed = ctx.cmd.trim();

    // Dangerous characters: redirection or background execution
    if trimmed.contains('>') || trimmed.contains('&') || trimmed.contains(';') || trimmed.contains('|') {
        return None;
    }

    // Dangerous tokens check
    let lower = trimmed.to_ascii_lowercase();
    let dangerous_tokens = [
        "xrapp_prod", "prod", "drop", "truncate", "delete", "remove",
        "migrate", "flush", "rm", "restart", "stop", "kill", "token", "password"
    ];
    for token in dangerous_tokens {
        if lower.contains(token) {
            return None;
        }
    }

    // Safe read-only prefixes
    let safe_prefixes = [
        "git status",
        "git diff",
        "git log",
        "git branch",
        "git show",
        "git remote",
        "git rev-parse",
        "ls ",
        "ls",
        "pwd",
        "dir",
        "dir ",
        "echo ",
        "which ",
        "where ",
        "cat ",
        "head ",
        "tail ",
    ];

    for prefix in safe_prefixes {
        if trimmed == prefix.trim_end() || trimmed.starts_with(prefix) {
            return Some(HookDecision::Allow);
        }
    }

    None
}
