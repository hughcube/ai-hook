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

    // 3. Per-prefix write guards: a whitelisted prefix must only pass its
    //    read-only surface. Substring matching is deliberately over-broad
    //    (e.g. "-d" also rejects "--no-describe"): a false positive only
    //    costs one trip through the rule engine, a false negative silently
    //    bypasses the gate.
    match matched_prefix {
        // `git branch` writes: delete (-d/-D/--delete), rename (-m/-M/--move),
        // copy (-c/-C/--copy), force (-f/--force), upstream (-u/--set-upstream/
        // --unset-upstream/--track/--no-track), description (--edit).
        // Short flags are checked per cluster character (so "-vd", "-dmain"
        // and "-d" are all caught) while long flags are checked by prefix
        // ("--set-upstream=x" is caught, "--show-current" is not).
        "git branch" => {
            const BRANCH_WRITE_SHORTS: &[char] = &['d', 'D', 'm', 'M', 'c', 'C', 'u', 'f'];
            const BRANCH_WRITE_LONGS: &[&str] = &[
                "--delete",
                "--move",
                "--copy",
                "--edit",
                "--force",
                "--set-upstream",
                "--unset-upstream",
                "--track",
                "--no-track",
            ];
            let writes = trimmed.split_whitespace().any(|tok| {
                if tok.starts_with('-') && !tok.starts_with("--") {
                    tok[1..].chars().any(|c| BRANCH_WRITE_SHORTS.contains(&c))
                } else {
                    BRANCH_WRITE_LONGS.iter().any(|f| tok.starts_with(f))
                }
            });
            if writes {
                return None;
            }
        }
        // `git remote` writes config or touches the network: add / rename /
        // remove / set-url / set-head / prune / update. Only the read-only
        // surface passes (bare list, -v/--verbose, show, get-url). The
        // verbose flags are skipped as *tokens*, not prefixes: git's
        // parse_options consumes `-v` before dispatching on the subcommand,
        // so `git remote -v add evil <url>` is a real `add` — matching a
        // bare ` -v` prefix would let it through as "read-only".
        "git remote" => {
            let rest = &trimmed[matched_prefix.len()..];
            let mut tokens = rest
                .split_whitespace()
                .skip_while(|tok| *tok == "-v" || *tok == "--verbose");
            let read_only = match tokens.next() {
                None => true, // bare list (with or without -v/--verbose)
                Some(sub) => sub == "show" || sub == "get-url",
            };
            if !read_only {
                return None;
            }
        }
        // git diff/log/show all accept `--output=<file>` / `--output <file>`
        // and their short form `-o <file>` / `-o<file>`, which writes the
        // output to disk — that is a write, not a read. `--o…` long options
        // are excluded from the short-form check so `git log --oneline`
        // keeps its fast path.
        // `--output=<file>` / `-o <file>` 把输出写到磁盘;
        // `--ext-diff` / `--textconv` 更危险:它们让 git 去执行
        // `diff.<driver>.command` 或 `*.txt diff=foo` 配置的外部驱动 ——
        // 白名单宣称"只放行单条只读命令",而这两个开关会拉起任意可执行
        // 文件(config 里配什么就是什么),等于把旁路变成代码执行入口。
        "git diff" | "git log" | "git show" => {
            let writes = trimmed.contains("--output")
                || trimmed.contains("--ext-diff")
                || trimmed.contains("--textconv")
                || trimmed
                    .split_whitespace()
                    .any(|tok| tok.starts_with("-o") && !tok.starts_with("--"));
            if writes {
                return None;
            }
        }
        _ => {}
    }

    let dangerous_tokens = [
        "prod", "drop", "truncate", "delete", "remove", "migrate", "flush", "rm ", "restart",
        "stop", "kill", "token", "password", "secret", "shutdown", "reboot", "mkfs",
    ];

    // Credential / private-key targets.
    //
    // The whitelisted prefixes include `cat` / `head` / `tail` — the very
    // commands used to read secrets. Without these tokens a command like
    // `cat ~/.ssh/id_rsa` sails through the bypass and any "protect secret
    // reads" rule never runs. The match is a plain substring scan, so it is
    // deliberately over-broad (`_key` also matches a source file named
    // `path_keys.rs`): a false positive
    // only costs one trip through the rule engine, a false negative silently
    // bypasses the gate.
    let sensitive_tokens = [
        ".ssh",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "credentials",
        ".aws",
        ".netrc",
        ".kube",
        "git-credentials",
        ".env",
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".keystore",
        // Bulk secret channels: the process environment itself, classic
        // account databases, and API keys whose name carries no other token
        // (`echo $OPENAI_API_KEY` must not ride the `echo ` prefix).
        "environ",
        "passwd",
        "shadow",
        "api_key",
        "apikey",
        "_key",
        ".kdbx",
        "hosts.yml",
        ".npmrc",
        ".dockercfg",
        ".docker",
        "auth_token",
        "bearer",
        "private_key",
        "secret_key",
        "access_token",
    ];

    // Zero-allocation case-insensitive ASCII substring search
    let bytes = trimmed.as_bytes();
    for token in dangerous_tokens.iter().chain(sensitive_tokens.iter()) {
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
