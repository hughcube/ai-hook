use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Classification of a command-line span.
///
/// Distinguishes parts of a command that are actually executed by the shell
/// from data arguments, inline scripts, or comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpanKind {
    /// Command word or executable token in execution position.
    Executed,
    /// Normal command argument.
    Argument,
    /// Inline code passed to an interpreter (e.g. bash -c "...", python -c "...").
    InlineCode,
    /// Pure data (e.g. single-quoted string, commit message, search pattern).
    Data,
    /// Shell comment (starting with #).
    Comment,
    /// Ambiguous / unclassified span.
    Unknown,
}

impl SpanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SpanKind::Executed => "executed",
            SpanKind::Argument => "argument",
            SpanKind::InlineCode => "inline_code",
            SpanKind::Data => "data",
            SpanKind::Comment => "comment",
            SpanKind::Unknown => "unknown",
        }
    }
}

/// A classified slice within the command line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub kind: SpanKind,
    pub start: usize,
    pub end: usize,
    pub text: String,
}

/// An inline script extracted from interpreter execution (e.g. python -c "...", bash -c "...").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnwrappedScript {
    pub interpreter: String,
    pub code: String,
}

/// Detailed breakdown of an individual command segment in a compound command, pipeline, or subshell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSegment {
    /// The original raw segment or subshell command text.
    pub raw: String,
    /// Backward-compatible alias of `raw`.
    pub command: String,
    /// Normalized segment text after stripping wrappers.
    pub normalized: String,
    /// Resolved executable name (lowercase basename).
    pub executable: String,
    /// First non-option subcommand for known CLI tools.
    pub subcommand: Option<String>,
    /// CLI flags extracted for this command segment.
    pub flags: Vec<String>,
    /// Positional arguments / non-flag operands for this segment.
    pub args: Vec<String>,
    /// Virtual working directory tracked at the moment of executing this segment.
    pub cwd: String,
    /// Resolved operand targets (combining virtual cwd with relative/wildcard operands).
    pub resolved_targets: Vec<String>,
    /// Inline code scripts extracted directly from this segment.
    pub unwrapped: Vec<UnwrappedScript>,
}

pub type ActionCommand = CommandSegment;

/// Rich semantic command and action context derived from command analysis.
///
/// Exposed to QuickJS hook rules as `ctx.command` (with `ctx.action` as a smooth transition alias).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandContext {
    /// The original raw command string.
    pub command: String,
    /// Normalized command line after stripping wrappers (sudo, env, \cmd, etc.).
    pub normalized: String,
    /// Primary resolved executable name (lowercase basename without path or .exe).
    pub executable: String,
    /// First non-option subcommand for known CLI tools (e.g. "push", "commit", "apply").
    pub subcommand: Option<String>,
    /// Wrappers that were stripped in order (e.g. ["sudo", "env", "backslash"]).
    pub stripped_wrappers: Vec<String>,
    /// Extracted environment variable assignments (e.g. {"PGPASSWORD": "secret"}).
    pub env_vars: HashMap<String, String>,
    /// Ultimate pipeline sink executable if present (e.g. "echo ... | psql" -> "psql").
    pub sink: Option<String>,
    /// Syntax-masked command line where safe data (commit msg, grep query, comments)
    /// is replaced with equal-length spaces to prevent false positives in regex checks.
    pub executable_text: String,
    /// True if command contains command substitution ($(...) or `...`) in execution context.
    pub has_dangerous_subst: bool,
    /// Extracted inline code scripts (e.g. bash -c, python -c, node -e, ssh host "...").
    pub unwrapped: Vec<UnwrappedScript>,
    /// Syntactic spans across the entire command line.
    pub spans: Vec<Span>,
    /// Aggregated CLI flags across all command segments (e.g. ["-f", "--force", "-m"]).
    pub flags: Vec<String>,
    /// All unique executable names called across compound commands, pipelines, and substitutions.
    pub executables: Vec<String>,
    /// Backward-compatible breakdown of sub-commands.
    pub commands: Vec<CommandSegment>,
    /// Segmented breakdown with virtual CWD tracking.
    pub segments: Vec<CommandSegment>,
    /// Initial working directory at evaluation start.
    pub cwd: String,
}

pub type ActionContext = CommandContext;

impl CommandContext {
    /// Check whether the command targets any of the specified programs.
    ///
    /// Checks primary `executable`, `sink`, all compound/nested `executables`,
    /// and all `unwrapped[].interpreter`.
    pub fn targets(&self, programs: &[&str]) -> bool {
        for prog in programs {
            let p = prog.to_ascii_lowercase();
            if self.executable == p {
                return true;
            }
            if let Some(ref s) = self.sink
                && s == &p
            {
                return true;
            }
            if self.executables.iter().any(|e| e == &p) {
                return true;
            }
            if self.unwrapped.iter().any(|u| u.interpreter == p) {
                return true;
            }
            if self.segments.iter().any(|c| c.executable == p) {
                return true;
            }
        }
        false
    }

    /// Check whether any of the specified flags are present across any command segment.
    pub fn has_flag(&self, flags: &[&str]) -> bool {
        for f in flags {
            if self
                .flags
                .iter()
                .any(|fl| fl == f || fl.starts_with(&format!("{f}=")))
            {
                return true;
            }
            for cmd in &self.segments {
                if cmd
                    .flags
                    .iter()
                    .any(|fl| fl == f || fl.starts_with(&format!("{f}=")))
                {
                    return true;
                }
            }
        }
        false
    }

    /// Find all segments matching the given program name (by executable or unwrapped interpreter).
    pub fn find(&self, prog: &str) -> Vec<&CommandSegment> {
        let p = prog.to_ascii_lowercase();
        self.segments
            .iter()
            .filter(|seg| {
                seg.executable == p
                    || seg
                        .unwrapped
                        .iter()
                        .any(|u| u.interpreter.eq_ignore_ascii_case(&p))
            })
            .collect()
    }

    /// Returns true if the command is composed entirely of harmless search or read-only queries.
    pub fn is_search(&self) -> bool {
        const READ_ONLY_TOOLS: &[&str] = &[
            "grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "fd", "cat", "head", "tail",
            "less", "more", "which", "where", "whereis", "type", "file", "wc", "diff", "sdiff",
            "cmp",
        ];
        const DB_CLIENTS: &[&str] = &[
            "mysql",
            "mariadb",
            "psql",
            "sqlite3",
            "clickhouse",
            "clickhouse-client",
        ];

        if self.executables.is_empty() {
            return false;
        }

        for cmd in &self.segments {
            let exec = cmd.executable.as_str();
            if READ_ONLY_TOOLS.contains(&exec) {
                continue;
            }
            if exec == "git"
                && let Some(ref sub) = cmd.subcommand
                && matches!(
                    sub.as_str(),
                    "status" | "log" | "diff" | "show" | "describe"
                )
            {
                continue;
            }
            if exec == "docker"
                && let Some(ref sub) = cmd.subcommand
                && matches!(sub.as_str(), "ps" | "images" | "logs" | "inspect")
            {
                continue;
            }
            if matches!(exec, "echo" | "printf") && self.segments.len() > 1 {
                continue;
            }

            // Database read-only verification
            if DB_CLIENTS.contains(&exec)
                && !cmd.unwrapped.is_empty()
                && cmd.unwrapped.iter().all(|u| is_sql_read_only(&u.code))
            {
                continue;
            }

            return false;
        }
        true
    }

    /// Returns true if the command is `git commit`.
    pub fn is_git_commit(&self) -> bool {
        self.executable == "git" && self.subcommand.as_deref() == Some("commit")
            || self
                .segments
                .iter()
                .any(|c| c.executable == "git" && c.subcommand.as_deref() == Some("commit"))
    }
}

/// Helper to trim matching single or double quotes from a string slice.
pub fn clean_quotes(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
        || (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolve virtual CWD transition when `cd` or `pushd` is executed.
pub fn resolve_cd_path(current_cwd: &str, target: &str) -> String {
    let t = clean_quotes(target);
    let t = t.trim();
    if t.is_empty() || t == "~" || t == "$HOME" || t == "%USERPROFILE%" {
        return "~".to_string();
    }

    // Windows drive absolute (e.g. C:\..., D:/...)
    if (t.len() >= 2 && t.as_bytes()[1] == b':' && t.as_bytes()[0].is_ascii_alphabetic())
        || t.starts_with("\\\\")
    {
        return t.replace('\\', "/");
    }

    // Unix root absolute
    if t.starts_with('/') {
        return t.to_string();
    }

    // Home-relative (e.g. ~/foo, ~/.tml)
    if t.starts_with("~/") || t.starts_with("~\\") {
        return format!("~/{}", t[2..].replace('\\', "/").trim_start_matches('/'));
    }

    // Relative directory navigation
    let base = if current_cwd.is_empty() {
        "."
    } else {
        current_cwd
    };
    let norm_base = base.replace('\\', "/");
    let norm_target = t.replace('\\', "/");

    let mut parts: Vec<&str> = norm_base
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let is_root = norm_base.starts_with('/') && !norm_base.starts_with("~/");
    let is_win_drive = norm_base.len() >= 2
        && norm_base.as_bytes()[1] == b':'
        && norm_base.as_bytes()[0].is_ascii_alphabetic();
    let drive_prefix = if is_win_drive {
        let (d, _) = norm_base.split_at(2);
        Some(d)
    } else {
        None
    };

    for comp in norm_target.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            if !parts.is_empty() {
                if is_win_drive && parts.len() == 1 {
                    // stay at drive
                } else if parts.len() == 1 && parts[0] == "~" {
                    // stay at ~
                } else {
                    parts.pop();
                }
            }
        } else {
            parts.push(comp);
        }
    }

    if is_root {
        format!("/{}", parts.join("/"))
    } else if let Some(dp) = drive_prefix {
        if parts.is_empty() || (parts.len() == 1 && parts[0] == dp) {
            format!("{dp}/")
        } else if parts[0] == dp {
            parts.join("/")
        } else {
            format!("{dp}/{}", parts.join("/"))
        }
    } else {
        parts.join("/")
    }
}

/// Resolve operand target by combining virtual CWD with relative/wildcard operands.
pub fn resolve_operand_target(cwd: &str, operand: &str) -> String {
    let op = clean_quotes(operand);
    let op = op.trim();
    if op.is_empty() {
        return String::new();
    }
    // Absolute paths
    if op.starts_with('/')
        || (op.len() >= 2 && op.as_bytes()[1] == b':' && op.as_bytes()[0].is_ascii_alphabetic())
        || op.starts_with("\\\\")
    {
        return op.replace('\\', "/");
    }

    let norm_cwd = cwd.replace('\\', "/");
    if norm_cwd.is_empty() || norm_cwd == "." {
        return op.replace('\\', "/");
    }

    let clean_op = op.replace('\\', "/");
    let trimmed_op = clean_op.trim_start_matches("./");

    if norm_cwd == "/" {
        format!("/{}", trimmed_op.trim_start_matches('/'))
    } else if norm_cwd.ends_with('/') {
        format!("{}{}", norm_cwd, trimmed_op.trim_start_matches('/'))
    } else {
        format!("{}/{}", norm_cwd, trimmed_op.trim_start_matches('/'))
    }
}

/// Split SQL text into statements by semicolon, skipping comments and quoted string literals.
pub fn split_sql_statements(sql: &str) -> Vec<String> {
    let mut stmts = Vec::new();
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;

    while i < bytes.len() {
        let b = bytes[i];

        // Line comments: -- or #
        if !in_single && !in_double && !in_backtick {
            if (b == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-') || b == b'#' {
                while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                    i += 1;
                }
                continue;
            }
            // Block comment: /* ... */
            if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
        }

        // Escape handling
        if b == b'\\' && (in_single || in_double) {
            i += 2;
            continue;
        }
        if b == b'\'' && !in_double && !in_backtick {
            if in_single && i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                i += 2;
                continue;
            }
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single && !in_backtick {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if b == b'`' && !in_single && !in_double {
            in_backtick = !in_backtick;
            i += 1;
            continue;
        }

        if !in_single && !in_double && !in_backtick && b == b';' {
            let stmt = sql[start..i].trim();
            if !stmt.is_empty() {
                stmts.push(stmt.to_string());
            }
            start = i + 1;
        }
        i += 1;
    }

    let last = sql[start..].trim();
    if !last.is_empty() {
        stmts.push(last.to_string());
    }
    stmts
}

/// Check if a single SQL statement is strictly read-only.
pub fn is_single_sql_read_only(stmt: &str) -> bool {
    let mut cleaned = stmt.trim();
    loop {
        if cleaned.starts_with("--") {
            if let Some(pos) = cleaned.find('\n') {
                cleaned = cleaned[pos + 1..].trim();
                continue;
            } else {
                return false;
            }
        }
        if cleaned.starts_with('#') {
            if let Some(pos) = cleaned.find('\n') {
                cleaned = cleaned[pos + 1..].trim();
                continue;
            } else {
                return false;
            }
        }
        if cleaned.starts_with("/*") {
            if let Some(pos) = cleaned.find("*/") {
                cleaned = cleaned[pos + 2..].trim();
                continue;
            } else {
                return false;
            }
        }
        break;
    }

    if cleaned.is_empty() {
        return false;
    }

    let first_token = cleaned
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();

    const READ_ONLY_SQL_KEYWORDS: &[&str] =
        &["SELECT", "SHOW", "EXPLAIN", "DESCRIBE", "DESC", "WITH"];

    if !READ_ONLY_SQL_KEYWORDS.contains(&first_token.as_str()) {
        return false;
    }

    let upper = cleaned.to_ascii_uppercase();
    if upper.contains("INTO OUTFILE") || upper.contains("INTO DUMPFILE") {
        return false;
    }

    true
}

/// Check if an entire SQL payload is strictly read-only.
/// Fail-closed: any non-read-only statement or empty payload returns false.
pub fn is_sql_read_only(sql: &str) -> bool {
    let stmts = split_sql_statements(sql);
    if stmts.is_empty() {
        return false;
    }
    for stmt in &stmts {
        if !is_single_sql_read_only(stmt) {
            return false;
        }
    }
    true
}

/// Extract CLI flags and non-flag positional arguments from a token stream.
/// Automatically skips the executable token (first word) and the first matching subcommand.
pub fn extract_flags_and_args(
    words: &[String],
    subcommand: Option<&str>,
) -> (Vec<String>, Vec<String>) {
    const VALUE_FLAGS_SHORT: &[&str] = &[
        "-u", "-h", "-p", "-P", "-c", "-e", "-m", "-d", "-o", "-f", "-i", "-s", "-t", "-b", "-F",
        "-q", "-D", "-S", "-L", "-v",
    ];
    const VALUE_FLAGS_LONG: &[&str] = &[
        "--user",
        "--host",
        "--port",
        "--password",
        "--file",
        "--config",
        "--database",
        "--command",
        "--execute",
        "--query",
        "--message",
        "--data",
        "--target",
        "--output",
        "--path",
        "--dir",
        "--source",
        "--dest",
        "--init-command",
    ];

    let mut flags = Vec::new();
    let mut args = Vec::new();
    let mut i = if words.is_empty() { 0 } else { 1 };
    let mut options_ended = false;
    let mut skipped_subcommand = false;

    while i < words.len() {
        let w = &words[i];
        if !options_ended && w == "--" {
            options_ended = true;
            i += 1;
            continue;
        }

        if options_ended || !w.starts_with('-') || w == "-" {
            let clean = clean_quotes(w);
            if !skipped_subcommand
                && let Some(sub) = subcommand
                && clean.eq_ignore_ascii_case(sub)
            {
                skipped_subcommand = true;
                i += 1;
                continue;
            }
            args.push(clean);
            i += 1;
            continue;
        }

        let clean_f = clean_quotes(w);
        if !flags.contains(&clean_f) {
            flags.push(clean_f.clone());
        }

        let is_value_option = if clean_f.contains('=') {
            false
        } else {
            VALUE_FLAGS_SHORT.contains(&clean_f.as_str())
                || VALUE_FLAGS_LONG.contains(&clean_f.as_str())
        };

        if is_value_option && i + 1 < words.len() && !words[i + 1].starts_with('-') {
            i += 1;
        }

        i += 1;
    }

    (flags, args)
}

/// Extract inline code or query payload from a command segment.
pub fn extract_code_slot(
    executable: &str,
    _raw_segment: &str,
    words: &[String],
) -> Option<UnwrappedScript> {
    let exec = executable.to_ascii_lowercase();

    // 1. Database clients
    if matches!(exec.as_str(), "mysql" | "mariadb") {
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if matches!(w.as_str(), "-e" | "--execute" | "--init-command") {
                if let Some(code) = words.get(i + 1) {
                    return Some(UnwrappedScript {
                        interpreter: exec,
                        code: clean_quotes(code),
                    });
                }
            } else if w.starts_with("-e") && w.len() > 2 {
                let code = &w[2..];
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            } else if let Some(code) = w.strip_prefix("--execute=") {
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            } else if let Some(code) = w.strip_prefix("--init-command=") {
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            }
            i += 1;
        }
    } else if exec == "psql" {
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if matches!(w.as_str(), "-c" | "--command") {
                if let Some(code) = words.get(i + 1) {
                    return Some(UnwrappedScript {
                        interpreter: exec,
                        code: clean_quotes(code),
                    });
                }
            } else if w.starts_with("-c") && w.len() > 2 {
                let code = &w[2..];
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            } else if let Some(code) = w.strip_prefix("--command=") {
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            }
            i += 1;
        }
    } else if exec == "sqlite3" {
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if w == "-cmd" {
                if let Some(code) = words.get(i + 1) {
                    return Some(UnwrappedScript {
                        interpreter: exec,
                        code: clean_quotes(code),
                    });
                }
            } else if let Some(code) = w.strip_prefix("-cmd=") {
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            }
            i += 1;
        }
        let non_flags: Vec<&String> = words
            .iter()
            .skip(1)
            .filter(|w| !w.starts_with('-'))
            .collect();
        if non_flags.len() >= 2 {
            let cand = clean_quotes(non_flags[1]);
            let first_kw = cand
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            if matches!(
                first_kw.as_str(),
                "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "CREATE" | "DROP" | "ALTER" | "PRAGMA"
            ) {
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: cand,
                });
            }
        }
    } else if matches!(exec.as_str(), "clickhouse" | "clickhouse-client") {
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if matches!(w.as_str(), "-q" | "--query") {
                if let Some(code) = words.get(i + 1) {
                    return Some(UnwrappedScript {
                        interpreter: "clickhouse".to_string(),
                        code: clean_quotes(code),
                    });
                }
            } else if let Some(code) = w.strip_prefix("--query=") {
                return Some(UnwrappedScript {
                    interpreter: "clickhouse".to_string(),
                    code: clean_quotes(code),
                });
            }
            i += 1;
        }
    } else if matches!(exec.as_str(), "redis-cli" | "valkey-cli" | "keydb-cli") {
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if w == "--eval"
                && let Some(code) = words.get(i + 1)
            {
                return Some(UnwrappedScript {
                    interpreter: "redis-cli".to_string(),
                    code: clean_quotes(code),
                });
            }
            i += 1;
        }
        const REDIS_COMMANDS: &[&str] = &[
            "KEYS", "FLUSHALL", "FLUSHDB", "DEL", "GET", "SET", "HGET", "HSET", "INFO", "CONFIG",
            "CLUSTER", "DBSIZE", "EXPIRE", "TTL", "SCAN",
        ];
        let mut i = 1;
        while i < words.len() {
            let w = &words[i];
            if w.starts_with('-') {
                if matches!(w.as_str(), "-h" | "-p" | "-a" | "-u" | "-s" | "-n")
                    && i + 1 < words.len()
                {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            let upper = w.to_ascii_uppercase();
            if REDIS_COMMANDS.contains(&upper.as_str()) {
                let redis_line = words[i..].join(" ");
                return Some(UnwrappedScript {
                    interpreter: "redis-cli".to_string(),
                    code: redis_line,
                });
            }
            break;
        }
    }

    // 2. Interpreter execution (e.g. bash -c, python -c, node -e)
    if let Some((_, flags)) = INTERPRETERS.iter().find(|(interp, _)| *interp == exec) {
        let mut i = 0;
        while i < words.len() {
            let w = &words[i];
            if flags.iter().any(|f| w == f)
                && let Some(code) = words.get(i + 1)
            {
                return Some(UnwrappedScript {
                    interpreter: exec,
                    code: clean_quotes(code),
                });
            }
            i += 1;
        }
    }

    None
}

/// If previous segment produces stdout data (e.g. echo, printf) and current segment
/// is a consumer that reads stdin as code (mysql, psql, etc.), extract and inject code payload.
pub fn extract_pipeline_producer_payload(
    prev_seg_raw: &str,
    consumer_exec: &str,
) -> Option<UnwrappedScript> {
    const CODE_CONSUMERS: &[&str] = &[
        "mysql",
        "mariadb",
        "psql",
        "sqlite3",
        "clickhouse",
        "clickhouse-client",
        "redis-cli",
        "bash",
        "sh",
        "zsh",
        "python",
        "python3",
        "node",
    ];

    if !CODE_CONSUMERS.contains(&consumer_exec) {
        return None;
    }

    let prev_clean = strip_redirections(prev_seg_raw);
    let (prev_norm, _, _) = strip_wrappers(&prev_clean);
    let (prev_exec, _) = extract_executable_and_subcommand(&prev_norm);

    if matches!(prev_exec.as_str(), "echo" | "printf") {
        let words = split_args(&prev_norm);
        if words.len() > 1 {
            let data = words.iter().skip(1).cloned().collect::<Vec<_>>().join(" ");
            let code = clean_quotes(&data);
            if !code.is_empty() {
                return Some(UnwrappedScript {
                    interpreter: consumer_exec.to_string(),
                    code,
                });
            }
        }
    }
    None
}

/// Known interpreters that accept inline code flags.
const INTERPRETERS: &[(&str, &[&str])] = &[
    ("bash", &["-c"]),
    ("sh", &["-c"]),
    ("zsh", &["-c"]),
    ("ksh", &["-c"]),
    ("dash", &["-c"]),
    ("python", &["-c"]),
    ("python3", &["-c"]),
    ("python2", &["-c"]),
    ("node", &["-e", "--eval"]),
    ("nodejs", &["-e", "--eval"]),
    ("bun", &["-e", "--eval"]),
    ("deno", &["eval", "-e"]),
    ("ruby", &["-e"]),
    ("perl", &["-e"]),
    ("php", &["-r"]),
    ("powershell", &["-c", "-command"]),
    ("pwsh", &["-c", "-command"]),
    ("cmd", &["/c", "/k"]),
    ("cmd.exe", &["/c", "/k"]),
];

/// Known CLI tools with subcommands.
const CLI_WITH_SUBCOMMANDS: &[&str] = &[
    "git",
    "docker",
    "kubectl",
    "npm",
    "pnpm",
    "yarn",
    "cargo",
    "gh",
    "aws",
    "gcloud",
    "pip",
    "dotnet",
    "go",
    "systemctl",
    "service",
    "svn",
    "hg",
    "apt",
    "yum",
    "brew",
];

/// Flags whose following argument is typically pure data (to be masked).
const DATA_ARG_FLAGS: &[&str] = &[
    "-m",
    "--message",
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "-query",
    "--query",
    "-pattern",
    "--pattern",
    "-p",
    "--password",
];

/// Strip wrappers and extract normalized command.
pub fn strip_wrappers(command: &str) -> (String, Vec<String>, HashMap<String, String>) {
    let mut current = command.trim().to_string();
    let mut stripped_wrappers = Vec::new();
    let mut env_vars = HashMap::new();

    const MAX_ITERATIONS: usize = 32;
    for _ in 0..MAX_ITERATIONS {
        let trimmed = current.trim_start();
        if trimmed.is_empty() {
            break;
        }

        // 1. Strip environment variable assignment (e.g. VAR=val, FOO="bar baz")
        if let Some((rest, key, val)) = try_strip_env_assign(trimmed) {
            stripped_wrappers.push("env_assign".to_string());
            env_vars.insert(key, val);
            current = rest;
            continue;
        }

        // 2. Strip leading backslash (\git, \rm)
        if trimmed.starts_with('\\') && trimmed.len() > 1 {
            let next_ch = trimmed.as_bytes()[1];
            if next_ch.is_ascii_alphabetic() {
                stripped_wrappers.push("backslash".to_string());
                current = trimmed[1..].to_string();
                continue;
            }
        }

        // 3. Strip sudo
        if let Some(rest) = try_strip_sudo(trimmed) {
            stripped_wrappers.push("sudo".to_string());
            current = rest;
            continue;
        }

        // 4. Strip env command
        if let Some((rest, extra_vars)) = try_strip_env_command(trimmed) {
            stripped_wrappers.push("env".to_string());
            if !extra_vars.is_empty() {
                stripped_wrappers.push("env_assign".to_string());
            }
            env_vars.extend(extra_vars);
            current = rest;
            continue;
        }

        // 5. Strip command wrapper (command [-p] [--])
        if let Some(rest) = try_strip_command_wrapper(trimmed) {
            stripped_wrappers.push("command".to_string());
            current = rest;
            continue;
        }

        // 6. Strip nohup, nice, setsid
        if let Some(rest) = try_strip_execution_wrapper(trimmed, &mut stripped_wrappers) {
            current = rest;
            continue;
        }

        break;
    }

    (current, stripped_wrappers, env_vars)
}

fn try_strip_env_assign(s: &str) -> Option<(String, String, String)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || (!bytes[0].is_ascii_alphabetic() && bytes[0] != b'_') {
        return None;
    }

    let mut eq_pos = None;
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'=' {
            eq_pos = Some(i);
            break;
        }
        if !b.is_ascii_alphanumeric() && b != b'_' {
            break;
        }
        i += 1;
    }

    let eq_idx = eq_pos?;
    let key = s[..eq_idx].to_string();
    let after_eq = &s[eq_idx + 1..];

    // Extract value
    let (val_str, rest_idx) = if let Some(stripped) = after_eq.strip_prefix('"') {
        // Find closing double quote (ignoring escaped quotes)
        let mut end = 0;
        let mut escaped = false;
        let ab = stripped.as_bytes();
        while end < ab.len() {
            if escaped {
                escaped = false;
            } else if ab[end] == b'\\' {
                escaped = true;
            } else if ab[end] == b'"' {
                break;
            }
            end += 1;
        }
        let v = &stripped[..end];
        (
            v.to_string(),
            eq_idx + 1 + 1 + end + usize::from(end < ab.len()),
        )
    } else if let Some(stripped) = after_eq.strip_prefix('\'') {
        let end = stripped.find('\'').unwrap_or(stripped.len());
        let v = &stripped[..end];
        (
            v.to_string(),
            eq_idx + 1 + 1 + end + usize::from(end < stripped.len()),
        )
    } else {
        let end = after_eq.find(char::is_whitespace).unwrap_or(after_eq.len());
        (after_eq[..end].to_string(), eq_idx + 1 + end)
    };

    let remaining = if rest_idx < s.len() {
        s[rest_idx..].trim_start().to_string()
    } else {
        String::new()
    };

    Some((remaining, key, val_str))
}

fn try_strip_sudo(s: &str) -> Option<String> {
    let first_word_end = s.find(char::is_whitespace).unwrap_or(s.len());
    let first_word = &s[..first_word_end];
    let basename = first_word.rsplit(['/', '\\']).next().unwrap_or(first_word);
    if basename != "sudo" {
        return None;
    }

    let rest = s[first_word.len()..].trim_start();
    if rest.is_empty() {
        return None;
    }

    let words: Vec<&str> = rest.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if w == "--" {
            i += 1;
            break;
        }
        if w.starts_with('-') {
            // Options that take an argument
            if matches!(
                w,
                "-u" | "-g" | "-h" | "-p" | "-C" | "-r" | "-U" | "-D" | "-t" | "-a" | "-T"
            ) {
                i += 2; // skip flag and argument
                continue;
            }
            i += 1;
            continue;
        }
        break;
    }

    if i < words.len() {
        // Locate where words[i] begins in rest
        let target = words[i];
        if let Some(pos) = rest.find(target) {
            return Some(rest[pos..].to_string());
        }
    }
    None
}

fn try_strip_env_command(s: &str) -> Option<(String, HashMap<String, String>)> {
    let first_word_end = s.find(char::is_whitespace).unwrap_or(s.len());
    let first_word = &s[..first_word_end];
    let basename = first_word.rsplit(['/', '\\']).next().unwrap_or(first_word);
    if basename != "env" {
        return None;
    }

    let rest = s[first_word.len()..].trim_start();
    if rest.is_empty() {
        return None;
    }

    let mut current = rest.to_string();
    let mut extra_vars = HashMap::new();

    loop {
        let t = current.trim_start().to_string();
        if t.is_empty() {
            return None;
        }
        if let Some(next) = t.strip_prefix("--") {
            return Some((next.trim_start().to_string(), extra_vars));
        }
        if t.starts_with('-') {
            let end = t.find(char::is_whitespace).unwrap_or(t.len());
            let flag = &t[..end];
            if matches!(flag, "-u" | "-C" | "-f" | "-a") {
                let after_flag = t[end..].trim_start();
                let arg_end = after_flag
                    .find(char::is_whitespace)
                    .unwrap_or(after_flag.len());
                current = after_flag[arg_end..].trim_start().to_string();
            } else if flag == "-S" || flag == "--split-string" {
                let after_flag = t[end..].trim_start();
                return Some((after_flag.to_string(), extra_vars));
            } else {
                current = t[end..].trim_start().to_string();
            }
            continue;
        }
        if let Some((remaining, k, v)) = try_strip_env_assign(&t) {
            extra_vars.insert(k, v);
            current = remaining;
            continue;
        }
        break;
    }

    if !current.trim().is_empty() {
        Some((current, extra_vars))
    } else {
        None
    }
}

fn try_strip_command_wrapper(s: &str) -> Option<String> {
    let first_word_end = s.find(char::is_whitespace).unwrap_or(s.len());
    let first_word = &s[..first_word_end];
    let basename = first_word.rsplit(['/', '\\']).next().unwrap_or(first_word);
    if basename != "command" {
        return None;
    }

    let rest = s[first_word.len()..].trim_start();
    let words = rest.split_whitespace();
    let mut current = rest;

    for w in words {
        if w == "-v" || w == "-V" {
            // Query mode, not wrapper execution
            return None;
        }
        if w == "-p" || w == "--" {
            let pos = current.find(w).unwrap_or(0) + w.len();
            current = current[pos..].trim_start();
            continue;
        }
        break;
    }

    if !current.is_empty() {
        Some(current.to_string())
    } else {
        None
    }
}

fn try_strip_execution_wrapper(s: &str, stripped: &mut Vec<String>) -> Option<String> {
    let first_word_end = s.find(char::is_whitespace).unwrap_or(s.len());
    let first_word = &s[..first_word_end];
    let basename = first_word.rsplit(['/', '\\']).next().unwrap_or(first_word);

    if matches!(basename, "nohup" | "setsid") {
        stripped.push(basename.to_string());
        let rest = s[first_word.len()..].trim_start();
        return Some(rest.to_string());
    }

    if basename == "nice" {
        stripped.push("nice".to_string());
        let rest = s[first_word.len()..].trim_start();
        let words: Vec<&str> = rest.split_whitespace().collect();
        let mut i = 0;
        if i < words.len() && (words[i] == "-n" || words[i].starts_with('-')) {
            i += if words[i] == "-n" { 2 } else { 1 };
        }
        if i < words.len()
            && let Some(pos) = rest.find(words[i])
        {
            return Some(rest[pos..].to_string());
        }
        return Some(rest.to_string());
    }

    None
}

/// Extract base executable and subcommand.
pub fn extract_executable_and_subcommand(normalized: &str) -> (String, Option<String>) {
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return (String::new(), None);
    }

    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.is_empty() {
        return (String::new(), None);
    }

    let raw_exec = words[0].trim_matches(|c| c == '\'' || c == '"');
    let basename = raw_exec.rsplit(['/', '\\']).next().unwrap_or(raw_exec);
    let exec_lower = basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".cmd"))
        .or_else(|| basename.strip_suffix(".bat"))
        .or_else(|| basename.strip_suffix(".sh"))
        .unwrap_or(basename)
        .to_ascii_lowercase();

    let mut subcommand = None;
    if CLI_WITH_SUBCOMMANDS.contains(&exec_lower.as_str()) {
        let mut i = 1;
        while i < words.len() {
            let w = words[i];
            if w.starts_with('-') {
                // Git -C /path, docker --context ctx, etc.
                if (w == "-C" || w == "-c" || w == "--git-dir" || w == "--work-tree")
                    && !w.contains('=')
                    && i + 1 < words.len()
                {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            subcommand = Some(w.to_ascii_lowercase());
            break;
        }
    }

    (exec_lower, subcommand)
}

/// Extract the sink executable from a piped command.
pub fn extract_sink(command: &str) -> Option<String> {
    let segments = split_pipes(command);
    if segments.len() <= 1 {
        return None;
    }

    let last = segments.last()?;
    // Strip trailing redirections (> file, 2>&1)
    let clean = strip_redirections(last);
    let (norm, _, _) = strip_wrappers(&clean);
    let (exec, _) = extract_executable_and_subcommand(&norm);
    if exec.is_empty() { None } else { Some(exec) }
}

fn split_pipes(command: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let bytes = command.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escaped = true;
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if !in_single && !in_double && b == b'|' {
            // Check for ||
            if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                i += 2;
                continue;
            }
            segments.push(command[start..i].trim());
            start = i + 1;
        }
        i += 1;
    }
    if start < command.len() {
        segments.push(command[start..].trim());
    }
    segments
}

fn strip_redirections(s: &str) -> String {
    let mut out = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let bytes = s.as_bytes();

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            out.push(b as char);
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escaped = true;
            out.push('\\');
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            out.push('\'');
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            out.push('"');
            i += 1;
            continue;
        }
        if !in_single
            && !in_double
            && (b == b'>'
                || b == b'<'
                || (b == b'2' && i + 1 < bytes.len() && bytes[i + 1] == b'>'))
        {
            // Skip redirection operator and target token
            if b == b'2' {
                i += 1;
            }
            while i < bytes.len()
                && (bytes[i] == b'>'
                    || bytes[i] == b'<'
                    || bytes[i] == b'&'
                    || bytes[i].is_ascii_whitespace())
            {
                i += 1;
            }
            // Skip target word
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// Split a command into compound segments separated by &&, ||, ;, |, or newlines,
/// respecting single/double quotes, command substitutions $(...), and backticks.
pub fn split_compound_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let bytes = command.as_bytes();
    let mut start = 0;
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escaped = true;
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        if !in_single && !in_double {
            // Skip $( ... )
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                i += 2;
                let mut depth = 1;
                let mut sub_single = false;
                let mut sub_double = false;
                let mut sub_escaped = false;
                while i < bytes.len() && depth > 0 {
                    let sb = bytes[i];
                    if sub_escaped {
                        sub_escaped = false;
                        i += 1;
                        continue;
                    }
                    if sb == b'\\' && !sub_single {
                        sub_escaped = true;
                        i += 1;
                        continue;
                    }
                    if sb == b'\'' && !sub_double {
                        sub_single = !sub_single;
                        i += 1;
                        continue;
                    }
                    if sb == b'"' && !sub_single {
                        sub_double = !sub_double;
                        i += 1;
                        continue;
                    }
                    if !sub_single && !sub_double {
                        if sb == b'(' {
                            depth += 1;
                        } else if sb == b')' {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }

            // Skip `...`
            if b == b'`' {
                i += 1;
                let mut b_esc = false;
                while i < bytes.len() {
                    let sb = bytes[i];
                    if b_esc {
                        b_esc = false;
                        i += 1;
                        continue;
                    }
                    if sb == b'\\' {
                        b_esc = true;
                        i += 1;
                        continue;
                    }
                    if sb == b'`' {
                        break;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }

            // Separators: &&, ||, ;, |, \n, \r
            if (b == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'&')
                || (b == b'|' && i + 1 < bytes.len() && bytes[i + 1] == b'|')
            {
                let seg = command[start..i].trim();
                if !seg.is_empty() {
                    segments.push(seg.to_string());
                }
                i += 2;
                start = i;
                continue;
            }

            if b == b';' || b == b'|' || b == b'\n' || b == b'\r' || b == b'&' {
                let seg = command[start..i].trim();
                if !seg.is_empty() {
                    segments.push(seg.to_string());
                }
                i += 1;
                start = i;
                continue;
            }
        }

        i += 1;
    }

    let final_seg = command[start..].trim();
    if !final_seg.is_empty() {
        segments.push(final_seg.to_string());
    }

    segments
}

/// Extract inner contents of command substitutions $(...) and `...`
pub fn extract_substitutions(command: &str) -> Vec<String> {
    let mut results = Vec::new();
    let bytes = command.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escaped = true;
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }

        if !in_single {
            // $(...)
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                let is_arith = i + 2 < bytes.len() && bytes[i + 2] == b'(';
                if !is_arith {
                    let start = i + 2;
                    let mut depth = 1;
                    let mut j = start;
                    let mut sub_single = false;
                    let mut sub_double = false;
                    let mut sub_escaped = false;

                    while j < bytes.len() && depth > 0 {
                        let sj = bytes[j];
                        if sub_escaped {
                            sub_escaped = false;
                            j += 1;
                            continue;
                        }
                        if sj == b'\\' && !sub_single {
                            sub_escaped = true;
                            j += 1;
                            continue;
                        }
                        if sj == b'\'' && !sub_double {
                            sub_single = !sub_single;
                            j += 1;
                            continue;
                        }
                        if sj == b'"' && !sub_single {
                            sub_double = !sub_double;
                            j += 1;
                            continue;
                        }
                        if !sub_single && !sub_double {
                            if sj == b'(' {
                                depth += 1;
                            } else if sj == b')' {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                            }
                        }
                        j += 1;
                    }

                    if depth == 0 {
                        let sub_content = &command[start..j];
                        results.push(sub_content.to_string());
                        results.extend(extract_substitutions(sub_content));
                        i = j + 1;
                        continue;
                    }
                }
            }

            // `...`
            if b == b'`' {
                let start = i + 1;
                let mut j = start;
                let mut b_esc = false;
                while j < bytes.len() {
                    let sj = bytes[j];
                    if b_esc {
                        b_esc = false;
                        j += 1;
                        continue;
                    }
                    if sj == b'\\' {
                        b_esc = true;
                        j += 1;
                        continue;
                    }
                    if sj == b'`' {
                        break;
                    }
                    j += 1;
                }
                if j < bytes.len() {
                    let sub_content = &command[start..j];
                    results.push(sub_content.to_string());
                    results.extend(extract_substitutions(sub_content));
                    i = j + 1;
                    continue;
                }
            }
        }

        i += 1;
    }

    results
}

/// Split command string into arguments/words respecting quotes.
pub fn split_args(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    let mut cur = String::new();

    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            escaped = false;
            cur.push(b as char);
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escaped = true;
            cur.push('\\');
            i += 1;
            continue;
        }
        if b == b'\'' && !in_double {
            in_single = !in_single;
            cur.push('\'');
            i += 1;
            continue;
        }
        if b == b'"' && !in_single {
            in_double = !in_double;
            cur.push('"');
            i += 1;
            continue;
        }
        if !in_single && !in_double && b.is_ascii_whitespace() {
            if !cur.is_empty() {
                args.push(cur);
                cur = String::new();
            }
            i += 1;
            continue;
        }
        cur.push(b as char);
        i += 1;
    }
    if !cur.is_empty() {
        args.push(cur);
    }
    args
}

/// Extract CLI flags from a normalized command segment.
pub fn extract_flags_from_str(s: &str) -> Vec<String> {
    let words = split_args(s);
    let mut flags = Vec::new();
    for w in words {
        if w.starts_with('-') && w.len() > 1 {
            let clean = w.trim_matches(|c| c == '\'' || c == '"');
            if clean.starts_with('-') && !flags.iter().any(|f| f == clean) {
                flags.push(clean.to_string());
            }
        }
    }
    flags
}

/// Extract remote execution script (ssh, sftp) or container exec (docker exec, kubectl exec).
pub fn extract_remote_or_container_command(
    executable: &str,
    raw_segment: &str,
) -> Option<UnwrappedScript> {
    if executable == "ssh" || executable == "sftp" {
        let words = split_args(raw_segment);
        let mut i = 1;
        while i < words.len() {
            let w = &words[i];
            if w.starts_with('-') {
                if matches!(w.as_str(), "-p" | "-i" | "-l" | "-o" | "-c" | "-b" | "-F")
                    && i + 1 < words.len()
                {
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            // First non-option word is host
            if i + 1 < words.len() {
                let remote_words = &words[i + 1..];
                let remote_cmd = remote_words.join(" ");
                let clean_remote = remote_cmd.trim_matches(|c| c == '\'' || c == '"').trim();
                if !clean_remote.is_empty() {
                    return Some(UnwrappedScript {
                        interpreter: "ssh".to_string(),
                        code: clean_remote.to_string(),
                    });
                }
            }
            break;
        }
    } else if executable == "docker" || executable == "kubectl" {
        let words = split_args(raw_segment);
        if let Some(exec_idx) = words.iter().position(|w| w == "exec") {
            let mut i = exec_idx + 1;
            while i < words.len() {
                let w = &words[i];
                if w == "--" && i + 1 < words.len() {
                    let cmd = words[i + 1..].join(" ");
                    return Some(UnwrappedScript {
                        interpreter: executable.to_string(),
                        code: cmd,
                    });
                }
                if !w.starts_with('-') {
                    if i + 1 < words.len() {
                        let cmd = words[i + 1..].join(" ");
                        let clean = if let Some(stripped) = cmd.strip_prefix("-- ") {
                            stripped
                        } else {
                            &cmd
                        };
                        return Some(UnwrappedScript {
                            interpreter: executable.to_string(),
                            code: clean.trim().to_string(),
                        });
                    }
                    break;
                }
                i += 1;
            }
        }
    }
    None
}

struct SubAnalysis {
    executables: Vec<String>,
    flags: Vec<String>,
    commands: Vec<CommandSegment>,
    unwrapped: Vec<UnwrappedScript>,
}

fn analyze_sub_command(sub: &str) -> SubAnalysis {
    let mut executables = Vec::new();
    let mut flags = Vec::new();
    let mut commands = Vec::new();
    let mut unwrapped = Vec::new();

    let segments = split_compound_segments(sub);
    for seg in &segments {
        let clean = strip_redirections(seg);
        let (seg_norm, _, _) = strip_wrappers(&clean);
        let (seg_exec, seg_sub) = extract_executable_and_subcommand(&seg_norm);
        let words = split_args(&seg_norm);
        let (seg_flags, seg_args) = extract_flags_and_args(&words, seg_sub.as_deref());

        for f in &seg_flags {
            if !flags.contains(f) {
                flags.push(f.clone());
            }
        }

        if !seg_exec.is_empty() {
            let e = seg_exec.to_ascii_lowercase();
            if !executables.contains(&e) {
                executables.push(e);
            }
            let mut seg_unwrapped = Vec::new();
            if let Some(slot) = extract_code_slot(&seg_exec, seg, &words) {
                seg_unwrapped.push(slot);
            }
            commands.push(CommandSegment {
                raw: seg.clone(),
                command: seg.clone(),
                normalized: seg_norm.clone(),
                executable: seg_exec.clone(),
                subcommand: seg_sub.clone(),
                flags: seg_flags,
                args: seg_args,
                cwd: ".".to_string(),
                resolved_targets: Vec::new(),
                unwrapped: seg_unwrapped,
            });

            if let Some(remote) = extract_remote_or_container_command(&seg_exec, &seg_norm) {
                let clean_r = strip_redirections(&remote.code);
                let (remote_norm, _, _) = strip_wrappers(&clean_r);
                let (r_exec, r_sub) = extract_executable_and_subcommand(&remote_norm);
                let r_words = split_args(&remote_norm);
                let (r_flags, r_args) = extract_flags_and_args(&r_words, r_sub.as_deref());
                for f in &r_flags {
                    if !flags.contains(f) {
                        flags.push(f.clone());
                    }
                }
                if !r_exec.is_empty() {
                    let re = r_exec.to_ascii_lowercase();
                    if !executables.contains(&re) {
                        executables.push(re);
                    }
                    let mut r_unwrapped = Vec::new();
                    if let Some(slot) = extract_code_slot(&r_exec, &remote.code, &r_words) {
                        r_unwrapped.push(slot);
                    }
                    commands.push(CommandSegment {
                        raw: remote.code.clone(),
                        command: remote.code.clone(),
                        normalized: remote_norm,
                        executable: r_exec,
                        subcommand: r_sub,
                        flags: r_flags,
                        args: r_args,
                        cwd: ".".to_string(),
                        resolved_targets: Vec::new(),
                        unwrapped: r_unwrapped,
                    });
                }
                unwrapped.push(remote);
            }
        }
    }

    SubAnalysis {
        executables,
        flags,
        commands,
        unwrapped,
    }
}

fn push_unique_exec(executables: &mut Vec<String>, exec: &str) {
    let e = exec.to_ascii_lowercase();
    if !e.is_empty() && !executables.contains(&e) {
        executables.push(e);
    }
}

fn push_unique_flag(flags: &mut Vec<String>, fl: &str) {
    let f = fl.to_string();
    if !flags.contains(&f) {
        flags.push(f);
    }
}

/// Tokenize command, classify spans, extract inline code, and generate masked text.
pub fn classify_and_mask(
    command: &str,
    executable: &str,
) -> (Vec<Span>, Vec<UnwrappedScript>, Vec<String>, bool, String) {
    let bytes = command.as_bytes();
    let mut masked_bytes = bytes.to_vec();
    let mut spans = Vec::new();
    let mut unwrapped = Vec::new();
    let mut flags = Vec::new();
    let mut has_dangerous_subst = false;

    let mut i = 0;
    let mut in_command_pos = true;
    let mut prev_token_is_data_flag = false;
    let mut prev_token_is_inline_flag = false;

    let is_interpreter = INTERPRETERS.iter().any(|(interp, _)| *interp == executable);
    let inline_flags = INTERPRETERS
        .iter()
        .find(|(interp, _)| *interp == executable)
        .map(|(_, flags)| *flags)
        .unwrap_or(&[]);

    while i < bytes.len() {
        // Skip whitespace
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Comment: starts with '#' (outside of quotes)
        if bytes[i] == b'#' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'\n' && bytes[i] != b'\r' {
                masked_bytes[i] = b' ';
                i += 1;
            }
            spans.push(Span {
                kind: SpanKind::Comment,
                start,
                end: i,
                text: command[start..i].to_string(),
            });
            continue;
        }

        // Command separator (;, &&, ||, |)
        if bytes[i] == b';' || bytes[i] == b'&' || bytes[i] == b'|' {
            let start = i;
            if (bytes[i] == b'&' && i + 1 < bytes.len() && bytes[i + 1] == b'&')
                || (bytes[i] == b'|' && i + 1 < bytes.len() && bytes[i + 1] == b'|')
            {
                i += 2;
            } else {
                i += 1;
            }
            in_command_pos = true;
            prev_token_is_data_flag = false;
            prev_token_is_inline_flag = false;
            spans.push(Span {
                kind: SpanKind::Executed,
                start,
                end: i,
                text: command[start..i].to_string(),
            });
            continue;
        }

        let token_start = i;

        // Single-quoted token: '...'
        if bytes[i] == b'\'' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'\'' {
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // include closing quote
            }
            let token_text = &command[start..i];
            let inner = if token_text.len() >= 2 {
                &token_text[1..token_text.len() - 1]
            } else {
                ""
            };

            if prev_token_is_inline_flag && is_interpreter {
                // Inline code: DO NOT mask, keep visible for pattern matching
                spans.push(Span {
                    kind: SpanKind::InlineCode,
                    start,
                    end: i,
                    text: token_text.to_string(),
                });
                unwrapped.push(UnwrappedScript {
                    interpreter: executable.to_string(),
                    code: inner.to_string(),
                });
                prev_token_is_inline_flag = false;
            } else {
                // Pure data: mask interior with spaces
                for b in &mut masked_bytes[start + 1..i.saturating_sub(1)] {
                    *b = b' ';
                }
                spans.push(Span {
                    kind: SpanKind::Data,
                    start,
                    end: i,
                    text: token_text.to_string(),
                });
            }
            in_command_pos = false;
            prev_token_is_data_flag = false;
            continue;
        }

        // Double-quoted token: "..."
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            let mut escaped = false;
            let mut has_subst_inside = false;

            while i < bytes.len() {
                if escaped {
                    escaped = false;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'\\' {
                    escaped = true;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'"' {
                    i += 1;
                    break;
                }
                if bytes[i] == b'`'
                    || (bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(')
                {
                    has_subst_inside = true;
                    has_dangerous_subst = true;
                }
                i += 1;
            }

            let token_text = &command[start..i];
            let inner = if token_text.len() >= 2 && token_text.ends_with('"') {
                &token_text[1..token_text.len() - 1]
            } else {
                ""
            };

            if prev_token_is_inline_flag && is_interpreter {
                spans.push(Span {
                    kind: SpanKind::InlineCode,
                    start,
                    end: i,
                    text: token_text.to_string(),
                });
                unwrapped.push(UnwrappedScript {
                    interpreter: executable.to_string(),
                    code: inner.to_string(),
                });
                prev_token_is_inline_flag = false;
            } else if has_subst_inside {
                // Contains command substitution: executed
                spans.push(Span {
                    kind: SpanKind::Executed,
                    start,
                    end: i,
                    text: token_text.to_string(),
                });
            } else if prev_token_is_data_flag || in_command_pos || is_all_args_data_tool(executable)
            {
                // Data argument: mask interior with spaces
                for b in &mut masked_bytes[start + 1..i.saturating_sub(1)] {
                    *b = b' ';
                }
                spans.push(Span {
                    kind: SpanKind::Data,
                    start,
                    end: i,
                    text: token_text.to_string(),
                });
            } else {
                spans.push(Span {
                    kind: SpanKind::Argument,
                    start,
                    end: i,
                    text: token_text.to_string(),
                });
            }

            in_command_pos = false;
            prev_token_is_data_flag = false;
            continue;
        }

        // Bare / unquoted token
        let mut escaped = false;
        while i < bytes.len() {
            let b = bytes[i];
            if escaped {
                escaped = false;
                i += 1;
                continue;
            }
            if b == b'\\' {
                escaped = true;
                i += 1;
                continue;
            }
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                has_dangerous_subst = true;
                i += 2;
                let mut depth = 1;
                let mut sub_single = false;
                let mut sub_double = false;
                let mut sub_escaped = false;
                while i < bytes.len() && depth > 0 {
                    let sb = bytes[i];
                    if sub_escaped {
                        sub_escaped = false;
                        i += 1;
                        continue;
                    }
                    if sb == b'\\' && !sub_single {
                        sub_escaped = true;
                        i += 1;
                        continue;
                    }
                    if sb == b'\'' && !sub_double {
                        sub_single = !sub_single;
                        i += 1;
                        continue;
                    }
                    if sb == b'"' && !sub_single {
                        sub_double = !sub_double;
                        i += 1;
                        continue;
                    }
                    if !sub_single && !sub_double {
                        if sb == b'(' {
                            depth += 1;
                        } else if sb == b')' {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                    }
                    i += 1;
                }
                continue;
            }
            if b == b'`' {
                has_dangerous_subst = true;
                i += 1;
                let mut b_esc = false;
                while i < bytes.len() {
                    let sb = bytes[i];
                    if b_esc {
                        b_esc = false;
                        i += 1;
                        continue;
                    }
                    if sb == b'\\' {
                        b_esc = true;
                        i += 1;
                        continue;
                    }
                    if sb == b'`' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                continue;
            }
            if b == b';' || b == b'&' || b == b'|' || b.is_ascii_whitespace() {
                break;
            }
            i += 1;
        }

        let token_text = &command[token_start..i];
        let is_env_assign = try_strip_env_assign(token_text).is_some();

        if token_text.starts_with('-') {
            flags.push(token_text.to_string());
            let lower_flag = token_text.to_ascii_lowercase();
            if is_interpreter && inline_flags.iter().any(|f| lower_flag == *f) {
                prev_token_is_inline_flag = true;
            } else {
                prev_token_is_data_flag = DATA_ARG_FLAGS.contains(&token_text);
            }
            spans.push(Span {
                kind: SpanKind::Argument,
                start: token_start,
                end: i,
                text: token_text.to_string(),
            });
        } else if in_command_pos {
            spans.push(Span {
                kind: SpanKind::Executed,
                start: token_start,
                end: i,
                text: token_text.to_string(),
            });
            if !is_env_assign {
                in_command_pos = false;
            }
        } else if prev_token_is_inline_flag && is_interpreter {
            spans.push(Span {
                kind: SpanKind::InlineCode,
                start: token_start,
                end: i,
                text: token_text.to_string(),
            });
            unwrapped.push(UnwrappedScript {
                interpreter: executable.to_string(),
                code: token_text.to_string(),
            });
            prev_token_is_inline_flag = false;
        } else if prev_token_is_data_flag || is_all_args_data_tool(executable) {
            for b in &mut masked_bytes[token_start..i] {
                *b = b' ';
            }
            spans.push(Span {
                kind: SpanKind::Data,
                start: token_start,
                end: i,
                text: token_text.to_string(),
            });
            prev_token_is_data_flag = false;
        } else {
            spans.push(Span {
                kind: SpanKind::Argument,
                start: token_start,
                end: i,
                text: token_text.to_string(),
            });
        }
    }

    let executable_text = String::from_utf8(masked_bytes).unwrap_or_else(|_| command.to_string());
    (
        spans,
        unwrapped,
        flags,
        has_dangerous_subst,
        executable_text,
    )
}

fn is_all_args_data_tool(executable: &str) -> bool {
    matches!(executable, "echo" | "printf" | "print")
}

/// Analyze a shell command line with virtual CWD tracking and DCG payload unwrapping.
pub fn analyze_command_with_cwd(command: &str, initial_cwd: &str) -> CommandContext {
    let (normalized, stripped_wrappers, env_vars) = strip_wrappers(command);
    let (executable, subcommand) = extract_executable_and_subcommand(&normalized);
    let sink = extract_sink(command);
    let (spans, mut unwrapped, mut flags, has_dangerous_subst, executable_text) =
        classify_and_mask(command, &executable);

    let mut executables: Vec<String> = Vec::new();
    let mut segments: Vec<CommandSegment> = Vec::new();

    let raw_segs = split_compound_segments(command);
    let mut current_cwd = if initial_cwd.is_empty() {
        ".".to_string()
    } else {
        initial_cwd.to_string()
    };

    let mut prev_raw_seg: Option<String> = None;

    for seg in &raw_segs {
        let clean = strip_redirections(seg);
        let (seg_norm, _, _) = strip_wrappers(&clean);
        let (seg_exec, seg_sub) = extract_executable_and_subcommand(&seg_norm);
        let words = split_args(&seg_norm);
        let (seg_flags, seg_args) = extract_flags_and_args(&words, seg_sub.as_deref());

        for f in &seg_flags {
            push_unique_flag(&mut flags, f);
        }

        let mut seg_unwrapped = Vec::new();

        // 1. Code slot extraction (e.g. mysql -e, psql -c, python -c)
        if let Some(slot) = extract_code_slot(&seg_exec, seg, &words) {
            seg_unwrapped.push(slot.clone());
            if !unwrapped
                .iter()
                .any(|u| u.interpreter == slot.interpreter && u.code == slot.code)
            {
                unwrapped.push(slot);
            }
        }

        // 2. Piped stdin code extraction (e.g. echo "..." | mysql)
        if seg_unwrapped.is_empty()
            && let Some(ref prev) = prev_raw_seg
            && let Some(piped) = extract_pipeline_producer_payload(prev, &seg_exec)
        {
            seg_unwrapped.push(piped.clone());
            if !unwrapped
                .iter()
                .any(|u| u.interpreter == piped.interpreter && u.code == piped.code)
            {
                unwrapped.push(piped);
            }
        }

        // 3. Virtual CWD tracking and target resolution
        let seg_cwd = current_cwd.clone();
        let mut seg_resolved_targets = Vec::new();

        if seg_exec == "cd" || seg_exec == "pushd" {
            let target = seg_args.first().map(String::as_str).unwrap_or("~");
            current_cwd = resolve_cd_path(&current_cwd, target);
            seg_resolved_targets.push(current_cwd.clone());
        } else {
            for arg in &seg_args {
                let resolved = resolve_operand_target(&seg_cwd, arg);
                if !resolved.is_empty() {
                    seg_resolved_targets.push(resolved);
                }
            }
        }

        if !seg_exec.is_empty() {
            push_unique_exec(&mut executables, &seg_exec);

            let segment_item = CommandSegment {
                raw: seg.clone(),
                command: seg.clone(),
                normalized: seg_norm.clone(),
                executable: seg_exec.clone(),
                subcommand: seg_sub.clone(),
                flags: seg_flags,
                args: seg_args,
                cwd: seg_cwd,
                resolved_targets: seg_resolved_targets,
                unwrapped: seg_unwrapped,
            };

            segments.push(segment_item);

            if let Some(remote_unwrapped) =
                extract_remote_or_container_command(&seg_exec, &seg_norm)
            {
                let remote_act = analyze_sub_command(&remote_unwrapped.code);
                for e in remote_act.executables {
                    push_unique_exec(&mut executables, &e);
                }
                for f in remote_act.flags {
                    push_unique_flag(&mut flags, &f);
                }
                segments.extend(remote_act.commands);
                unwrapped.push(remote_unwrapped);
            }
        }

        prev_raw_seg = Some(seg.clone());
    }

    // Extract command substitutions: $(...) and `...`
    let substitutions = extract_substitutions(command);
    for sub_cmd in &substitutions {
        let sub_act = analyze_sub_command(sub_cmd);
        for e in sub_act.executables {
            push_unique_exec(&mut executables, &e);
        }
        for f in sub_act.flags {
            push_unique_flag(&mut flags, &f);
        }
        segments.extend(sub_act.commands);
        unwrapped.extend(sub_act.unwrapped);
    }

    // Also check unwrapped interpreter scripts (e.g. bash -c)
    for u in &unwrapped {
        if matches!(
            u.interpreter.as_str(),
            "bash" | "sh" | "zsh" | "ksh" | "dash"
        ) {
            let inner_act = analyze_sub_command(&u.code);
            for e in inner_act.executables {
                push_unique_exec(&mut executables, &e);
            }
            for f in inner_act.flags {
                push_unique_flag(&mut flags, &f);
            }
            segments.extend(inner_act.commands);
        }
    }

    // Ensure sink is in executables
    if let Some(ref s) = sink {
        push_unique_exec(&mut executables, s);
    }

    let final_executable = if executable.is_empty() {
        executables.first().cloned().unwrap_or_default()
    } else {
        executable
    };
    push_unique_exec(&mut executables, &final_executable);

    CommandContext {
        command: command.to_string(),
        normalized,
        executable: final_executable,
        subcommand,
        stripped_wrappers,
        env_vars,
        sink,
        executable_text,
        has_dangerous_subst: has_dangerous_subst || !substitutions.is_empty(),
        unwrapped,
        spans,
        flags,
        executables,
        commands: segments.clone(),
        segments,
        cwd: initial_cwd.to_string(),
    }
}

/// Analyze a shell command line and produce the comprehensive CommandContext.
pub fn analyze_command(command: &str) -> CommandContext {
    analyze_command_with_cwd(command, ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_wrappers_nested() {
        let cmd = r#"sudo -u admin env -i PGPASSWORD="my secret" FOO=bar \git push --force"#;
        let (norm, wrappers, env_vars) = strip_wrappers(cmd);
        assert_eq!(norm, "git push --force");
        assert!(wrappers.contains(&"sudo".to_string()));
        assert!(wrappers.contains(&"env".to_string()));
        assert!(wrappers.contains(&"env_assign".to_string()));
        assert!(wrappers.contains(&"backslash".to_string()));
        assert_eq!(
            env_vars.get("PGPASSWORD").map(|s| s.as_str()),
            Some("my secret")
        );
        assert_eq!(env_vars.get("FOO").map(|s| s.as_str()), Some("bar"));
    }

    #[test]
    fn test_extract_executable_and_subcommand() {
        let (exec, sub) =
            extract_executable_and_subcommand("git -C /root --no-pager commit -m 'initial'");
        assert_eq!(exec, "git");
        assert_eq!(sub.as_deref(), Some("commit"));

        let (exec2, sub2) = extract_executable_and_subcommand(
            "/usr/local/bin/kubectl.exe --namespace=prod apply -f deployment.yaml",
        );
        assert_eq!(exec2, "kubectl");
        assert_eq!(sub2.as_deref(), Some("apply"));

        let (exec3, sub3) = extract_executable_and_subcommand("cat file.txt");
        assert_eq!(exec3, "cat");
        assert_eq!(sub3, None);
    }

    #[test]
    fn test_sink_extraction() {
        let sink1 = extract_sink("curl -sSL https://install.example.com | sudo bash -s");
        assert_eq!(sink1.as_deref(), Some("bash"));

        let sink2 = extract_sink("echo 'SELECT * FROM users' | psql -U postgres > output.txt 2>&1");
        assert_eq!(sink2.as_deref(), Some("psql"));

        let sink_none = extract_sink("git status");
        assert_eq!(sink_none, None);
    }

    #[test]
    fn test_inline_code_unwrapping() {
        let cmd = "python -c 'import shutil; shutil.rmtree(\"/tmp\")'";
        let action = analyze_command(cmd);
        assert_eq!(action.executable, "python");
        assert_eq!(action.unwrapped.len(), 1);
        assert_eq!(action.unwrapped[0].interpreter, "python");
        assert_eq!(
            action.unwrapped[0].code,
            "import shutil; shutil.rmtree(\"/tmp\")"
        );
        // Inline code must not be blanked in executable_text
        assert!(action.executable_text.contains("shutil.rmtree"));
    }

    #[test]
    fn test_masking_data_and_comments() {
        let cmd = "git commit -m 'danger: rm -rf / everywhere' # this is a comment";
        let action = analyze_command(cmd);
        assert!(!action.executable_text.contains("danger: rm -rf"));
        assert!(!action.executable_text.contains("this is a comment"));
        assert_eq!(
            action.executable_text.len(),
            cmd.len(),
            "Masking must preserve exact string byte length"
        );
    }

    #[test]
    fn test_dangerous_substitution_detection() {
        let cmd1 = "echo \"$(cat /etc/shadow)\"";
        let action1 = analyze_command(cmd1);
        assert!(action1.has_dangerous_subst);

        let cmd2 = "echo '`rm -rf /`'";
        let action2 = analyze_command(cmd2);
        // Single quotes don't expand backticks in POSIX
        assert!(!action2.has_dangerous_subst);

        let cmd3 = "curl `cat domain.txt`";
        let action3 = analyze_command(cmd3);
        assert!(action3.has_dangerous_subst);
    }

    #[test]
    fn test_action_targets_helper() {
        let action = analyze_command("pg_dump db | psql remote_db");
        assert!(action.targets(&["psql"]));
        assert!(action.targets(&["pg_dump"]));
        assert!(!action.targets(&["mysql", "redis-cli"]));
    }

    #[test]
    fn test_compound_and_nested_substitutions() {
        let cmd = r#"cd "c:/Users/hugh.li/Data/xrapp/api-dev" && SUDO_PW=$(tr -d "[:space:]" < storage/app/.prod-sudo-pass) && DB_PW=$(printf "%s\n" "$SUDO_PW" | ssh xrAliYunProdWeb1 "sudo -S -u www-data grep -E '^DB_PASSWORD=' /data/www/xrapp-console/.env" 2>/dev/null | sed -E 's/^DB_PASSWORD=["'"'"']?([^"'"'"']+)["'"'"']?/\1/' | tr -d '\r\n') && export MYSQL_PWD="$DB_PW" && mysql -h 127.0.0.1 -P 41063 -u xrapp_prod_readonly --get-server-public-key=1 -t -e "SELECT 1" | head -20; unset MYSQL_PWD"#;
        let action = analyze_command(cmd);

        assert!(
            action.targets(&["ssh"]),
            "Action must detect ssh in pipeline substitution"
        );
        assert!(
            action.targets(&["mysql"]),
            "Action must detect mysql command in compound chain"
        );
        assert!(
            action.targets(&["grep"]),
            "Action must detect grep in remote ssh execution"
        );
        assert!(
            action.targets(&["tr"]),
            "Action must detect tr in substitution"
        );
        assert!(action.targets(&["head"]), "Action must detect head sink");
        assert!(
            !action.targets(&["rm", "pkill"]),
            "Action must not match unrelated programs"
        );

        assert!(
            action.has_flag(&["-P"]),
            "Action must detect -P flag passed to mysql"
        );
        assert!(
            action.has_flag(&["-h"]),
            "Action must detect -h flag passed to mysql"
        );
        assert!(
            action.has_flag(&["-E"]),
            "Action must detect -E flag passed to grep/sed"
        );
        assert!(
            action.has_flag(&["-d"]),
            "Action must detect -d flag passed to tr"
        );

        assert!(action.executables.contains(&"cd".to_string()));
        assert!(action.executables.contains(&"mysql".to_string()));
        assert!(action.executables.contains(&"ssh".to_string()));
        assert!(action.executables.contains(&"grep".to_string()));
        assert!(action.executables.contains(&"export".to_string()));
        assert!(action.executables.contains(&"unset".to_string()));

        assert!(
            !action.is_search(),
            "Compound command doing DB queries and remote exec is not read-only search"
        );
    }

    #[test]
    fn test_virtual_cwd_tracking_and_target_resolution() {
        let cmd = "cd ~ && git push -f && cd ~/.tml && rm -rf aa && cd / && rm *";
        let ctx = analyze_command_with_cwd(cmd, "/initial");

        // Verify segments count
        assert_eq!(ctx.segments.len(), 6);

        // Segment 0: cd ~
        assert_eq!(ctx.segments[0].executable, "cd");
        assert_eq!(ctx.segments[0].cwd, "/initial");
        assert_eq!(ctx.segments[0].resolved_targets, vec!["~"]);

        // Segment 1: git push -f
        assert_eq!(ctx.segments[1].executable, "git");
        assert_eq!(ctx.segments[1].subcommand.as_deref(), Some("push"));
        assert!(ctx.segments[1].flags.contains(&"-f".to_string()));
        assert_eq!(ctx.segments[1].cwd, "~");

        // Segment 2: cd ~/.tml
        assert_eq!(ctx.segments[2].executable, "cd");
        assert_eq!(ctx.segments[2].cwd, "~");
        assert_eq!(ctx.segments[2].resolved_targets, vec!["~/.tml"]);

        // Segment 3: rm -rf aa
        assert_eq!(ctx.segments[3].executable, "rm");
        assert_eq!(ctx.segments[3].cwd, "~/.tml");
        assert_eq!(ctx.segments[3].resolved_targets, vec!["~/.tml/aa"]);

        // Segment 4: cd /
        assert_eq!(ctx.segments[4].executable, "cd");
        assert_eq!(ctx.segments[4].cwd, "~/.tml");
        assert_eq!(ctx.segments[4].resolved_targets, vec!["/"]);

        // Segment 5: rm *
        assert_eq!(ctx.segments[5].executable, "rm");
        assert_eq!(ctx.segments[5].cwd, "/");
        assert_eq!(ctx.segments[5].resolved_targets, vec!["/*"]);

        // Verify helper find()
        let rm_segs = ctx.find("rm");
        assert_eq!(rm_segs.len(), 2);
        assert_eq!(rm_segs[0].resolved_targets, vec!["~/.tml/aa"]);
        assert_eq!(rm_segs[1].resolved_targets, vec!["/*"]);

        let git_segs = ctx.find("git");
        assert_eq!(git_segs.len(), 1);
        assert_eq!(git_segs[0].subcommand.as_deref(), Some("push"));
    }

    #[test]
    fn test_sql_statement_splitting_and_fail_closed() {
        // Safe read only
        let safe_sql = "SELECT id, name FROM users WHERE id = 1";
        assert!(is_sql_read_only(safe_sql));

        // Multiple read only statements with semicolons inside strings
        let safe_multi =
            "SELECT 'hello;world' AS greeting; SHOW TABLES; EXPLAIN SELECT * FROM orders";
        assert!(is_sql_read_only(safe_multi));

        // Injection with DROP TABLE (Fail-Closed)
        let injection_sql = "SELECT 1; DROP TABLE users; -- comment";
        assert!(!is_sql_read_only(injection_sql));

        // Destruction without semicolon: SELECT INTO OUTFILE
        let outfile_sql = "SELECT * FROM users INTO OUTFILE '/tmp/dump.txt'";
        assert!(!is_sql_read_only(outfile_sql));

        // DDL / DML
        assert!(!is_sql_read_only("DELETE FROM users WHERE 1=1"));
        assert!(!is_sql_read_only("UPDATE users SET admin = 1"));
        assert!(!is_sql_read_only("TRUNCATE TABLE logs"));
    }

    #[test]
    fn test_dcg_code_slot_unwrapping() {
        let cmd = r#"mysql -h 127.0.0.1 -P 3306 -u root -e "SELECT * FROM users" dbname"#;
        let ctx = analyze_command(cmd);

        assert_eq!(ctx.executable, "mysql");
        assert_eq!(ctx.unwrapped.len(), 1);
        assert_eq!(ctx.unwrapped[0].interpreter, "mysql");
        assert_eq!(ctx.unwrapped[0].code, "SELECT * FROM users");
        assert!(
            ctx.is_search(),
            "Pure SELECT in mysql CLI is read-only search"
        );

        let psql_cmd = r#"psql -U postgres -c "SELECT 1; DROP DATABASE test""#;
        let psql_ctx = analyze_command(psql_cmd);
        assert_eq!(psql_ctx.unwrapped.len(), 1);
        assert_eq!(psql_ctx.unwrapped[0].interpreter, "psql");
        assert!(
            !psql_ctx.is_search(),
            "DROP DATABASE in psql CLI is destructive"
        );
    }

    #[test]
    fn test_piped_code_injection() {
        let cmd = r#"echo "SELECT * FROM users" | mysql -u root db"#;
        let ctx = analyze_command(cmd);

        assert!(ctx.targets(&["mysql"]));
        assert!(ctx.targets(&["echo"]));
        assert!(
            ctx.unwrapped
                .iter()
                .any(|u| u.interpreter == "mysql" && u.code == "SELECT * FROM users")
        );
        assert!(
            ctx.is_search(),
            "Piped read-only query into mysql is search"
        );
    }
}
