//! Rule prelude: shared, pure helpers injected as the global `aiHook` before
//! every rule runs.
//!
//! Rules are compiled via `new Function("ctx","sys",code)` in an isolated
//! QuickJS context with **no module system** — a helper needed by several rules
//! could only be copy-pasted per file, which drifts (the same function had
//! already diverged on single-pipe handling across seven rules). This prelude
//! is evaluated once per rule context and exposes one stable namespace so the
//! helpers have a single source of truth.
//!
//! Scope discipline: only **pure, stateless, I/O-free** text analysis lives
//! here. Anything that reads the filesystem / environment / network stays in
//! `sys`, and anything that encodes a plugin's business policy (whitelists,
//! host names, account names) stays in that rule file.
//!
//! The source is plain JS and is prepended to the rule wrapper (a single
//! compile+eval per rule — no second `eval`). `globalThis.aiHook` is used
//! rather than a bare `const` because the rule body runs in a *separate*
//! compilation whose scope chain is the global object only: a lexical binding
//! from the wrapper program would be invisible to it.
//!
//! Quote handling mirrors bash: separators inside `'…'` / `"…"` never split,
//! a backslash inside `"…"` escapes the next character, and a single-quoted
//! region keeps backslashes literal.

/// JS prepended to every rule wrapper; defines the global `aiHook` namespace.
pub const PRELUDE_JS: &str = r#"
// ---- ai-hook rule prelude (injected global: aiHook) ------------------------
// Pure, stateless, I/O-free helpers for command-text analysis. Single source
// of truth shared by every rule; never redefine these inside a rule file.
globalThis.aiHook = (function () {
    var SEARCH_PREFIX = /^\s*(grep|rg|git|find|cat|head|tail|sed|awk|echo|printf)\b/i;
    var GIT_COMMIT = /^\s*git\s+commit\b/i;
    var CMD_SUBSTITUTION = /\$\(/;

    // Quote-aware top-level segmentation of a command line.
    //   - splits on && || ; and newlines; never splits inside quotes
    //   - single pipe '|' is NOT a separator by default (callers that judge
    //     pipe flow — e.g. `echo ... | mysql` — need both sides in one segment)
    //   - opts.splitPipe = true also splits on a single '|' (rm-root semantics)
    function splitTopCommands(cmd, opts) {
        if (typeof cmd !== "string") return [];
        var splitPipe = !!(opts && opts.splitPipe);
        var segs = [];
        var cur = "";
        var quote = null;
        for (var i = 0; i < cmd.length; i++) {
            var c = cmd.charAt(i);
            if (quote) {
                cur += c;
                if (quote === '"' && c === "\\") {
                    cur += cmd.charAt(i + 1);
                    i++;
                } else if (c === quote) {
                    quote = null;
                }
                continue;
            }
            if (c === '"' || c === "'") { quote = c; cur += c; continue; }
            var two = cmd.slice(i, i + 2);
            if (two === "&&" || two === "||") { segs.push(cur); cur = ""; i++; continue; }
            if (c === ";" || c === "\n") { segs.push(cur); cur = ""; continue; }
            if (splitPipe && c === "|") { segs.push(cur); cur = ""; continue; }
            cur += c;
        }
        segs.push(cur);
        return segs;
    }

    // Collapse a multi-line command to a single line (newlines -> spaces) so
    // downstream regexes and quote state do not straddle line boundaries.
    function flatten(cmd) {
        return typeof cmd === "string" ? cmd.replace(/[\r\n]+/g, " ") : "";
    }

    // Search-style prefix ("only talks, does not do"): grep/rg/git/find/cat/
    // sed/echo… — a keyword inside such a command is not an execution.
    function isSearchPrefix(seg) {
        return typeof seg === "string" && SEARCH_PREFIX.test(seg);
    }

    // `git commit` segment: its message is descriptive text, so SQL/Redis/file
    // keywords inside it are not executed.
    function isGitCommit(seg) {
        return typeof seg === "string" && GIT_COMMIT.test(seg);
    }

    // Contains command substitution `$(` — the executed content is not
    // statically decidable, so callers should default to asking.
    function hasCmdSubstitution(seg) {
        return typeof seg === "string" && CMD_SUBSTITUTION.test(seg);
    }

    // Write vector: redirect to disk (`>` / `>>`, `2>&1` allowed) or a pipe
    // into `tee`.
    function hasWriteVector(cmdStr) {
        if (typeof cmdStr !== "string") return false;
        if (/(>>|>)\s*[^&]/.test(cmdStr)) return true;
        if (/[>|]\s*[^;&|]*\b(tee)\b/i.test(cmdStr)) return true;
        return false;
    }

    return {
        splitTopCommands: splitTopCommands,
        flatten: flatten,
        isSearchPrefix: isSearchPrefix,
        isGitCommit: isGitCommit,
        hasCmdSubstitution: hasCmdSubstitution,
        hasWriteVector: hasWriteVector
    };
})();
"#;
