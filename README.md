# ai-hook — Unified Multi-Agent Security Interceptor & Autonomous Rule Dispatcher

[![CI](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml/badge.svg)](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hughcube/ai-hook)](https://github.com/hughcube/ai-hook/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **It exists for two things: hiding complexity, and making rules pleasant to write.**  
> **① Hide the complexity** — hook-protocol differences across agents, platform quirks, and subprocess/context-fetching plumbing are all wrapped into one native binary: the same rules are written once and run everywhere, with no per-agent, per-platform script matrix. On Windows it also collapses the old one-process-per-fetch stutter into a single process with millisecond-scale in-process evaluation.  
> **② Better rule authoring** — a rule is just plain JS: a rich `ctx` context, native microsecond `sys` primitives, one uniform deny/ask/inject decision protocol with desktop/terminal interaction, plus `list`/`test`/`bench`/`tutorial` tooling — instead of hand-written shell glue and cross-platform trial and error.  
> Zero variable pollution, a single-process closed loop, and extreme speed all fall out of this design.  
> Hooks for **Claude Code**, **Google Antigravity**, **CodeBuddy / WorkBuddy**, **OpenAI Codex**, **Gemini CLI**, **OpenCode** — one rule set, every agent, on Windows / macOS / Linux.
>
> **OpenCode note:** OpenCode has no out-of-process hook protocol of its own — it loads in-process JS/TS plugins (see [opencode.ai/docs/plugins](https://opencode.ai/docs/plugins/)). ai-hook reaches it through the community bridge [`magarcia/opencode-claude-hooks`](https://github.com/magarcia/opencode-claude-hooks), which forwards Claude-Code-shaped envelopes and sets `OPENCODE_COMPAT=1`. Install the bridge (or use the in-process plugin approach) for OpenCode support.

English | [中文](README_zh.md)

---

## 📖 Motivation & Problem Statement

Hooks sit on the **hot path** of every tool invocation — they guard before a tool runs and wrap up after it finishes. To defend against destructive operations (e.g. `rm -rf /`, unexpected `migrate:fresh`, cache wiping `FLUSHALL`, or secret leakage), multi-agent and plugin-heavy ecosystems traditionally make each plugin write its own script: on Windows that drags the high-frequency path into jarring stutter, and on every platform those scripts end up as islands that cannot be shared across agents or platforms. Legacy hook mechanisms therefore suffer from four fundamental problems:

1. **Process Explosion & Noticeable Lag**: Each plugin maintaining independent Bash scripts means spawning 10+ sequential processes on Windows, causing jarring **500~750ms** pauses for every single tool invocation;
2. **Variable Pollution & State Drift**: Sourcing multiple scripts in a shared environment leads to leaked environment variables, overridden functions, and working directory drift;
3. **The Trap of Forced Script Concatenation**: Trying to speed things up by physically merging scripts into one massive monolithic bundle drastically escalates maintenance complexity;
4. **Rigid, Non-Autonomous Rules**: Traditional hooks *can* reach this context — `date` for time, `git branch` for branches, `cat .env` for local config, `curl` for the network — but wiring it into a rule means writing glue by hand. On **Windows**, each fetch spawns a fresh subprocess whose cold start is expensive, so multiple rules compound into visible stutter. On **every platform**, you still face: hand-rolled regex parsing of command output, shell syntax that is not portable across platforms, zero caching between rules in the same request, a `curl` without a timeout that hangs the whole gate — and that glue must be **re-written for every agent**. So dynamic rules like *"no production writes after 16:00 on Friday"*, *"block force-push on master"*, or *"honor the local `.env`"* are **hard to write and impossible to share**, and in practice collapse into static regexes and path matching.

**`ai-hook` solves these problems once and for all**: A single, standalone native binary written in Rust serves as the central dispatcher. With an embedded lightweight QuickJS engine, every plugin's rules execute in physically isolated sandboxes while **autonomously acquiring their own prerequisite data** with microsecond latency — local context (time/branch/config) is read through native APIs (the OS page cache already makes repeat reads pure in-memory operations), so rules contain no shell glue and spawn no subprocesses, behaving identically on every platform (and sidestepping Windows' expensive subprocess cold starts). Remote context such as network probes goes through the built-in `sys.http` exit — no `curl` subprocess spawn, round-trip latency unchanged, timeout required to avoid hangs.

---

## ⚡ Architecture Overview

```
[Agent Tool Invocation (run_command / write_to_file / ...)]
                       │
                       ▼ (stdin: JSON payload)
┌─────────────────────────────────────────────────────────────┐
│             Central Dispatcher Binary: ai-hook.exe          │
│   (Rust Native / Statically Linked / 0 External Deps /       │
│    in-process ms-scale evaluation)                            │
│                                                             │
│  1. Fast Path Short-Circuit:                                │
│     Read-only safe commands (git status, ls, pwd) short-    │
│     circuit in-process (no JS VM started)                    │
│  2. Native Serde JSON Ingress Parser:                       │
│     Recognizes AGY (.toolCall), CC (.tool_input), Codex     │
│  3. Explicit Rule Loading (CLI args / AI_HOOK_RULES / ./.ai-hook):│
│     ┌───────────────────────────────────────────────────┐   │
│     │ Sandboxed Rule Execution (0 Variable Pollution):  │   │
│     │ - ai-hook ./rules/protect-prod.js (explicit args)  │   │
│     │ - AI_HOOK_RULES="a.js;b.js" (env var)│   │
│     │ - ./.ai-hook/rules.js or ./.ai-hook/rules/ (local)   │   │
│     │ - every rule runs in its own sandbox, zero merging │   │
│     └───────────────────────────────────────────────────┘   │
│  4. Autonomous Prerequisite Data Access (Native sys SDK):   │
│     - sys.git.branch(): Pure in-memory .git/HEAD read (µs)   │
│     - sys.fs.readText(): Native Rust file I/O (µs, in-engine)│
│  5. Decision Egress & Real Interactive GUI:                 │
│     - YOLO/Unattended mode: Native 60s countdown popup      │
│     - Terminal interactive: Protocol output (force_ask/ask) │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼ (stdout: JSON decision)
[Agent Resumes Execution OR Aborts with Rejection]
```

---

## ✨ Key Features

- 🚀 **Extreme Performance**:
  - Single Rust PE binary with zero runtime deps: one hook invocation measures **~7ms** end-to-end (median, Windows 11 x64, node-style host), and almost all of it is the host's process-creation cost — independent of ai-hook itself;
  - Read-only safe commands short-circuit in-process via Fast Path without loading the JS VM (near-zero decision cost);
  - Rule evaluation runs in-process at millisecond scale (measured gap to Fast Path is <1ms); each extra rule adds only ~0.2ms.
- 🧩 **Write Once, Run in Every Agent**:
  - One binary auto-detects each host's payload/events and emits each host's output protocol (AGY `.toolCall`, CC `.tool_input`, Codex `turn_id`…), so there is no per-agent hook to maintain;
  - The same JS rule files drop straight into Antigravity, Claude Code, CodeBuddy, or Codex with **zero migration cost**.
- 🛡️ **Zero Variable Pollution**:
  - Each plugin rule stays completely independent in its own file. **Zero file concatenation or build-step bundling required**.
  - Evaluated in isolated QuickJS Context sandboxes; variables and functions evaporate upon completion.
- 🧠 **Fully Autonomous Rules**:
  - Rules fetch their own prerequisites dynamically via the `sys` SDK without base engine bloating:
    - **Time / Calendar**: Built-in standard JavaScript `new Date()` (Friday freeze, holiday windows).
    - **Git Branch Aware**: `sys.git.branch()` parses `.git/HEAD` in pure memory (0 external processes).
    - **Configuration Inspection**: `sys.fs.readText(".env")` resolved against `ctx.cwd` (repeat reads hit the OS page cache).
- ⏱️ **Native 60-Second Countdown Docked Dialog**:
  - In unattended / skip-permissions (YOLO) mode, `ai-hook` presents a topmost window with a 60s countdown, docked action buttons, and scrollable command inspection (rendered by a hidden PowerShell host running WPF — one child process whose console window is suppressed, never a conhost flash).
- 🧰 **Developer Tooling Suite**:
  - Built-in `list`, `test`, `bench`, and `install` subcommands for effortless debugging and verification.

---

## 📊 Performance Benchmarks (Windows 11 x64 / node-style host)

> **Measurement note**: most of a hook invocation's latency is **process creation & loading, triggered by the host** — an empty probe binary measures the same as ai-hook. ai-hook only controls in-process rule evaluation, so the two are reported separately instead of crediting host-side overhead to ai-hook.

| Metric | Legacy Bash Hooks (10 scripts) | ai-hook | Notes |
| :--- | :--- | :--- | :--- |
| **Process creation** | 10 `bash.exe` spawns per call | 1 `ai-hook.exe` spawn | 90% fewer process creations |
| **Full hook lifecycle** | 420–750ms (historical measurement) | **~7ms median** (fast-path 6.7 / engine 6.9) | Gap mostly comes from 10→1 processes |
| **Read-only commands (Fast Path)** | Boots the whole script chain | In-process short-circuit, no JS VM | Near-zero decision cost |
| **Rule evaluation (in-process)** | Re-spawns `date`/`git`/`cat`/`curl` per rule | Native `sys` reads; <1ms per rule, ~0.2ms per extra rule | Measured engine-side |
| **GUI popup** | Spawns PowerShell, ~300ms cold start | One hidden PowerShell host (CREATE_NO_WINDOW) renders the WPF dialog | One child process, console hidden — no conhost flash |

---

## 🚀 Quick Start

### 1. Download & Install

Download standalone precompiled executables directly from [GitHub Releases](https://github.com/hughcube/ai-hook/releases) (ready to run, no extraction needed):

```bash
# Windows (PowerShell): Download directly to ~/.local/bin
$bin = "$HOME\.local\bin"; if (-not (Test-Path $bin)) { New-Item -ItemType Directory -Path $bin -Force }; Invoke-WebRequest -Uri "https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.exe" -OutFile "$bin\ai-hook.exe"

# Linux: Download directly to system bin path
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86_64
chmod +x /usr/local/bin/ai-hook

# macOS (Apple Silicon M-series)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-aarch64
chmod +x /usr/local/bin/ai-hook

# macOS (Intel)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-x86_64
chmod +x /usr/local/bin/ai-hook

# 32-bit (i686; macOS has no 32-bit support since 10.15, so Windows/Linux only)
curl -Lo ai-hook.exe https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86.exe
curl -Lo ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86 && chmod +x ai-hook
```

Or compile and install from source:

```bash
cargo install --path .
ai-hook install
```

### 2. Register in Agent Configurations (Supports Multiple Scripts)

`ai-hook` is designed as a universal, zero-dependency safety gate. Pass one or more rule script paths directly as positional CLI arguments:

#### (1) Google Antigravity
Configure in `~/.gemini/config/hooks.json` (or workspace `.agents/hooks.json`). The official schema wraps events in a top-level hook name (with optional `enabled`):
```json
{
  "ai-hook-gate": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "ai-hook ~/.agents/plugins/dev/hooks/protect-db-migrate.js ~/.agents/plugins/rd/hooks/protect-prod-db-write.js",
            "timeout": 70
          }
        ]
      }
    ]
  }
}
```

#### (2) Anthropic Claude Code / CodeBuddy
Configure in your hooks configuration:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "command": "ai-hook ./rules/protect-prod.js ./rules/protect-publish.js"
      }
    ]
  }
}
```

> **Performance Guarantee**: `ai-hook` strictly evaluates only the explicit scripts provided, with zero disk traversal. Full evaluation across 10 rules takes only ~2ms.

### 3. Modern Adaptive Dialog & Timeout Configuration

`ai-hook` ditches clunky legacy dialogs in favor of an adaptive floating card design (rendered via native WPF XAML on Windows):
- **Intelligent Auto-Collapsing**: When there is no command to display, **the code box is completely collapsed**, eliminating awkward blank areas!
- **Dark Mode Code Card**: When a command is present, it is rendered in a sleek `#0F172A` dark container with syntax-friendly styling and auto-scrollbars;
- **Full Keyboard Navigation**: Press `Enter` to Allow, press `Esc` to Deny;
- **Selectable Text**: reason and command are selectable and copyable (`Ctrl+A` then `Ctrl+C`) on Windows; macOS/Linux use native system dialogs (same structure: reason/command sections, countdown, Esc to deny) where text selection is limited by the platform dialog
- **Topmost & Draggable**: Smooth mouse drag & drop anywhere on the card.

| Env Variable / CLI Option | Default | Description |
| :--- | :--- | :--- |
| `AI_HOOK_GUI_TIMEOUT` / `--timeout <N>` | `60` | Default countdown timeout in seconds (auto-denies on expiration) |
| `AI_HOOK_GUI` / `--no-gui` | `1` (enabled) | Set to `0` or `false` to disable the GUI dialog completely |
| `AI_HOOK_FORCE_GUI` / `--force-gui` | `0` (disabled) | **Forced Popup**: Forces GUI popup confirmation even if agent supports native terminal ask (except hard deny) |
| `AI_HOOK_DEBUG` / `--debug` | `0` (disabled) | **Debug Mode**: Record raw host input, context, execution chain, and result to `~/.ai-hook/logs/ai-hook-debug-{agent}-{YYYYMMDD}.log` |
| `AI_HOOK_DEBUG_MAX_FILES` | `14` | Maximum log files retained (defaults to keeping the latest 14 files, older ones pruned automatically) |
| `AI_HOOK_DEBUG_FILE` | (auto) | Custom debug log file path (overrides default naming/path) |

---

## 📝 Rule Authoring Guide

Rules are written in standard JavaScript (ES6+) with zero npm dependencies:

```javascript
export default function(ctx, sys) {
  // Your autonomous safety logic...
  return null; // Pass
}
```

### 1. `ctx` Context Object Reference

Through the `ctx` object, your rule can inspect the AI Agent type, the full raw payload, and the tool name/arguments:

| Property | Type | Semantics (full contract: `ai-hook tutorial`) |
| :--- | :--- | :--- |
| `ctx.platform` | `string` | Detected host: `"antigravity"` / `"claude_code"` / `"codebuddy"` / `"workbuddy"` / `"codex"` / `"gemini"` / `"opencode"` / `"generic"` |
| `ctx.mode` | `string?` | Host permission mode: `default`/`plan`/`acceptEdits`/`dontAsk`/`bypassPermissions` |
| `ctx.isYolo` | `boolean` | No-confirm mode (auto-detects `AGY_DANGEROUSLY_SKIP_PERMISSIONS` and `CODEX_DANGEROUSLY_SKIP_PERMISSIONS`, or mode bypassPermissions/dontAsk) |
| `ctx.event` | `string?` | **Canonical event name (identical across hosts)**: `"PreToolUse"` / `"PostToolUse"` / `"UserPromptSubmit"` / `"Stop"`… Gemini's `AfterTool`/`BeforeAgent` fold into `PostToolUse`/`UserPromptSubmit`, so a rule written once holds everywhere |
| `ctx.eventRaw` | `string?` | The host's own event spelling (e.g. Gemini `"AfterTool"`), for host-specific branches |
| `ctx.prompt` | `string?` | User raw prompt text (provided in `UserPromptSubmit` prompt intercept events) |
| `ctx.session` | `{id, transcriptPath}?` | Session id + full transcript path (read with `sys.fs.readText`) |
| `ctx.cwd` | `string` | Session/command working directory |
| `ctx.model` | `string?` | Host model id (e.g. Antigravity `modelName`) |
| `ctx.tool` | `string` | Host tool name verbatim (`"Bash"`/`"run_command"`/`"Write"`…) |
| `ctx.cmd` | `string?` | Command tools only; `null` otherwise |
| `ctx.file` | `{path, action}?` | File tools only; `action`: `read`/`write`/`edit`/`delete`/`list` (Codex `apply_patch` targets are extracted from the patch text by the engine) |
| `ctx.mcp` | `{server, tool}?` | MCP tools only; both host spellings (`mcp__server__tool` / `mcp_server_tool`) normalize to the same pair — server-defined parameters stay verbatim in `ctx.args`. `server`/`tool` are lower-cased for host-free matching; if an MCP tool's exact case matters, compare against `ctx.tool` verbatim |
| `ctx.web` | `{action, url, query}?` | Web tools only; `action`: `fetch` (WebFetch / AGY `read_url_content`, has `url`) or `search` (WebSearch / AGY `search_web`, has `query`) |
| `ctx.search` | `{kind, path, pattern}?` | Code-search tools only; `kind`: `glob` (Glob) or `grep` (Grep / AGY `grep_search`) |
| `ctx.agent` | `{kind, description, prompt}?` | Delegation tools only; `kind`: `agent` (Agent / Codex spawn) / `workflow` / `task` |
| `ctx.args` | `object` | Host tool arguments verbatim (`{command}`, `{file_path, content}`, …) |
| `ctx.raw` | `object?` | Full original host payload — escape hatch, prefer `cmd`/`file`/`args`; **parsed on first access**, so MB-sized transcripts cost nothing to rules that never touch it |
| `ctx.rawInput` | `string` | Raw payload text |
> Design rule: one semantic per property, no aliases; `cmd`/`file` are `null` when not applicable — guard rules with truthiness checks.

#### 1.1 Host event names at a glance: canonical (`ctx.event`) ↔ every agent

`ctx.event` is the **Claude Code spelling**, used identically on every host. The table maps each canonical name to the event each agent fires for the same lifecycle point (`—` = the host has no such event):

| `ctx.event` (canonical) | Claude Code | OpenAI Codex | CodeBuddy / WorkBuddy | Google Antigravity | Gemini CLI | OpenCode (bridge) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `PreToolUse` | PreToolUse | PreToolUse | PreToolUse | PreToolUse (shape-inferred) | `BeforeTool` | PreToolUse |
| `PostToolUse` | PostToolUse | PostToolUse | PostToolUse | (official event; deliberately *not* distinguished — payloads land under `PreToolUse`, see note) | `AfterTool` | PostToolUse |
| `PostToolUseFailure` | PostToolUseFailure | — | — | — | — | — |
| `PermissionRequest` | PermissionRequest | PermissionRequest | — | — | — | — |
| `UserPromptSubmit` | UserPromptSubmit | UserPromptSubmit | UserPromptSubmit | — | `BeforeAgent` | — |
| `Stop` | Stop | Stop | Stop | Stop (shape-inferred) | `AfterAgent` | — |
| `SubagentStart` | SubagentStart | SubagentStart | SubagentStart | — | — | — |
| `SubagentStop` | SubagentStop | SubagentStop | SubagentStop | — | — | — |
| `PreCompact` | PreCompact | PreCompact | PreCompact | — | `PreCompress` | — |
| `PostCompact` | PostCompact | PostCompact | PostCompact | — | — | — |
| `SessionStart` | SessionStart | SessionStart | SessionStart | — | SessionStart | — |
| `SessionEnd` | SessionEnd | SessionEnd | SessionEnd | — | SessionEnd | — |
| `Setup` | Setup (observe only\*) | — | — | — | — | — |
| `PreInvocation` | — | — | — | PreInvocation (shape-inferred) | — | — |

Notes that keep the table honest:

- **Gemini CLI** spells events in its own vocabulary (`BeforeTool`/`AfterTool`/`BeforeAgent`/`AfterAgent`/`PreCompress`). They fold into the canonical names above — that is the whole point of `ctx.event` — while the original spelling stays readable as `ctx.eventRaw` (e.g. `"AfterTool"`) and named exports can still be written per canonical name.
- **Antigravity sends no event name on stdin at all** (its official input fields are `conversationId`/`workspacePaths`/`transcriptPath`/… plus `toolCall`); ai-hook infers the event from the envelope shape. `PreInvocation` and `PostInvocation` have byte-identical input shapes, so both are classified as `PreInvocation` (`ctx.eventRaw` stays `null` for AGY — it genuinely has no spelling to report). AGY's `PostToolUse` is deliberately **not** inferred from the `error` key either (its presence is undocumented for `PreToolUse`, and a misclassification would silently drop the gate), so a post-tool payload is reported as `PreToolUse` — rules on it can still read the tool/cwd, but any decision they emit is ignored by the host, whose `PostToolUse` output schema is the empty object `{}`.
- **OpenCode** has no out-of-process hook protocol; through the `opencode-claude-hooks` bridge it forwards Claude-Code-shaped envelopes (`OPENCODE_COMPAT=1`), so the canonical column equals the Claude Code column. **The bridge surface is much narrower than Claude Code's**, though: `src/executor.ts` only treats `exitCode === 2` as a block and `src/index.ts` checks just `result.blocked` in `tool.execute.before`, so a PreToolUse deny is delivered as **exit code 2 with the reason on stderr** (`permissionDecision` would be ignored = fail open). `PermissionRequest` uses `permissionDecision` (not `decision.behavior`). The bridge wires neither `Stop` nor `UserPromptSubmit`, discards everything `tool.execute.after` returns, and implements no `ask` — those events carry no capability on opencode, and a `confirm` degrades to the GUI dialog or a fail-closed deny.
- **`Setup` (\*)** is observable but has no decision/inject channel: Claude Code's official Setup decision control discards a Setup hook's JSON output fields (including `hookSpecificOutput.additionalContext`). Setup is absent from the CodeBuddy / WorkBuddy official event list and from Codex's, so only Claude Code ever fires it.
- Events ai-hook does not model (e.g. Claude Code `TaskCompleted`, `Notification`, `ConfigChange`, `WorktreeCreate`… ) are never lost: they surface as `ctx.event` with the **host's own spelling** and can be observed (logged / branched on), they just cannot drive a decision.
- **CodeBuddy and WorkBuddy share one engine**: WorkBuddy runs the CodeBuddy Code CLI with its own config directory, and its hooks documentation is the same CodeBuddy document.
- **Follow the implementation, not just the doc**: CodeBuddy's `hooks.md` says Stop/SubagentStop should use `continue: false`, but the shipped CLI requires `blocking === true` (`SessionHookManager.executeStopHooks`), which only `decision: "block"` / a `permissionDecision` deny / exit code 2 produce — `continue: false` is a no-op that lets the agent stop anyway. ai-hook emits `decision: "block"` there. `continue: false` *is* used for UserPromptSubmit and PreCompact, where `allowed = false` alone is enough.
- **Gemini CLI was folded into Antigravity CLI**: Google stopped serving Gemini CLI for free / AI Pro / Ultra tiers on 2026-06-18 ([announcement](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli)); Antigravity CLI keeps Hooks. The Gemini column stays for paid/self-hosted setups and is recognised by Gemini's documented `BeforeTool`/`AfterTool`/… vocabulary plus its unique `timestamp` input field.

#### 1.2 Matchers: waking ai-hook up, and writing rules that do not care about tool names

Think of it as **two independent filter layers**:

1. **The host's native `matcher` (coarse)** — written in the host config file. It
   decides *which tool calls wake ai-hook up at all*. Syntax and tool names are
   host-specific, and a wrong value silently disables the hook (the gate never
   fires — Claude Code's own docs describe the result as "silently disabled").
2. **Your rules (fine)** — once ai-hook is awake, the JS rules decide
   allow / ask / deny / inject from the normalized `ctx` fields, which mean the
   same thing on every host.

**Rule of thumb: keep the native matcher wide; keep the decision in the rule.**
A matcher must be rewritten per host anyway (different syntax, different tool
names), while rules travel everywhere: they test `ctx.cmd` (command text) and
`ctx.file.action` (`read`/`write`/`edit`/`delete`/`list`), never a host's tool
spelling. Put the "should this be blocked" logic in the rule — it is then
testable with `ai-hook test --platform <host>` and auditable in one place — and
let the matcher only stop unrelated tool calls from paying the hook's process
cost. **Wide is safe**: a false positive costs one extra hook run; a false
negative silently disables the gate.

Matchers are **per event**: configuring `PreToolUse` does nothing for
`PostToolUse`/`UserPromptSubmit`…, and only events that document a matcher
honour one.

##### Table A — matcher values per intercept goal

| Intercept goal | Claude Code | OpenAI Codex | CodeBuddy / WorkBuddy | Google Antigravity | Gemini CLI | OpenCode (bridge) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Run a command | `Bash`, `PowerShell`\* | `Bash` (official example `^Bash$`) | `Bash` | `run_command` | `run_shell_command` | `bash` |
| Write a file | `Write` | `Write`/`apply_patch`† | `Write` | `write_to_file` | `write_file` | `write` |
| Edit a file | `Edit` | `Edit`/`apply_patch`† | `Edit` | `replace_file_content`, `multi_replace_file_content` | `replace` | `edit` |
| Read a file | `Read` | `Read`† | `Read` | `view_file` | `read_file` (batch: `read_many_files`) | `read` |
| List a directory | — | — | — | `list_dir` | `list_directory` | — (no built-in `list` tool; use `bash`) |

\* Claude Code registers `Bash` and `PowerShell`; on Windows without Git Bash
only `PowerShell` exists. † Codex's `apply_patch` payload always reports
`tool_name: "apply_patch"`, whose official aliases include `Edit`/`Write`
(hooks-doc matcher examples also name `Bash`, `update_plan`, `Agent`,
`WebSearch`; a read tool is not named there — confirm against the official tool
list). Prefer anchored patterns (`^Bash$`) like the official example.

##### Table B — matcher semantics per host

| Host | matcher semantics | Match everything | Notes |
| :--- | :--- | :--- | :--- |
| Claude Code | exact string / `\|`-`,`-list when the value contains only letters, digits, `_`, `-`, spaces, `,`, `\|`; otherwise an **unanchored** JS regex (`RegExp.prototype.test` — wrap in `^…$` for a whole-name match) | `"*"`, `""`, or omitted | Tool-name filtering applies to PreToolUse/PostToolUse/PostToolUseFailure/PermissionRequest/PermissionDenied; SessionStart/Setup/SessionEnd/Notification filter other fields (`source`/`trigger`/…); a matcher on an unsupported event is silently ignored |
| OpenAI Codex | "regex string" (official); anchoring/case not stated — the official example anchors (`^Bash$`) | `"*"`, `""`, or omitted | UserPromptSubmit / Stop / Interrupt ignore the matcher; MCP names `mcp__<server>__<tool>` |
| CodeBuddy / WorkBuddy | regex pattern, **case-sensitive**; a bare `Write` matches any tool name *containing* "Write" — anchor `^Write$` for an exact match | `"*"`, `""`, or omitted | Only PreToolUse / PostToolUse honour it; other events omit the field; hooks run under Git Bash on Windows |
| Google Antigravity | regex (official examples `run_command`, `run_command\|view_file`, `browser_.*`) | `""` or `"*"` | Only PreToolUse / PostToolUse honour it; PreInvocation / PostInvocation / Stop ignore it |
| Gemini CLI | regex on tool events; exact strings on lifecycle events (official reference) | `""` or `"*"` | MCP names `mcp_<server>_<tool>` |
| OpenCode (bridge) | the bridge compiles the CC matcher into a **case-sensitive, anchored** regex `^(pattern)$` against `input.tool` — which is OpenCode's *lowercase* tool id | n/a | ⚠️ A CC-style `"Bash"` matcher does **not** hit OpenCode's `bash` tool; use lowercase matchers (`bash\|write\|edit\|read`) for OpenCode entries (or keep a separate OpenCode section) |

##### MCP tools — separators differ per host

MCP-backed tools get server-prefixed names, and the separator is **not the same everywhere** (all examples are official):

| Host | MCP tool-name format | Official examples |
| :--- | :--- | :--- |
| Claude Code | `mcp__<server>__<tool>` | `mcp__github__search_repositories`, `mcp__memory__.*` |
| OpenAI Codex | `mcp__<server>__<tool>` | `mcp__filesystem__read_file`, `mcp__filesystem__.*` |
| CodeBuddy / WorkBuddy | `mcp__<server>__<tool>` | `mcp__memory__.*`, `mcp__.*__write.*` |
| Gemini CLI | `mcp_<server>_<tool>` (**single** underscore) | reference matcher docs |
| Google Antigravity | not documented for MCP (matcher is a plain tool-name regex) | — |
| OpenCode (bridge) | no native matcher; permission rules use `"mymcp_*": "ask"` wildcards; bridge matching of MCP `input.tool` unverified | — |

⚠️ Claude Code foot-gun, stated by the docs: to match every tool of one server
you must write `mcp__memory__.*` — a bare `mcp__memory` contains only
exact-match characters, is compared as an exact string, and matches nothing
("The `.*` is required"). The same applies to hyphenated server names
(`mcp__brave-search__.*`). On Gemini CLI use the single-underscore form.

##### A rule that needs no matcher knowledge — same file on every host

```js
export default function (ctx, sys) {
  // Command guard: ctx.cmd carries the text whether the host calls the tool
  // "Bash", "run_command" or "run_shell_command".
  if (ctx.cmd && /rm\s+-rf\s+(\/|\*)/.test(ctx.cmd)) {
    return { deny: "rm -rf on / or glob is forbidden" };
  }
  // File guard: action is normalized across hosts
  // (Write / write_file / write_to_file / write → "write").
  if (ctx.file && ctx.file.action === "write" &&
      /\.(env|pem|p12|pfx)$/i.test(ctx.file.path || "")) {
    return { deny: "Refusing to overwrite a secret file: " + ctx.file.path };
  }
  return null;
}
```

Per-host wiring for that rule (wide matcher, one entry per event you guard):

```jsonc
// Claude Code — .claude/settings.json / ~/.claude/settings.json
{ "hooks": { "PreToolUse": [ { "matcher": "Bash|PowerShell|Write|Edit",
    "hooks": [{ "command": "ai-hook ./rules/guard.js" }] } ] } }
// Codex — ~/.codex/hooks.json
{ "hooks": { "PreToolUse": [ { "matcher": "^(Bash|Write|Edit)$",
    "hooks": [{ "command": "ai-hook ./rules/guard.js" }] } ] } }
// CodeBuddy — ~/.codebuddy/settings.json
{ "hooks": { "PreToolUse": [ { "matcher": "^Bash$|^Write$|^Edit$",
    "hooks": [{ "command": "ai-hook ./rules/guard.js" }] } ] } }
// Antigravity — .agents/hooks.json (top-level hook name, optional enabled)
{ "ai-hook-gate": { "enabled": true, "PreToolUse": [
    { "matcher": "run_command|write_to_file|replace_file_content",
      "hooks": [{ "command": "ai-hook ./rules/guard.js" }] } ] } }
// Gemini CLI — ~/.gemini/settings.json (BeforeTool; timeout is in ms)
{ "hooks": { "BeforeTool": [ { "matcher": "run_shell_command|write_file|replace",
    "hooks": [{ "type": "command", "command": "ai-hook ./rules/guard.js",
                "timeout": 10000 }] } ] } }
// OpenCode — via the bridge: reuse the Claude Code config, but lowercase
// the matcher values for the built-in ids (bash|write|edit|read|…).
```

##### Common mistakes

1. **Copying a matcher across hosts verbatim.** `run_command` never fires on
   Claude Code; `Bash` never fires on Gemini CLI (its shell tool is
   `run_shell_command`) — names *and* syntax differ per host.
2. **Exact vs containment.** CC `"Write"` is an exact tool-name match; CB
   `"Write"` matches any name *containing* "Write" (anchor it); OpenCode's
   bridge is case-sensitive against lowercase ids — a CC-style `"Bash"`
   matcher silently matches nothing there.
3. **Matchers are per event.** Guarding `PreToolUse` does not configure
   `PostToolUse` or `UserPromptSubmit` — add one entry per event you care about.
4. **Events that ignore matchers fire unconditionally** (Codex
   UserPromptSubmit/Stop/Interrupt; AGY Stop/PreInvocation/PostInvocation): the
   hook still runs — filter inside the rule (`ctx.event`, prompt, payload),
   do not expect the host not to call you.
5. **In rules, prefer `ctx.file.action` / `ctx.cmd` over `ctx.tool === "Write"`**:
   one logical file write is `Write` (CC/CB), `apply_patch` (Codex),
   `write_to_file` (AGY), `write_file` (Gemini) and `write` (OpenCode).

### 2. `sys` Native Microsecond Primitives & Safe Extensions

Subprocess spawning is eliminated for standard reads. In addition, command execution and synchronous HTTP requests are provided for zero-token intercepts and integrations. ⚠️ `sys.exec` / `sys.http` escape the QuickJS sandbox (arbitrary processes / arbitrary network) — use them only when the rule source is trusted:

| Method / Property | Return Type | Description & Latency |
| :--- | :--- | :--- |
| `sys.git.branch()` | `string?` | In-engine pure-memory parse of `.git/HEAD` for the current branch (e.g. `"master"`), 0 subprocesses |
| `sys.git.root()` | `string?` | Root directory path of current Git repository |
| `sys.fs.exists(path)` | `boolean` | In-engine existence check for relative/absolute paths (resolved against `ctx.cwd`) |
| `sys.fs.readText(path)` | `string?` | In-engine native file read (e.g. `.env`, `package.json`) |
| `sys.fs.list([dir])` | `string[]` | List files and directories in path |
| `sys.env("KEY")` | `string?` | **< 1 µs** get environment variable |
| `sys.ruleDir` | `string` | Absolute directory path of the executing rule script |
| `sys.rulePath` | `string` | Absolute file path of the executing rule script |
| `sys.exec(target, args?, opt?)` | `object` | **Universal Execution Engine (macOS/Linux/Windows, 0 hardcoded paths)**: executes system commands in PATH, native binaries (ELF/Mach-O/PE exe directly executed), scripts and Shebangs (`#!/bin/sh`, `#!/usr/bin/env bash/zsh/python3/node`, etc. adaptively dispatched based on system environment without single-shell binding); supports `cwd`/`env`/`input`/`timeout` (ms, default 10000 — the process group is killed and `ok:false` returned on expiry); returns `{ code, ok, stdout, stderr }` |
| `sys.http.get(url, opt?)` | `object` | **Lightweight HTTP GET**: supports `headers`/`timeout`, returns `{ status, ok, headers, body }` |
| `sys.http.post(url, opt?)` | `object` | **Lightweight HTTP POST**: supports `headers`/`body`/`timeout`, returns `{ status, ok, headers, body }` |
| `console.log(...)` | `void` | Debug logging to stderr (never corrupts decision JSON) |
| `sys.log(level, ...)` | `void` | Structured logging to stderr **and** `~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log` (JSONL; disk writes happen only when a rule logs; keeps latest 14 files by default; disable `AI_HOOK_LOG=0`, override `AI_HOOK_LOG_FILE`, configure retention via `AI_HOOK_LOG_MAX_FILES`) |
| **Standard JS builtins** | - | `new Date()` clock (days, hours, freeze windows), `JSON` / `RegExp` / `Math` / `Map` / `Set` are QuickJS builtins — no sys needed; sys only adds the I/O that JS has no primitive for |

### 3. `aiHook` — Shared Rule-Parsing Prelude (Global, Pure Functions, Zero I/O)

Command-text rules used to copy their own helpers (the same `splitTopCommands` had been duplicated across seven rules and had already diverged). The engine now injects a global `aiHook` **before each rule runs**, exposing a set of **pure, stateless, zero-I/O** parsing primitives. Call them directly and **never redefine them inside a rule** (quote handling follows bash):

| Method | Returns | Description |
| :--- | :--- | :--- |
| `aiHook.splitTopCommands(cmd, opt?)` | `string[]` | **Quote-aware top-level segmentation**: splits on `&&` `\|\|` `;` and newlines, never inside quotes (a backslash escapes inside `"…"`, stays literal inside `'…'`); a single `\|` is not a separator by default (keeps `echo ... \| mysql` pipe-flow detection intact); `opt.splitPipe = true` also splits on a single pipe (rm-root semantics) |
| `aiHook.flatten(cmd)` | `string` | Collapse a multi-line command to one line (newlines→spaces) so downstream regex and quote state do not straddle lines |
| `aiHook.isSearchPrefix(seg)` | `boolean` | Search-style prefix (`grep`/`rg`/`git`/`find`/`cat`/`head`/`tail`/`sed`/`awk`/`echo`/`printf`) — "only talks"; a keyword inside is not an execution |
| `aiHook.isGitCommit(seg)` | `boolean` | `git commit` segment: its message is descriptive text (not SQL/Redis/file access) |
| `aiHook.hasCmdSubstitution(seg)` | `boolean` | Contains command substitution `$(` — undecidable statically, so default to asking |
| `aiHook.hasWriteVector(cmd)` | `boolean` | Write vector: redirect to disk `>` / `>>` (`2>&1` allowed) or a pipe into `tee` |

> Division of labour: `ctx` describes the **host input**, `sys` provides **I/O capabilities**, `aiHook` provides **pure text parsing**. Use `sys.exec` / `sys.http` only when the rule source is trusted; `aiHook` is pure and never escapes the sandbox.

### 4. Controlling Decisions: Hard Block vs GUI Prompt vs Zero-Token Intercept

Your rule's return object determines the exact action:

#### Scenario A: Direct Hard Block (No Popup)
For destructive actions that should **never be executed without question**:
```javascript
return {
  deny: "【Hard Block】Force-pushing to production branch is strictly forbidden!"
};
```
> **Behavior**: `ai-hook` immediately outputs a rejection to the agent with the reason. **No dialog is ever displayed.**

#### Scenario B: Modern Fluent Card GUI Popup
For sensitive operations that require human review:
```javascript
return {
  ask: "Database reset command detected. Existing tables will be wiped!",
  title: "Database Reset Authorization", // Custom dialog title
  gui: true,                     // Force the desktop dialog (pierces --no-gui; unset by default)
  timeout: 45                    // Custom countdown in seconds (auto-denies on timeout)
};
```
> **Behavior**: A sleek floating card pops up. Clicking "Allow" or pressing `Enter` permits execution. Clicking "Deny", pressing `Esc`, or timing out aborts the command.

#### Scenario C: Terminal-Only Confirmation (No GUI)
Delegate confirmation to the Agent CLI interface (e.g. Claude Code `(y/n)` prompt). If the host cannot ask (no ask channel in its protocol), the command is auto-denied instead — fail-closed:
```javascript
return {
  ask: "Release publishing detected. Proceed?",
  gui: false // No dialog: terminal ask when the host supports it, auto-deny otherwise
};
```

#### Scenario D: Zero-Token Local Intercept (UserPromptSubmit)
For user prompts that can be answered immediately locally (e.g. `/ai:balance`, `/ai:usage`):
```javascript
return {
  deny: "Balance: $100.00" // Displayed directly to user without LLM inference
};
```
> **Behavior**: Outputs `{"decision":"block","reason":"..."}` to halt LLM invocation and return local results directly.

#### Scenario E: PostToolUse Context & Guideline Injection
Inject guidelines or reminders after a tool finishes (e.g. after editing migration files):
```javascript
return {
  inject: "Migration file was edited. Ensure models and test suites are updated!"
};
```
> **Behavior**: Outputs `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"..."}}`.

#### Scenario F: Safe Pass
```javascript
return null; // or return { allow: true };
```

> **Rule failure handling (fail-closed)**: if any rule fails — syntax error, runtime exception, infinite-loop timeout, or a returned Promise (async) — ai-hook **denies** the command by default and returns the rule error as the reason; a broken gate never silently opens. Every rule has a 5s execution watchdog that interrupts runaway loops. To opt in to allow-on-error, pass `--allow-on-error` or set `AI_HOOK_ALLOW_ON_ERROR=1` (not recommended for production gates).
> **Output language**: dialogs, messages and logs follow the system language (Windows user locale / `LANG`); force it with `AI_HOOK_LANG=zh|en`. `ai-hook tutorial` also follows the system language by default (`--lang en|zh` overrides).


---

## 💡 Rule Demos

Every demo below is a real, loadable rule file in [`examples/`](examples/). Drop
one into your host config (`ai-hook examples/01_basic_regex.js`) and watch it
guard the tools listed in §1.2 — the same file works on every agent. The files
in `examples/` are the single source of truth; if an embedded copy ever drifts,
trust the file.

### Demo 01 — High-risk command interception (`examples/01_basic_regex.js`)

Regex guards against destructive commands: hard-deny `rm -rf /` (and drive
roots), ask-confirm for Redis `FLUSHALL`/`FLUSHDB`:

```js
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // 1. Block root deletion (绝对禁止删除根目录或盘符根)
  if (/rm\s+-rf\s+(\/|[a-zA-Z]:[/\\]|\*|\/\*)(\s+|$)/i.test(cmd)) {
    return {
      deny: "【硬阻断】严禁在 Agent 中执行整盘或根目录物理删除命令！"
    };
  }

  // 2. Confirm Redis flushall/flushdb (清空缓存需要确认)
  if (/\b(FLUSHALL|FLUSHDB)\b/i.test(cmd)) {
    return {
      ask: "检测到清空全库 Redis 缓存操作，请确认环境与影响范围。"
    };
  }

  // Pass (放行)
  return null;
}
```

### Demo 02 — Time-window & freeze-period control (`examples/02_time_freeze.js`)

Autonomous time via plain `new Date()`: blocks production DB resets on Friday
16:00+ (release freeze) and on configured holiday dates:

```js
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";
  const now = new Date();
  const dayOfWeek = now.getDay(); // 0 is Sunday, 5 is Friday
  const hour = now.getHours();

  // 1. Friday 16:00+ Deployment Freeze (周五下午 16:00 后禁止生产环境数据库迁移)
  if (dayOfWeek === 5 && hour >= 16) {
    if (/migrate:(fresh|reset|refresh)|db:wipe/i.test(cmd)) {
      return {
        deny: `【封网期保护】当前为周五下午 (${hour}:00)，系统处于发布封网期，严禁执行数据库重置或迁移！`
      };
    }
  }

  // 2. Specific calendar freeze dates (特定节假日封网日期)
  // Local date string, NOT toISOString(): that one is UTC and would drift a
  // day ahead of `getHours()` above for any timezone east of UTC.
  const todayStr = `${now.getFullYear()}-` +
    `${String(now.getMonth() + 1).padStart(2, "0")}-` +
    `${String(now.getDate()).padStart(2, "0")}`; // e.g. "2026-10-01"
  const freezeDates = ["2026-10-01", "2026-10-02", "2026-10-03"];

  if (freezeDates.includes(todayStr) && /production|prod/i.test(cmd)) {
    return {
      deny: `【节日封网】当前处于重要保障期(${todayStr})，禁止任何生产环境变更操作！`
    };
  }

  return null;
}
```

### Demo 03 — Git branch-aware protection (`examples/03_git_branch.js`)

`sys.git.branch()` reads `.git/HEAD` in pure memory (0 subprocesses): block
force-push (`-f`/`--force`/`--force-with-lease`) on `master`/`main`:

```js
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // Check if current command is a git push
  if (/git\s+push\b/i.test(cmd)) {
    // Autonomously query current Git branch
    const currentBranch = sys.git.branch();
    console.log("Current Git branch:", String(currentBranch));

    if (currentBranch === "master" || currentBranch === "main") {
      // Check for force push flags
      if (/\s+(-f|--force|--force-with-lease)\b/.test(cmd)) {
        return {
          deny: `【分支安全门禁】当前处于核心生产分支 '${currentBranch}'，严禁执行强制推送操作！`
        };
      }
    }
  }

  return null;
}
```

### Demo 04 — Config & privileged-account control (`examples/04_env_context.js`)

`sys.fs.exists()` / `sys.fs.readText()` read the local `.env` (page-cache fast,
no app-level cache): require confirmation before the privileged DB account
`xrapp_prod` is used, and hard-deny destructive migrations when the local
`.env` binds production:

```js
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // 1. Check if database client is invoked
  if (/\b(mysql|mariadb|psql)\b/i.test(cmd)) {
    // 2. Privilege account check: xrapp_prod
    if (/(-u\s*|--user(=|\s+))xrapp_prod\b/i.test(cmd) || /psql.*-U\s*xrapp_prod\b/i.test(cmd)) {
      // Exclude readonly account
      if (!cmd.includes("xrapp_prod_readonly")) {
        return {
          ask: "【生产特权写账户门禁】动用生产主账户 xrapp_prod 访问数据库，请核验 SQL 影响并确认！"
        };
      }
    }
  }

  // 3. Project .env protection: if local .env connects to production, forbid destructive migration
  if (sys.fs.exists(".env")) {
    const envContent = sys.fs.readText(".env") || "";
    if (envContent.includes("APP_ENV=production") || envContent.includes("DB_DATABASE=xrapp_prod")) {
      if (/\b(migrate:fresh|migrate:reset|db:wipe)\b/i.test(cmd)) {
        return {
          deny: "【灾难防御】当前工作区 .env 绑定生产数据库，物理级严禁执行清库与重置迁移！"
        };
      }
    }
  }

  return null;
}
```

### Demo 05 — All features in one file (`examples/demo_all_features.js`)

`demo_all_features.js` walks every capability end to end — platform/raw/args
context, `sys` autonomous reads, and all four decision styles (hard `deny`,
GUI `ask(gui:true)`, terminal `ask(gui:false)`, prompt intercept, `inject`).
Source is linked above; run it against any host:

```bash
# Replay "git push --force" as if fired by each host, print the exact JSON:
ai-hook test --platform antigravity "git push origin master --force" examples/demo_all_features.js
ai-hook test --platform gemini       "git push origin master --force" examples/demo_all_features.js
ai-hook test --platform codex        "git push origin master --force" examples/demo_all_features.js
ai-hook test --platform opencode     "git push origin master --force" examples/demo_all_features.js
```

---
## 🛠️ CLI Reference

```bash
# 1. Inspect specified rule scripts
ai-hook list ./rules/rule1.js ./rules/rule2.js

# 2. Test a simulated command against rules with microsecond profiling
ai-hook test "git push origin master --force" ./examples/demo_all_features.js

#    Replay the same rule against another host's envelope (default: claude_code;
#    also codex / codebuddy / workbuddy / gemini / antigravity / opencode).
#    Prints the exact JSON that host would receive.
ai-hook test --platform gemini "npm run build" ./examples/demo_all_features.js

# 3. Run high-iteration benchmark across specified rules
ai-hook bench -i 1000 -c "git status" ./examples/demo_all_features.js

# 4. Install as a global system command (auto-detects existing PATH directory with 0 env pollution)
ai-hook install

# 5. One-command self-update to latest GitHub release
ai-hook update

# 6. View built-in interactive tutorial and rule authoring guide
ai-hook tutorial
ai-hook tutorial --lang en

# 7. Actively clean and prune historical log files (keeps latest 14 files per category by default; alias: ai-hook prune)
ai-hook clean
ai-hook clean --max-files 7
ai-hook clean --dry-run

# Force download and replace even if on the same version
ai-hook update --force
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
