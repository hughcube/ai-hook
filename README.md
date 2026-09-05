# ai-hook — Unified Multi-Agent Security Interceptor & Autonomous Rule Dispatcher

[![CI](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml/badge.svg)](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hughcube/ai-hook)](https://github.com/hughcube/ai-hook/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **It exists for two things: hiding complexity, and making rules pleasant to write.**  
> **① Hide the complexity** — hook-protocol differences across agents, platform quirks, and subprocess/context-fetching plumbing are all wrapped into one native binary: the same rules are written once and run everywhere, with no per-agent, per-platform script matrix. On Windows it also collapses the old one-process-per-fetch stutter into a single process with millisecond-scale in-process evaluation.  
> **② Better rule authoring** — a rule is just plain JS: a rich `ctx` context, native microsecond `sys` primitives, one uniform deny/confirm/block decision protocol with desktop/terminal interaction, plus `list`/`test`/`bench`/`tutorial` tooling — instead of hand-written shell glue and cross-platform trial and error.  
> Zero variable pollution, a single-process closed loop, and extreme speed all fall out of this design.  
> Hooks for **Claude Code**, **Google Antigravity**, **CodeBuddy**, and **OpenAI Codex** — one rule set, every agent, on Windows / macOS / Linux.

English Documentation | [简体中文文档](README_zh.md)

---

## 📖 Motivation & Problem Statement

Hooks sit on the **hot path** of every tool invocation — they guard before a tool runs and wrap up after it finishes. To defend against destructive operations (e.g. `rm -rf /`, unexpected `migrate:fresh`, cache wiping `FLUSHALL`, or secret leakage), multi-agent and plugin-heavy ecosystems traditionally make each plugin write its own script: on Windows that drags the high-frequency path into jarring stutter, and on every platform those scripts end up as islands that cannot be shared across agents or platforms. Legacy hook mechanisms therefore suffer from four fundamental problems:

1. **Process Explosion & Noticeable Lag**: Each plugin maintaining independent Bash scripts means spawning 10+ sequential processes on Windows, causing jarring **500~750ms** pauses for every single tool invocation;
2. **Variable Pollution & State Drift**: Sourcing multiple scripts in a shared environment leads to leaked environment variables, overridden functions, and working directory drift;
3. **The Trap of Forced Script Concatenation**: Trying to speed things up by physically merging scripts into one massive monolithic bundle drastically escalates maintenance complexity;
4. **Rigid, Non-Autonomous Rules**: Traditional hooks *can* reach this context — `date` for time, `git branch` for branches, `cat .env` for local config, `curl` for the network — but wiring it into a rule means writing glue by hand. On **Windows**, each fetch spawns a fresh subprocess whose cold start is expensive, so multiple rules compound into visible stutter. On **every platform**, you still face: hand-rolled regex parsing of command output, shell syntax that is not portable across platforms, zero caching between rules in the same request, a `curl` without a timeout that hangs the whole gate — and that glue must be **re-written for every agent**. So dynamic rules like *"no production writes after 16:00 on Friday"*, *"block force-push on master"*, or *"honor the local `.env`"* are **hard to write and impossible to share**, and in practice collapse into static regexes and path matching.

**`ai-hook` solves these problems once and for all**: A single, standalone native binary written in Rust serves as the central dispatcher. With an embedded lightweight QuickJS engine, every plugin's rules execute in physically isolated sandboxes while **autonomously acquiring their own prerequisite data** with microsecond latency — local context (time/branch/config) is read through native APIs with request-scoped caching, so rules contain no shell glue and spawn no subprocesses, behaving identically on every platform (and sidestepping Windows' expensive subprocess cold starts). Remote context such as network probes goes through the built-in `sys.http` exit — no `curl` subprocess spawn, round-trip latency unchanged, timeout required to avoid hangs.

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
│     - Request-Scoped Cache: Automatic single-disk read      │
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
    - **Configuration Inspection**: `sys.fs.readText(".env")` with request-scoped caching.
- ⏱️ **Native 60-Second Countdown Docked Dialog**:
  - In unattended / skip-permissions (YOLO) mode, `ai-hook` presents a native topmost window with a 60s countdown, docked action buttons, and scrollable command inspection.
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
| **Rule evaluation (in-process)** | Re-spawns `date`/`git`/`cat`/`curl` per rule | Native `sys` reads + request-scoped cache; <1ms per rule, ~0.2ms per extra rule | Measured engine-side |
| **GUI popup** | Spawns PowerShell, ~300ms cold start | Raised natively in-process | No second process |

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
Configure in `~/.gemini/config/hooks.json`:
```json
{
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

### 4. Modern Adaptive Dialog & Timeout Configuration

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
| `ctx.agent` | `string` | Detected host: `"antigravity"` / `"claude_code"` / `"codebuddy"` / `"codex"` / `"generic"` |
| `ctx.mode` | `string?` | Host permission mode: `default`/`plan`/`acceptEdits`/`dontAsk`/`bypassPermissions` |
| `ctx.isYolo` | `boolean` | No-confirm mode (auto-detects `AGY_DANGEROUSLY_SKIP_PERMISSIONS` and `CODEX_DANGEROUSLY_SKIP_PERMISSIONS`, or mode bypassPermissions/dontAsk) |
| `ctx.event` | `string?` | Lifecycle event name: `"PreToolUse"` / `"PostToolUse"` / `"UserPromptSubmit"` |
| `ctx.prompt` | `string?` | User raw prompt text (provided in `UserPromptSubmit` prompt intercept events) |
| `ctx.session` | `{id, transcriptPath}?` | Session id + full transcript path (read with `sys.fs.readText`) |
| `ctx.cwd` | `string` | Session/command working directory |
| `ctx.model` | `string?` | Host model id (e.g. Antigravity `modelName`) |
| `ctx.tool` | `string` | Host tool name verbatim (`"Bash"`/`"run_command"`/`"Write"`…) |
| `ctx.cmd` | `string?` | Command tools only; `null` otherwise |
| `ctx.file` | `{path, action}?` | File tools only; `action`: `read`/`write`/`edit`/`delete`/`list` |
| `ctx.args` | `object` | Host tool arguments verbatim (`{command}`, `{file_path, content}`, …) |
| `ctx.raw` | `object` | Full original host payload (always available) |
| `ctx.rawInput` | `string` | Raw payload text |
> Design rule: one semantic per property, no aliases; `cmd`/`file` are `null` when not applicable — guard rules with truthiness checks.

### 2. `sys` Native Microsecond Primitives & Safe Extensions

Subprocess spawning is eliminated for standard reads. In addition, controlled command execution and synchronous HTTP requests are provided for zero-token intercepts and integrations:

| Method / Property | Return Type | Description & Latency |
| :--- | :--- | :--- |
| `sys.git.branch()` | `string?` | In-engine pure-memory parse of `.git/HEAD` for the current branch (e.g. `"master"`), 0 subprocesses |
| `sys.git.root()` | `string?` | Root directory path of current Git repository |
| `sys.git.status()` | `string` | Quick status summary |
| `sys.fs.exists(path)` | `boolean` | In-engine existence check for relative/absolute paths (request-scoped cached) |
| `sys.fs.readText(path)` | `string?` | In-engine native file read (e.g. `.env`, `package.json`), request-scoped cached |
| `sys.fs.list([dir])` | `string[]` | List files and directories in path |
| `sys.env("KEY")` | `string?` | **< 1 µs** get environment variable (or `sys.env.get("KEY")`) |
| `sys.cwd()` | `string` | Current working directory |
| `sys.ruleDir` / `sys.__dirname` | `string` | Absolute directory path of the executing rule script |
| `sys.rulePath` / `sys.__filename` | `string` | Absolute file path of the executing rule script |
| `sys.exec(target, args?, opt?)` | `object` | **Universal Execution Engine (macOS/Linux/Windows, 0 hardcoded paths)**: executes system commands in PATH, native binaries (ELF/Mach-O/PE exe directly executed), scripts and Shebangs (`#!/bin/sh`, `#!/usr/bin/env bash/zsh/python3/node`, etc. adaptively dispatched based on system environment without single-shell binding); returns `{ code, status, exitCode, stdout, stderr, success }` |
| `sys.http.get(url, opt?)` | `object` | **Lightweight HTTP GET**: supports `headers`/`timeout`, returns `{ status, ok, headers, body }` |
| `sys.http.post(url, opt?)` | `object` | **Lightweight HTTP POST**: supports `headers`/`body`/`timeout`, returns `{ status, ok, headers, body }` |
| `console.log(...)` | `void` | Debug logging to stderr (never corrupts decision JSON) |
| `sys.log(level, ...)` | `void` | Structured logging to stderr **and** `~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log` (JSONL; disk writes happen only when a rule logs; disable `AI_HOOK_LOG=0`, override `AI_HOOK_LOG_FILE`) |
| **Standard JS Clock** | - | `new Date()` for days, hours, freeze windows |

### 3. Controlling Decisions: Hard Block vs GUI Prompt vs Zero-Token Intercept

Your rule's return object determines the exact action:

#### Scenario A: Direct Hard Block (No Popup)
For destructive actions that should **never be executed without question**:
```javascript
return {
  action: "deny", // or "block", "reject"
  reason: "【Hard Block】Force-pushing to production branch is strictly forbidden!"
};
```
> **Behavior**: `ai-hook` immediately outputs a rejection to the agent with the reason. **No dialog is ever displayed.**

#### Scenario B: Modern Fluent Card GUI Popup
For sensitive operations that require human review:
```javascript
return {
  action: "confirm",             // Trigger confirmation gate
  title: "Database Reset Authorization", // Custom dialog title
  reason: "Database reset command detected. Existing tables will be wiped!",
  gui: true,                     // Pop up modern floating card dialog (default: true)
  timeout: 45                    // Custom countdown in seconds (auto-denies on timeout)
};
```
> **Behavior**: A sleek floating card pops up. Clicking "Allow" or pressing `Enter` permits execution. Clicking "Deny", pressing `Esc`, or timing out aborts the command.

#### Scenario C: Terminal-Only Confirmation (No GUI)
Delegate confirmation to the Agent CLI interface (e.g. Claude Code `(y/n)` prompt):
```javascript
return {
  action: "confirm",
  reason: "Release publishing detected. Proceed?",
  gui: false // Disables GUI dialog, falls back to terminal prompt
};
```

#### Scenario D: Zero-Token Local Intercept (UserPromptSubmit)
For user prompts that can be answered immediately locally (e.g. `/ai:balance`, `/ai:usage`):
```javascript
return {
  action: "block",
  reason: "Balance: $100.00" // Displayed directly to user without LLM inference
};
```
> **Behavior**: Outputs `{"decision":"block","reason":"..."}` to halt LLM invocation and return local results directly.

#### Scenario E: PostToolUse Context & Guideline Injection
Inject guidelines or reminders after a tool finishes (e.g. after editing migration files):
```javascript
return {
  additionalContext: "Migration file was edited. Ensure models and test suites are updated!"
};
```
> **Behavior**: Outputs `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"..."}}`.

#### Scenario F: Safe Pass
```javascript
return null; // or return { action: "allow" };
```

> **Rule failure handling (fail-closed)**: if any rule fails — syntax error, runtime exception, infinite-loop timeout, or a returned Promise (async) — ai-hook **denies** the command by default and returns the rule error as the reason; a broken gate never silently opens. Every rule has a 5s execution watchdog that interrupts runaway loops. To restore the legacy allow-on-error behavior, pass `--allow-on-error` or set `AI_HOOK_ALLOW_ON_ERROR=1` (not recommended for production gates).
> **Output language**: dialogs, messages and logs follow the system language (Windows user locale / `LANG`); force it with `AI_HOOK_LANG=zh|en`. `ai-hook tutorial` also follows the system language by default (`--lang en|zh` overrides).


---

## 💡 Comprehensive Feature Demo

See [`examples/demo_all_features.js`](examples/demo_all_features.js) in the repository (single source of truth, not duplicated here). It demonstrates:
- Agent type, raw payload and tool-argument access (`ctx.agent` / `ctx.raw` / `ctx.args`);
- Autonomous `sys` data access (`sys.git.branch()` / `sys.fs.readText()` / `sys.env`);
- The three decision modes: hard `deny`, desktop popup `confirm(gui: true)`, terminal ask `confirm(gui: false)`.

---
## 🛠️ CLI Reference

```bash
# 1. Inspect specified rule scripts
ai-hook list ./rules/rule1.js ./rules/rule2.js

# 2. Test a simulated command against rules with microsecond profiling
ai-hook test "git push origin master --force" ./examples/demo_all_features.js

# 3. Run high-iteration benchmark across specified rules
ai-hook bench -i 1000 -c "git status" ./examples/demo_all_features.js

# 4. Install as a global system command (auto-detects existing PATH directory with 0 env pollution)
ai-hook install

# 5. One-command self-update to latest GitHub release
ai-hook update

# 6. View built-in interactive tutorial and rule authoring guide
ai-hook tutorial
ai-hook tutorial --lang en

# Force download and replace even if on the same version
ai-hook update --force
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
