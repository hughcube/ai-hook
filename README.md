# ai-hook — Unified Multi-Agent Security Interceptor & Autonomous Rule Dispatcher

[![CI](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml/badge.svg)](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hughcube/ai-hook)](https://github.com/hughcube/ai-hook/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Ultra-Fast (2~3ms) end-to-end, Zero Variable Pollution, Single-Process Closed-Loop, Autonomous Rule-Driven** Next-Gen Security Base for AI Agents.  
> Purpose-built for **Google Antigravity**, **Claude Code**, **CodeBuddy**, and **OpenAI Codex**.

English Documentation | [简体中文文档](README_zh.md)

---

## 📖 Motivation & Problem Statement

In multi-agent collaborative development ecosystems, preventing destructive operations (e.g. `rm -rf /`, unexpected `migrate:fresh`, cache wiping `FLUSHALL`, or secret leakage) is paramount. However, traditional shell-based hook mechanisms suffer from fundamental bottlenecks:

1. **Process Explosion & Noticeable Lag**: Each plugin maintaining independent Bash scripts means spawning 10+ sequential processes on Windows, causing jarring **500~750ms** pauses for every single tool invocation;
2. **Variable Pollution & State Drift**: Sourcing multiple scripts in a shared environment leads to leaked environment variables, overridden functions, and working directory drift;
3. **The Trap of Forced Script Concatenation**: Trying to speed things up by physically merging scripts into one massive monolithic bundle drastically escalates maintenance complexity;
4. **Rigid Rules Lacking Autonomous Context**: Static regex hooks cannot dynamically handle real-world needs like *"forbid production writes after 16:00 on Fridays"*, *"block force-push when on master branch"*, or *"inspect project-level .env config"*.

**`ai-hook` solves these problems once and for all**: A single, standalone native binary written in Rust serves as the central dispatcher. With an embedded lightweight QuickJS engine, every plugin's rules execute in physically isolated sandboxes while **autonomously acquiring their own prerequisite data** with microsecond latency.

---

## ⚡ Architecture Overview

```
[Agent Tool Invocation (run_command / write_to_file / ...)]
                       │
                       ▼ (stdin: JSON payload)
┌─────────────────────────────────────────────────────────────┐
│             Central Dispatcher Binary: ai-hook.exe          │
│   (Rust Native / Statically Linked / 0 External Deps / ~2ms)│
│                                                             │
│  1. Fast Path Short-Circuit:                                │
│     Read-only safe commands (git status, ls, pwd) exit in   │
│     < 0.01ms without loading JS VM                          │
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
│     - sys.git.branch(): Pure memory .git/HEAD read (0.02ms) │
│     - sys.fs.readText(): Native Rust file I/O (0.01ms)      │
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
  - Pure Rust native PE binary; cold startup takes only **1.5ms** on Windows.
  - Safe read-only commands short-circuit via Fast Path in **< 0.01ms**.
  - Complete multi-rule evaluation finishes in **1.3ms** (a **500x speedup** over legacy Bash hooks).
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

## 📊 Performance Benchmarks (Windows 11 x64)

| Metric | Legacy Bash Hooks (10 scripts) | ai-hook (Rust + Autonomous Rules) | Improvement |
| :--- | :--- | :--- | :--- |
| **Process Count** | **10** `bash.exe` instances | **Strictly 1** `ai-hook.exe` | **-90% processes** |
| **Read-only Commands** | 420ms ~ 750ms | **< 0.02 ms** (Fast Path) | **20,000x faster** |
| **End-to-End Evaluation**| 500ms ~ 750ms (noticeable stutter) | **1.34 ms** (1/10th of a 60fps frame) | **500x faster** |
| **Duplicate File I/O** | Multiple redundant reads | **0** (Request-Scoped Memory Cache) | Instant memory hit |
| **GUI Popup Launch** | ~300ms (PowerShell cold start) | **Immediate / Native** | Desktop responsive |

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

### 2. AI Dependency Management & Shell Integration

`ai-hook` serves as the primary security guardrail in multi-agent workflows. We recommend configuring a unified AI dependency self-test function in your `~/.zshrc` or `~/.bashrc` (with `ai-hook` as the first baseline dependency):

```bash
# 1. Convenient command alias (optional)
alias ai:hook="ai-hook"

# 2. Automated AI environment dependency doctor (recommended in ~/.zshrc)
# Automatically checks and installs/updates local AI toolchain dependencies
ai:doctor() {
  echo "🔍 Checking local AI toolchain dependencies & security hook dispatcher..."
  if ! command -v ai-hook >/dev/null 2>&1; then
    echo "⚠️  ai-hook not found. Automatically downloading and installing globally..."
    if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "win32"* ]]; then
      mkdir -p "$HOME/.local/bin"
      curl -fsSL "https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.exe" -o "$HOME/.local/bin/ai-hook.exe"
    else
      local os="$(uname -s | tr '[:upper:]' '[:lower:]')"
      local mach="$(uname -m)"
      case "$os:$mach" in
        darwin:arm64|darwin:aarch64) local asset="ai-hook-darwin-aarch64" ;;
        darwin:x86_64)               local asset="ai-hook-darwin-x86_64" ;;
        linux:x86_64)                local asset="ai-hook-linux-x86_64" ;;
        *) echo "Unsupported platform: $os-$mach. Download manually or build from source."; return 1 ;;
      esac
      local target_bin="/usr/local/bin/ai-hook"
      [[ ! -w "/usr/local/bin" ]] && target_bin="$HOME/.local/bin/ai-hook"
      mkdir -p "$(dirname "$target_bin")"
      curl -fsSL "https://github.com/hughcube/ai-hook/releases/latest/download/${asset}" -o "$target_bin" && chmod +x "$target_bin"
    fi
    echo "✨ ai-hook successfully installed!"
  else
    echo "✓ ai-hook is ready: $(which ai-hook 2>/dev/null || command -v ai-hook) ($(ai-hook --version 2>/dev/null))"
  fi
  # Extend additional AI tool dependencies here in the future...
}
```

### 3. Register in Agent Configurations (Supports Multiple Scripts)

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
| `sys.git.branch()` | `string?` | **0.02ms** memory parse of `.git/HEAD` for current branch (e.g. `"master"`) |
| `sys.git.root()` | `string?` | Root directory path of current Git repository |
| `sys.git.status()` | `string` | Quick status summary |
| `sys.fs.exists(path)` | `boolean` | **0.01ms** check if file or directory exists (request-scoped cached) |
| `sys.fs.readText(path)` | `string?` | **0.01ms** read file text (cached in request-scoped memory) |
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
