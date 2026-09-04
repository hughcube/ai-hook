# ai-hook — Unified Multi-Agent Security Interceptor & Autonomous Rule Dispatcher

[![CI](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml/badge.svg)](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hughcube/ai-hook)](https://github.com/hughcube/ai-hook/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Ultra-Fast (1~2ms), Zero Variable Pollution, Single-Process Closed-Loop, Autonomous Rule-Driven** Next-Gen Security Base for AI Agents.  
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
│  3. Dynamic Rule Discovery (~/.agents/plugins/*/hooks/*.js):│
│     ┌───────────────────────────────────────────────────┐   │
│     │ Sandboxed Rule Execution (0 Variable Pollution):  │   │
│     │ - rd/protect-prod-db-write.js (Production write)  │   │
│     │ - xr/protect-prod-db-write.js (Whitelisted access)│   │
│     │ - dev/protect-db-migrate.js   (Migration guard)   │   │
│     │ - sys/protect-rm-root.js      (Root delete guard) │   │
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
# Windows (PowerShell): Download directly into official native app directory (Zero PATH setup needed)
Invoke-WebRequest -Uri "https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.exe" -OutFile "$env:LOCALAPPDATA\Microsoft\WindowsApps\ai-hook.exe"

# Linux: Download directly to system bin path
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86_64
chmod +x /usr/local/bin/ai-hook

# macOS (Apple Silicon M-series)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-aarch64
chmod +x /usr/local/bin/ai-hook

# macOS (Intel)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-x86_64
chmod +x /usr/local/bin/ai-hook
```

Or compile and install from source:

```bash
cargo install --path .
ai-hook install
```

### 2. Configure Shell Alias

Add the alias to your `~/.zshrc` or `~/.bashrc`:

```bash
alias ai:hook="ai-hook"
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
- **Topmost & Draggable**: Smooth mouse drag & drop anywhere on the card.

| Env Variable / CLI Option | Default | Description |
| :--- | :--- | :--- |
| `AI_HOOK_GUI_TIMEOUT` / `--timeout <N>` | `60` | Default countdown timeout in seconds (auto-denies on expiration) |
| `AI_HOOK_GUI` / `--no-gui` | `1` (enabled) | Set to `0` or `false` to disable the GUI dialog completely |

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

| Property | Type | Description |
| :--- | :--- | :--- |
| `ctx.agent` / `ctx.agentType` | `string` | **Current AI Agent**: `"antigravity"` (Google AGY), `"claude_code"` (Claude Code), `"codebuddy"` (CodeBuddy), `"codex"` (OpenAI Codex), `"generic"` (other) |
| `ctx.raw` | `object` | **Full raw payload** deserialized into a JS object (access any agent-specific nested properties) |
| `ctx.rawInput` | `string` | Raw unprocessed JSON payload string |
| `ctx.args` | `object` | **Tool arguments object** (e.g. `ctx.args.CommandLine`, `ctx.args.TargetFile`, `ctx.args.CodeContent`) |
| `ctx.tool` / `ctx.toolName` | `string` | Tool name being executed (e.g. `"run_command"`, `"write_to_file"`) |
| `ctx.cmd` | `string` | Command line string (for command execution tools; empty for others) |
| `ctx.file` / `ctx.targetFile` | `string` | Target file path (for file operations) |
| `ctx.cwd` | `string` | Current workspace absolute directory |
| `ctx.isYolo` | `boolean` | Whether skip-permissions/YOLO mode is active |
| `ctx.conversationId` | `string?` | Session conversation ID (if provided by agent) |

### 2. `sys` Native Microsecond Primitives

Subprocess spawning (`git.exe`) is eliminated. All prerequisite data is resolved in microseconds via native Rust memory APIs:

| Method | Return Type | Description & Latency |
| :--- | :--- | :--- |
| `sys.git.branch()` | `string?` | **0.02ms** memory parse of `.git/HEAD` for current branch (e.g. `"master"`) |
| `sys.git.root()` | `string?` | Root directory path of current Git repository |
| `sys.git.status()` | `string` | Quick status summary |
| `sys.fs.exists(path)` | `boolean` | **0.01ms** check if file or directory exists (request-scoped cached) |
| `sys.fs.readText(path)` | `string?` | **0.01ms** read file text (cached in request-scoped memory) |
| `sys.fs.list([dir])` | `string[]` | List files and directories in path |
| `sys.env("KEY")` | `string?` | **< 1 µs** get environment variable (or `sys.env.get("KEY")`) |
| `sys.cwd()` | `string` | Current working directory |
| `console.log(...)` | `void` | Debug logging redirected to stderr (does not corrupt decision JSON) |
| **Standard JS Clock** | - | `new Date()` for days, hours, freeze windows |

### 3. Controlling Decisions: Hard Block vs GUI Prompt vs Terminal Ask

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

#### Scenario D: Safe Pass
```javascript
return null; // or return { action: "allow" };
```

---

## 💡 Comprehensive Feature Demo

See [`examples/demo_all_features.js`](examples/demo_all_features.js) for an end-to-end example:

```javascript
/**
 * demo_all_features.js - Comprehensive ai-hook rule showcase
 */
export default function(ctx, sys) {
  // 1. Inspect agent & tool
  console.log(`[Demo] Agent: ${ctx.agent}, Tool: ${ctx.tool}`);

  // 2. Fatal command: Hard block without popup
  if (ctx.cmd && /git\s+push\b.*(-f|--force)\b/.test(ctx.cmd)) {
    const branch = sys.git.branch();
    if (branch === "master" || branch === "main") {
      return {
        action: "deny",
        reason: `【Hard Block】Force-push to '${branch}' forbidden!`
      };
    }
  }

  // 3. Sensitive operation: Pop up modern Fluent card
  if (ctx.cmd && /\b(migrate|wipe|reset)\b/i.test(ctx.cmd)) {
    return {
      action: "confirm",
      title: "Database Modification Authorization",
      reason: "Destructive migration detected. Existing data may be lost!",
      gui: true,
      timeout: 45
    };
  }

  // 4. Terminal confirmation (no GUI)
  if (ctx.cmd && /\b(npm\s+publish)\b/i.test(ctx.cmd)) {
    return {
      action: "confirm",
      reason: "npm publish detected. Confirm release?",
      gui: false
    };
  }

  return null;
}
```

---

## 🛠️ CLI Reference

```bash
# 1. Inspect specified rule scripts
ai-hook list ./rules/rule1.js ./rules/rule2.js

# 2. Test a simulated command against rules with microsecond profiling
ai-hook test "git push origin master --force" ./examples/demo_all_features.js

# 3. Run high-iteration benchmark across specified rules
ai-hook bench -i 1000 -c "git status" ./examples/demo_all_features.js

# 4. Install as a global system command (copies to user bin and verifies PATH)
ai-hook install

# 5. One-command self-update to latest GitHub release
ai-hook update

# Force download and replace even if on the same version
ai-hook update --force
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
