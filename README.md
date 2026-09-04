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

Download the precompiled binary for your operating system from [GitHub Releases](https://github.com/hughcube/ai-hook/releases):

```bash
# Windows
curl -LO https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.zip
# Unzip and place ai-hook.exe into your PATH (e.g. ~/bin or C:\Users\<Username>\bin)

# Linux / macOS
curl -LO https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86_64.tar.gz
tar -xzf ai-hook-linux-x86_64.tar.gz
mv ai-hook /usr/local/bin/
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

### 3. Register in Agent Configurations

In your global agent configuration (e.g. Antigravity `~/.gemini/config/hooks.json`), you only need a single entry:

```json
{
  "PreToolUse": [
    {
      "matcher": "run_command",
      "hooks": [
        {
          "type": "command",
          "command": "ai-hook",
          "timeout": 70
        }
      ]
    }
  ]
}
```

---

## 📝 Writing Autonomous Rules

Rules are written in standard JavaScript (ES6+). Place your `.js` files in any of the following directories:
1. **Project Local Rules**: `./.ai-hook/rules/*.js`
2. **User Global Rules**: `~/.ai-hook/rules/*.js`
3. **Plugin Rules**: `~/.agents/plugins/<plugin_name>/hooks/*.js`

### Contract & Example

```javascript
/**
 * protect-deploy.js - Comprehensive production deployment & safety guard
 */
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // 1. Autonomous time logic: Friday afternoon freeze
  const now = new Date();
  if (now.getDay() === 5 && now.getHours() >= 16) {
    if (/migrate:(fresh|reset)|production/i.test(cmd)) {
      return {
        action: "deny",
        reason: "【Deployment Freeze】Friday afternoon change freeze in effect. Destructive migrations prohibited!"
      };
    }
  }

  // 2. Autonomous Git branch awareness: Protect master branch from force push
  if (/git\s+push\b/i.test(cmd)) {
    const branch = sys.git.branch();
    if ((branch === "master" || branch === "main") && /\s+(-f|--force)\b/.test(cmd)) {
      return {
        action: "deny",
        reason: `【Branch Protection】Force-pushing to production branch '${branch}' is strictly prohibited!`
      };
    }
  }

  // 3. Autonomous configuration check: Protect production databases
  if (sys.fs.exists(".env")) {
    const envText = sys.fs.readText(".env") || "";
    if (envText.includes("DB_DATABASE=prod_db")) {
      if (/\b(db:wipe|migrate:fresh)\b/i.test(cmd)) {
        return {
          action: "confirm",
          reason: "Local workspace connects to production database! Database wipe requires manual confirmation."
        };
      }
    }
  }

  // Pass by returning null or undefined
  return null;
}
```

---

## 🛠️ CLI Reference

```bash
# List all discovered active rule scripts
ai-hook list

# Test a simulated command against all active rules and print microsecond profiling
ai-hook test "git push origin master --force"

# Run high-iteration benchmark across all active rules
ai-hook bench -i 1000 -c "git status"

# Specify custom rule directory
ai-hook -r ./custom-rules list
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
