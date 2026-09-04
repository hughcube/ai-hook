# ai-hook —— 多 Agent 统一安全拦截与规则自治调度基座

[![CI](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml/badge.svg)](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hughcube/ai-hook)](https://github.com/hughcube/ai-hook/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **极速（2~3ms）、零变量污染、单进程闭环、自治规则驱动** 的新一代 AI Agent 安全防御底座。  
> 专为 **Google Antigravity**、**Claude Code**、**CodeBuddy**、**OpenAI Codex** 等主流多 Agent 体系深度打造。

[English Documentation](README.md) | 简体中文文档

---

## 📖 背景与痛点

在多 Agent 协同与插件化研发环境中，为了防御误操作（如物理删库 `rm -rf /`、未授权高危迁移 `migrate:fresh`、清空缓存 `FLUSHALL`、私钥泄露），传统的 Hook 机制面临严重挑战：

1. **进程爆炸与明显卡顿**：每个插件各自维护独立 Bash 脚本，Windows 上单次命令触发 10 个进程串行启动，顿挫感长达 **500~750ms**；
2. **变量污染与环境漂移**：多脚本在同环境中调用时，环境变量泄露、同名函数相互覆盖、工作目录漂移；
3. **代码强行合并的灾难**：为了提速而将各插件脚本物理拼接打包，导致维护成本与耦合度指数级上升；
4. **规则僵化，无法自治**：传统 Hook 缺乏上下文，面对“周五封网期禁动生产库”、“master 分支禁强推”、“检测特定本地配置”等动态诉求无能为力。

**`ai-hook` 彻底终结了上述问题**：以 Rust 编写的原生单二进制为中央调度基座，内嵌微型 QuickJS 引擎，让每个插件的规则文件在物理隔离的沙箱中**自给自足地获取前置数据**并做出瞬发决策。

---

## ⚡ 架构全景

```
[Agent 发起工具调用 (run_command / write_to_file / ...)]
                       │
                       ▼ (stdin: JSON payload)
┌─────────────────────────────────────────────────────────────┐
│             中央调度基座二进制: ai-hook.exe                   │
│   (Rust 原生编译 / 静态链接 / 零外部依赖 / 2~3ms 物理级瞬发)    │
│                                                             │
│  1. Fast Path 前置短路:                                     │
│     只读安全命令 (git status, ls, pwd 等) 0.01ms 放行，不启引擎│
│  2. 原生 Serde JSON 纳秒级解析:                              │
│     自动识别 AGY (.toolCall) / CC (.tool_input) / Codex (turn_id)│
│  3. 动态发现各插件独立规则 (~/.agents/plugins/*/hooks/*.js):   │
│     ┌───────────────────────────────────────────────────┐   │
│     │ 物理级独立沙箱 (零代码合并，绝无变量污染):           │   │
│     │ - rd/protect-prod-db-write.js (生产特权写保护)    │   │
│     │ - xr/protect-prod-db-write.js (生产库白名单放行)  │   │
│     │ - dev/protect-db-migrate.js   (破坏性迁移阻断)    │   │
│     │ - sys/protect-rm-root.js      (删根与整盘防护)    │   │
│     └───────────────────────────────────────────────────┘   │
│  4. 规则自治前置数据获取 (sys 原生能力，拒绝外部子进程):         │
│     - sys.git.branch() 纯内存读取 .git/HEAD (0.02ms)        │
│     - sys.fs.readText() 原生 Rust 文件 I/O (0.01ms)         │
│     - Request-Scoped Cache: 单次请求内 I/O 自动单例缓存     │
│  5. 决策中枢与系统级真交互:                                   │
│     - 免确认模式/高危: 呼出 60s 倒计时吸附置顶弹窗          │
│     - 终端交互: 输出对应平台原生协议 (force_ask / ask / deny) │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼ (stdout: JSON decision)
[Agent 放行继续执行 或 拦截报错]
```

---

## ✨ 核心特性

- 🚀 **极致性能**：
  - 采用 Rust 原生 PE 二进制，Windows 下冷启动耗时仅 **1.5ms**；
  - 常见只读指令由 Fast Path 在 **0.01ms** 内短路放行；
  - 全量规则评估仅需 **0.5~1.0ms**，整体验证 **2~3ms**（相比旧方案提速 **200+ 倍**）。
- 🛡️ **物理级绝对隔离（零变量污染）**：
  - 各插件规则文件各自独立，**无需做任何物理文件拼接与合并**；
  - 每个规则执行在独立的 QuickJS Context 沙箱中，执行完立即释放，变量绝不外溢。
- 🧠 **规则完全自治（Self-Sufficient Rules）**：
  - 规则无需基座预埋繁杂逻辑，直接调用原生 `sys` 能力：
    - **时间/日历计算**：标准 JS 原生 `new Date()`，时段、星期几、封网日期自然表达；
    - **Git 分支感知**：`sys.git.branch()` 纯内存解析 `.git/HEAD`，不调 `git.exe`；
    - **配置读取**：`sys.fs.readText(".env")`，配合单次请求内存缓存，杜绝重复读盘。
- ⏱️ **60 秒倒计时置顶吸附弹窗**：
  - 在全自动免确认（YOLO）或后台会话中，基座原生拉起系统置顶窗体；
  - 底部吸附固定【允许】/【拒绝】大按钮，支持长文本滚动与 ESC 退出，点【允许】自动放行，超时自动阻断。
- 🧰 **全套开发者管理 CLI**：
  - 内建 `list`、`test`、`bench`、`install` 子命令，随时调试、压测与自检。

---

## 📊 性能实测指标对比（Windows 11 真机）

| 指标 | 旧方案（10个独立 Bash 脚本） | ai-hook 基座（Rust + 自治规则） | 提升幅度 |
| :--- | :--- | :--- | :--- |
| **进程创建数量** | **10 个** `bash.exe` | **严格仅 1 个** `ai-hook.exe` | **减少 90%** |
| **只读命令耗时** | 420ms ~ 750ms | **< 0.02 毫秒** (Fast Path) | **提速 20,000+ 倍** |
| **端到端规则总耗时** | 500ms ~ 750ms (肉眼卡顿) | **2.5 ~ 3.5 毫秒** (1/5 帧画面) | **提速 200 倍** |
| **单次请求重复 I/O** | 多次读盘 | **0 次** (Request-Scoped 缓存) | 内存级命中 |
| **交互弹窗延迟** | ~300ms (PowerShell 冷启动) | **立即秒级呼出** | 桌面级响应 |

---

## 🚀 快速开始

### 1. 下载与安装

从 [GitHub Releases](https://github.com/hughcube/ai-hook/releases) 下载适合你平台的预编译二进制：

```bash
# Windows
curl -LO https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.zip
# 解压并将 ai-hook.exe 放入 PATH（例如 ~/bin 或 C:\Users\<Username>\bin）

# Linux / macOS
curl -LO https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86_64.tar.gz
tar -xzf ai-hook-linux-x86_64.tar.gz
mv ai-hook /usr/local/bin/
```

或者从源码直接编译安装：

```bash
cargo install --path .
ai-hook install
```

### 2. 配置 Shell 别名

在 `~/.zshrc` 或 `~/.bashrc` 中添加：

```bash
alias ai:hook="ai-hook"
```

### 3. 在 Agent 宿主中启用（支持传入多个脚本）

在各 Agent 的全局配置（如 Antigravity `~/.gemini/config/hooks.json`）中直接指定基座与要执行的多个规则脚本：

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

> **提示**：`ai-hook` 会精准仅执行所传入的这几个脚本，绝不发生全盘盲目扫描，单次调起全规则评估仅耗时 ~2ms。

### 4. 弹窗与超时环境控制

| 环境变量 / CLI 参数 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `AI_HOOK_GUI_TIMEOUT` / `--timeout <N>` | `60` | 倒计时弹窗秒数（超时自动拒绝关闭） |
| `AI_HOOK_GUI` / `--no-gui` | `1` (开启) | 设置为 `0` 或 `false` 可完全静默关闭弹窗 |

---

## 📝 编写自定义规则

规则文件采用标准 JavaScript (ES6+)，可通过命令行参数直接传递给 `ai-hook`。

### 规则契约与示例

```javascript
/**
 * protect-deploy.js - 生产发布与特权操作综合防护
 */
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // 1. 自主获取时间：周五 16:00 之后封网期
  const now = new Date();
  if (now.getDay() === 5 && now.getHours() >= 16) {
    if (/migrate:(fresh|reset)|production/i.test(cmd)) {
      return {
        action: "deny",
        reason: "【封网保护】当前为周五下午发布封网期，严禁执行生产迁移与重置！"
      };
    }
  }

  // 2. 自主感知 Git 分支：主分支严禁强制推送
  if (/git\s+push\b/i.test(cmd)) {
    const branch = sys.git.branch();
    if ((branch === "master" || branch === "main") && /\s+(-f|--force)\b/.test(cmd)) {
      return {
        action: "deny",
        reason: `【分支安全】核心分支 '${branch}' 严禁执行强制推送 (force-push)！`
      };
    }
  }

  // 3. 自主读取本地项目配置：若连接生产库，拦截清库
  if (sys.fs.exists(".env")) {
    const envText = sys.fs.readText(".env") || "";
    if (envText.includes("DB_DATABASE=prod_db")) {
      if (/\b(db:wipe|migrate:fresh)\b/i.test(cmd)) {
        return {
          action: "confirm",
          reason: "检测到本地工作区连接生产数据库，清库操作需要人工审批！"
        };
      }
    }
  }

  // 放行返回 null
  return null;
}
```

---

## 🛠️ CLI 命令行指南

```bash
# 查看所有已生效的规则文件
ai-hook list

# 终端直测一条命令，回显每条规则耗时与判定结果
ai-hook test "git push origin master --force"

# 对当前全量规则进行 1,000 次压测
ai-hook bench -i 1000 -c "git status"

# 指定特定规则目录运行
ai-hook -r ./custom-rules list
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
