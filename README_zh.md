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

从 [GitHub Releases](https://github.com/hughcube/ai-hook/releases) 直接下载对应系统的独立可执行文件（开箱即用，无需解压）：

```bash
# Windows (PowerShell): 直接下载并存入用户 bin
New-Item -ItemType Directory -Force -Path "$HOME\bin"
Invoke-WebRequest -Uri "https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.exe" -OutFile "$HOME\bin\ai-hook.exe"

# Linux: 直接下载到系统全局路径
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86_64
chmod +x /usr/local/bin/ai-hook

# macOS (Apple Silicon M系列)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-aarch64
chmod +x /usr/local/bin/ai-hook

# macOS (Intel)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-x86_64
chmod +x /usr/local/bin/ai-hook
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

### 3. 在各大主流 AI Agent 中配置接入（支持传多个脚本）

`ai-hook` 设计为零外部依赖的通用拦截基座，支持直接通过命令行位置参数传入一个或多个 JS 规则文件：

#### (1) Google Antigravity 体系
在 `~/.gemini/config/hooks.json` 中配置：
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

#### (2) Anthropic Claude Code / CodeBuddy 体系
在 hooks 配置中指定：
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

> **性能保障**：`ai-hook` 严格仅评估所传入的规则脚本，绝不发生全盘扫描；即使加载 10 个规则，全量执行仅耗时 ~2ms。

### 4. 现代化自适应弹窗与超时控制

`ai-hook` 彻底弃用了传统粗糙的系统默认窗口，采用现代化自适应卡片设计（Windows 平台采用原生 WPF XAML 渲染）：
- **智能自适应高度**：当无命令内容时，**代码框自动彻底折叠隐藏**，彻底消灭中间空白区域！仅保留紧凑的授权提示卡片；
- **暗色高亮代码预览**：当有命令时，采用 `#0F172A` 深色代码卡片，自适应最大高度并自带横纵滚动条；
- **全键盘支持**：按 `Enter` 快速允许，按 `Esc` 快速拒绝；
- **置顶与拖拽**：窗体默认置顶吸附，鼠标按住任意区域可平滑拖拽。

| 环境变量 / CLI 参数 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `AI_HOOK_GUI_TIMEOUT` / `--timeout <N>` | `60` | 默认倒计时弹窗秒数（超时自动拒绝关闭） |
| `AI_HOOK_GUI` / `--no-gui` | `1` (开启) | 设置为 `0` 或 `false` 可完全静默关闭桌面弹窗 |

---

## 📝 规则开发全景指南 (Rule Authoring Guide)

规则文件采用标准 JavaScript (ES6+)，无需依赖任何 npm 包，语法极其轻量：

```javascript
export default function(ctx, sys) {
  // 编写自治防护逻辑...
  return null; // 放行
}
```

### 1. `ctx` 上下文对象（可获取的信息全景）

通过 `ctx` 对象，你可以直接拿到当前是哪个 AI Agent、完整的原始输入 Payload、调用的工具名称与参数：

| 属性名 | 类型 | 说明与示例 |
| :--- | :--- | :--- |
| `ctx.agent` / `ctx.agentType` | `string` | **当前 AI Agent 类型**：`"antigravity"` (Google AGY)、`"claude_code"` (Claude Code)、`"codebuddy"` (CodeBuddy)、`"codex"` (OpenAI Codex)、`"generic"` (其他) |
| `ctx.raw` | `object` | **AI 宿主下发的完整原始 Payload**（已自动反序列化为 JS 对象，可任意读取 `ctx.raw.conversationId` 等宿主私有字段） |
| `ctx.rawInput` | `string` | AI 宿主下发的原始未经处理的 JSON 字符串 |
| `ctx.args` | `object` | **当前工具调用的参数对象**（如 `ctx.args.CommandLine`, `ctx.args.TargetFile`, `ctx.args.CodeContent` 等） |
| `ctx.tool` / `ctx.toolName` | `string` | 当前被调用的工具名称（如 `"run_command"`, `"write_to_file"`, `"replace_file_content"`） |
| `ctx.cmd` | `string` | 待执行的命令行文本（针对命令执行工具，非命令工具时为空字符串） |
| `ctx.file` / `ctx.targetFile` | `string` | 目标文件绝对/相对路径（针对文件读写工具） |
| `ctx.cwd` | `string` | 当前宿主工作目录绝对路径 |
| `ctx.isYolo` | `boolean` | 是否处于免确认/自动授权模式（如 `AGY_DANGEROUSLY_SKIP_PERMISSIONS=1`） |
| `ctx.conversationId` | `string?` | 当前会话 ID（如果宿主提供了） |

### 2. `sys` 原生极速自治能力（微秒级原生数据获取）

`ai-hook` 严禁在规则中启动低效的外部子进程（如 `git.exe`），所有前置数据均由 Rust 原生微秒级 API 提供：

| 方法 | 返回类型 | 说明与性能 |
| :--- | :--- | :--- |
| `sys.git.branch()` | `string?` | **0.02ms** 内存直读 `.git/HEAD` 获取当前 Git 分支名（如 `"master"`, `"main"`） |
| `sys.git.root()` | `string?` | 获取当前 Git 仓库根目录绝对路径 |
| `sys.git.status()` | `string` | 快速返回 Git 状态简报 |
| `sys.fs.exists(path)` | `boolean` | **0.01ms** 检查相对/绝对路径文件是否存在（带请求内单例缓存） |
| `sys.fs.readText(path)` | `string?` | **0.01ms** 极速读取文本文件（如 `.env`, `package.json`），自动命中请求级单例缓存 |
| `sys.fs.list([dir])` | `string[]` | 列出目标目录下的所有文件名 |
| `sys.env("KEY")` | `string?` | **< 1 µs** 获取宿主环境变量，亦可使用 `sys.env.get("KEY")` |
| `sys.cwd()` | `string` | 获取当前工作目录 |
| `console.log(...)` | `void` | 规则内调试日志输出（自动重定向到 stderr，不破坏 Agent 决策 JSON 输出） |
| **标准 JS 原生时钟** | - | 使用原生 `new Date()` 即可做星期几、小时、日期、封网期计算 |

### 3. 决策返回值：精确控制是强制阻断、还是弹窗确认

JS 规则文件通过返回值精确控制拦截行为：

#### 场景 A: 【直接强制不通过，绝对不弹窗】 (Direct Hard Block)
用于防御主分支强推、删除根目录、私钥外泄等**绝对禁止、无需用户复核**的致命操作：
```javascript
return {
  action: "deny", // 或 "block", "reject"
  reason: "【硬阻断】核心生产分支严禁执行强制推送 (force-push) 操作！"
};
```
> **效果**：`ai-hook` 直接阻断 Agent 并回显错误原因，**完全不弹窗、零多余打扰**。

#### 场景 B: 【唤起桌面现代化吸附弹窗】 (Modern Fluent Card GUI Popup)
用于敏感但允许用户人工复核的操作（如清空开发数据库、全表重置）：
```javascript
return {
  action: "confirm",             // 触发确认门禁
  title: "数据库重置操作安全授权",   // 自定义弹窗标题
  reason: "检测到清库命令，请确认本地工作区所连接的环境与影响范围！",
  gui: true,                     // 唤起桌面置顶吸附卡片弹窗 (默认 true)
  timeout: 45                    // 自定义本次弹窗倒计时秒数（超时自动拒绝关闭）
};
```
> **效果**：屏幕中央立即弹出现代化卡片弹窗。用户点击【允许执行】或敲击 `Enter` 后 Agent 继续执行；点击【拒绝】、敲击 `Esc` 或倒计时超时自动阻断！

#### 场景 C: 【终端命令行确认，不唤起弹窗】 (Terminal-Only Ask)
若希望将确认交由 Agent 终端交互（如 Claude Code CLI 内的 `(y/n)` 提示）：
```javascript
return {
  action: "confirm",
  reason: "检测到版本发布命令，是否确认推送到公共制品库？",
  gui: false // 显式禁用弹窗，转为终端命令行提示
};
```

#### 场景 D: 【安全放行】
```javascript
return null; // 或 return { action: "allow" };
```

---

## 💡 完整全功能演示规则 (Demo)

完整演示规则参见源码仓库中的 [`examples/demo_all_features.js`](examples/demo_all_features.js)：

```javascript
/**
 * demo_all_features.js - ai-hook 全能力演示规则
 */
export default function(ctx, sys) {
  // 1. 打印 Agent 与工具信息
  console.log(`[Demo] 当前 Agent: ${ctx.agent}, 工具: ${ctx.tool}`);

  // 2. 致命高危命令：直接强制拦截，绝不弹窗
  if (ctx.cmd && /git\s+push\b.*(-f|--force)\b/.test(ctx.cmd)) {
    const branch = sys.git.branch();
    if (branch === "master" || branch === "main") {
      return {
        action: "deny",
        reason: `【硬阻断】主分支 '${branch}' 严禁 force-push！`
      };
    }
  }

  // 3. 敏感操作：唤起现代化 Fluent 吸附弹窗
  if (ctx.cmd && /\b(migrate|wipe|reset)\b/i.test(ctx.cmd)) {
    return {
      action: "confirm",
      title: "数据库结构变更授权",
      reason: "检测到数据库重置或变更命令，可能影响现有数据！",
      gui: true,
      timeout: 45
    };
  }

  // 4. 终端提示确认（不弹窗）
  if (ctx.cmd && /\b(npm\s+publish)\b/i.test(ctx.cmd)) {
    return {
      action: "confirm",
      reason: "检测到 npm 发布操作，是否继续？",
      gui: false
    };
  }

  return null;
}
```

---

## 🛠️ CLI 命令行指南

```bash
# 1. 查看指定的规则脚本状态
ai-hook list ./rules/rule1.js ./rules/rule2.js

# 2. 模拟一条命令测试判定结果与耗时
ai-hook test "git push origin master --force" ./examples/demo_all_features.js

# 3. 压测规则性能（1,000 次循环评估）
ai-hook bench -i 1000 -c "git status" ./examples/demo_all_features.js

# 4. 安装为全局命令（自动复制到用户 bin 目录并提示/校验全局 PATH）
ai-hook install

# 5. 一键自我更新至 GitHub 最新 Release（自动匹配系统架构并安全替换自身）
ai-hook update

# 强制重新下载覆盖
ai-hook update --force
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
