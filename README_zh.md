# ai-hook —— 多 Agent 统一安全拦截与规则自治调度基座

[![CI](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml/badge.svg)](https://github.com/hughcube/ai-hook/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hughcube/ai-hook)](https://github.com/hughcube/ai-hook/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **为两件事而生：屏蔽复杂度，与舒服地写规则。**  
> **① 屏蔽复杂度**——把多 Agent 的 Hook 协议差异、平台差异、进程与上下文获取等底层细节，全部封装进单个原生二进制：同一套规则一次编写、处处运行，不再为每个 Agent / 每套平台各维护一份脚本；在 Windows 上，还顺带把旧方案“每次调用连开十余个脚本进程”的顿挫收敛为单进程内的毫秒级评估。  
> **② 舒服地写规则**——规则就是普通 JS：丰富的 `ctx` 上下文、原生微秒级 `sys` 自治 API、统一的 deny/ask/inject 决策协议与桌面/终端交互，配合 `list`/`test`/`bench`/`tutorial` 调试工具，替代手写 Shell 胶水与跨平台试错。  
> 零变量污染、单进程闭环与极致速度，都是这套设计的自然结果。  
> 一套规则，通吃 **Claude Code**、**Google Antigravity**、**CodeBuddy / WorkBuddy**、**OpenAI Codex**、**Gemini CLI**、**OpenCode**——Windows / macOS / Linux 行为一致。
>
> **OpenCode 说明：** OpenCode 本身没有进程外 Hook 协议，它加载的是进程内 JS/TS 插件（见 [opencode.ai/docs/plugins](https://opencode.ai/docs/plugins/)）。ai-hook 通过社区桥 [`magarcia/opencode-claude-hooks`](https://github.com/magarcia/opencode-claude-hooks) 接入——该桥转发 Claude Code 形态的信封并置 `OPENCODE_COMPAT=1`。使用 OpenCode 时需先装该桥（或改用进程内插件方案）。

[English](README.md) | 中文

---

## 📖 背景与痛点

Hook 位于每次工具调用的**关键路径**上：调用前要评估、调用后要收口。为了防御误操作（如物理删库 `rm -rf /`、未授权高危迁移 `migrate:fresh`、清空缓存 `FLUSHALL`、私钥泄露），多 Agent 与插件化研发环境的传统做法是**各写各的脚本**：在 Windows 上，它们把这条高频路径拖成肉眼可见的顿挫；而在所有平台上，它们最终都沦为无法跨 Agent、跨平台复用的脚本孤岛。传统 Hook 机制由此面临四重挑战：

1. **进程爆炸与明显卡顿**：每个插件各自维护独立 Bash 脚本，Windows 上单次命令触发 10 个进程串行启动，顿挫感长达 **500~750ms**；
2. **变量污染与环境漂移**：多脚本在同环境中调用时，环境变量泄露、同名函数相互覆盖、工作目录漂移；
3. **代码强行合并的灾难**：为了提速而将各插件脚本物理拼接打包，导致维护成本与耦合度指数级上升；
4. **规则僵化，无法自治**：这类上下文传统脚本并非拿不到——时间有 `date`、分支有 `git branch`、本地配置有 `cat .env`、网络有 `curl`。但要把它们接进规则，就得自己写胶水：在 **Windows** 上，每抓一次都要临时 spawn 一批子进程（子进程冷启动昂贵，多规则叠加即成卡顿）；而在**所有平台**上，还都要面对——命令输出要靠手写正则解析、Shell 语法跨平台互不通用、同一次请求内多个规则各自重复抓取而零缓存、漏写超时的 `curl` 会把整道闸门挂死，且这套胶水还得为每个 Agent 各写一份。于是“周五封网期禁动生产库”、“master 分支禁强推”、“按本地 `.env` 放行”这类动态规则**难写、也难复用**，最终全部退化成静态正则与路径匹配。

**`ai-hook` 彻底终结了上述问题**：以 Rust 编写的原生单二进制为中央调度基座，内嵌微型 QuickJS 引擎，让每个插件的规则文件在物理隔离的沙箱中**自给自足地获取前置数据**并做出瞬发决策——时间、分支、配置等本地上下文由原生 API 直读（重复读取由 OS page cache 兜底为纯内存操作），规则里不再有 Shell 胶水、无需反复 spawn 子进程，跨平台行为天然一致（在 Windows 上顺带省掉了子进程冷启动的昂贵开销）；网络等远程上下文走内置 `sys.http` 出口，免去 spawn `curl`——网络往返时延不变，可设超时防挂死。

---

## ⚡ 架构全景

```
[Agent 发起工具调用 (run_command / write_to_file / ...)]
                       │
                       ▼ (stdin: JSON payload)
┌─────────────────────────────────────────────────────────────┐
│             中央调度基座二进制: ai-hook.exe                   │
│   (Rust 原生编译 / 静态链接 / 零外部依赖 / 进程内毫秒级评估)   │
│                                                             │
│  1. Fast Path 前置短路:                                     │
│     只读安全命令 (git status, ls, pwd 等) 进程内近零放行      │
│  2. 原生 Serde JSON 快速解析:                               │
│     自动识别 AGY / CC / Codex / CodeBuddy / Gemini / OpenCode│
│  3. 显式加载规则脚本 (CLI 参数 / AI_HOOK_RULES / ./.ai-hook):   │
│     ┌───────────────────────────────────────────────────┐   │
│     │ 物理级独立沙箱 (零代码合并，绝无变量污染):           │   │
│     │ - ai-hook ./rules/protect-prod.js (显式传参)    │   │
│     │ - AI_HOOK_RULES="a.js;b.js" (环境变量)  │   │
│     │ - ./.ai-hook/rules.js 或 ./.ai-hook/rules/ (本地)    │   │
│     │ - 每条规则在独立沙箱执行,零合并零污染    │   │
│     └───────────────────────────────────────────────────┘   │
│  4. 规则自治前置数据获取 (sys 原生能力，拒绝外部子进程):         │
│     - sys.git.branch() 纯内存解析 .git/HEAD（引擎内微秒级）   │
│     - sys.fs.readText() 原生 Rust 文件 I/O（引擎内微秒级）    │
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
  - Rust 原生 PE 单二进制、零运行时依赖；一次 hook 调用完整生命周期实测中位数 **~7ms**（Windows 11 x64 / node 式宿主），其中绝大部分是宿主创建进程的固定成本，与 ai-hook 自身几乎无关；
  - 只读安全命令由 Fast Path 进程内短路，不加载 JS 引擎，判定成本近零；
  - 规则评估在进程内毫秒级完成（实测 Fast Path 与引擎路径差值 <1ms），每新增一条规则仅增加 ~0.2ms。
- 🧩 **一处编写，处处通用（Universal Across Agents）**：
  - 单二进制内建各宿主 Payload/事件识别并输出各宿主协议（AGY `.toolCall`、CC `.tool_input`、Codex `turn_id`…），为哪个 Agent 接入都无需另写一套 Hook；
  - 同一份 JS 规则文件可在 Antigravity / Claude Code / CodeBuddy / Codex 间直接复用，切换 Agent **零迁移成本**。
- 🛡️ **物理级绝对隔离（零变量污染）**：
  - 各插件规则文件各自独立，**无需做任何物理文件拼接与合并**；
  - 每个规则执行在独立的 QuickJS Context 沙箱中，执行完立即释放，变量绝不外溢。
- 🧠 **规则完全自治（Self-Sufficient Rules）**：
  - 规则无需基座预埋繁杂逻辑，直接调用原生 `sys` 能力：
    - **时间/日历计算**：标准 JS 原生 `new Date()`，时段、星期几、封网日期自然表达；
    - **Git 分支感知**：`sys.git.branch()` 纯内存解析 `.git/HEAD`，不调 `git.exe`；
    - **配置读取**：`sys.fs.readText(".env")` 按 `ctx.cwd` 解析（重复读取由 OS page cache 兜底）。
- ⏱️ **60 秒倒计时置顶吸附弹窗**：
  - 在全自动免确认（YOLO）或后台会话中，基座拉起系统置顶 WPF 窗体（Windows 由**单个隐藏 PowerShell 宿主进程**渲染——抑制控制台窗口、无 conhost 闪烁）；
  - 底部吸附固定【允许】/【拒绝】大按钮，支持长文本滚动与 ESC 退出，点【允许】自动放行，超时自动阻断。
- 🧰 **全套开发者管理 CLI**：
  - 内建 `list`、`test`、`bench`、`install` 子命令，随时调试、压测与自检。

---

## 📊 性能基准（Windows 11 x64 / node 式宿主实测）

> **口径说明**：一次 hook 调用的耗时中，**进程创建与加载（由宿主触发）占绝大多数**——实测空程序与 ai-hook 相当；ai-hook 自身可控的只有进程内规则评估，故分列计量，避免把宿主侧开销误算成 ai-hook 的“启动成本”。

| 指标 | 旧方案（10 个独立 Bash 脚本） | ai-hook 基座 | 说明 |
| :--- | :--- | :--- | :--- |
| **进程创建数量** | 每次调用 10 个 `bash.exe` 串行 | 仅 1 个 `ai-hook.exe` | 减少 90% 进程创建 |
| **hook 调用全生命周期** | 420~750ms（历史实测） | **~7ms 中位数**（fast-path 6.7 / 引擎 6.9） | 差异主因是进程数 10→1 |
| **只读命令（Fast Path）** | 需启动整条脚本链 | 进程内短路，不加载 JS 引擎 | 判定成本近零 |
| **规则评估（进程内）** | 每规则反复 spawn `date`/`git`/`cat`/`curl` | 原生 sys 直读；单规则 <1ms、每增一条 ~0.2ms | 引擎侧实测 |
| **GUI 弹窗** | 另起 PowerShell，冷启动 ~300ms | 单个隐藏 PowerShell 宿主(CREATE_NO_WINDOW)渲染 WPF 弹窗 | 一个子进程、控制台隐藏——无 conhost 闪烁 |

---

## 🚀 快速开始

### 1. 下载与安装

从 [GitHub Releases](https://github.com/hughcube/ai-hook/releases) 直接下载对应系统的独立可执行文件（开箱即用，无需解压）：

```bash
# Windows (PowerShell): 下载至 ~/.local/bin（跨平台标准用户级 bin 目录）
$bin = "$HOME\.local\bin"; if (-not (Test-Path $bin)) { New-Item -ItemType Directory -Path $bin -Force }; Invoke-WebRequest -Uri "https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86_64.exe" -OutFile "$bin\ai-hook.exe"

# Linux: 直接下载到系统全局路径
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86_64
chmod +x /usr/local/bin/ai-hook

# macOS (Apple Silicon M系列)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-aarch64
chmod +x /usr/local/bin/ai-hook

# macOS (Intel)
curl -Lo /usr/local/bin/ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-darwin-x86_64
chmod +x /usr/local/bin/ai-hook

# 32 位 (i686;macOS 自 10.15 起已无 32 位支持,仅 Windows/Linux)
curl -Lo ai-hook.exe https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-windows-x86.exe
curl -Lo ai-hook https://github.com/hughcube/ai-hook/releases/latest/download/ai-hook-linux-x86 && chmod +x ai-hook
```

或者从源码直接编译安装：

```bash
cargo install --path .
ai-hook install
```

### 2. 在各大主流 AI Agent 中配置接入（支持传多个脚本）

`ai-hook` 设计为零外部依赖的通用拦截基座，支持直接通过命令行位置参数传入一个或多个 JS 规则文件：

#### (1) Google Antigravity 体系
在 `~/.gemini/config/hooks.json`(或工作区 `.agents/hooks.json`)中配置。官方 schema 顶层多一层 hook 名(可配 `enabled`):
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

### 3. 现代化自适应弹窗与超时控制

`ai-hook` 彻底弃用了传统粗糙的系统默认窗口，采用现代化自适应卡片设计（Windows 平台采用原生 WPF XAML 渲染）：
- **智能自适应高度**：当无命令内容时，**代码框自动彻底折叠隐藏**，彻底消灭中间空白区域！仅保留紧凑的授权提示卡片；
- **暗色高亮代码预览**：当有命令时，采用 `#0F172A` 深色代码卡片，自适应最大高度并自带横纵滚动条；
- **全键盘支持**：按 `Enter` 快速允许，按 `Esc` 快速拒绝；
- **文本可复制**：原因与命令文本可拖选 / `Ctrl+A` / `Ctrl+C`(Windows)；macOS 与 Linux 使用系统原生对话框(结构一致:原因/命令分区、倒计时、Esc 拒绝),文本选择能力受平台对话框限制
- **置顶与拖拽**：窗体默认置顶吸附，鼠标按住任意区域可平滑拖拽。

| 环境变量 / CLI 参数 | 默认值 | 作用说明 |
| :--- | :--- | :--- |
| `AI_HOOK_GUI_TIMEOUT` / `--timeout <N>` | `60` | 默认倒计时弹窗秒数（超时自动拒绝关闭） |
| `AI_HOOK_GUI` / `--no-gui` | `1` (开启) | 设置为 `0` 或 `false` 可完全静默关闭桌面弹窗 |
| `AI_HOOK_FORCE_GUI` / `--force-gui` | `0` (关闭) | **强制弹出**：即使 Agent (如 Claude Code) 支持原生终端 ask，亦强制唤起系统弹窗确认（硬阻断 deny 场景除外） |
| `AI_HOOK_DEBUG` / `--debug` | `0` (关闭) | **全量调试模式**：记录原生宿主输入、上下文、规则执行链与决策结果到 `~/.ai-hook/logs/ai-hook-debug-{agent}-{YYYYMMDD}.log` |
| `AI_HOOK_DEBUG_MAX_FILES` | `14` | 调试日志保留最大文件数（默认保留最后 14 个文件，超出自动删除最老历史文件） |
| `AI_HOOK_DEBUG_FILE` | (自动) | 自定义调试日志写入路径（覆盖默认路径） |

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

| 属性 | 类型 | 语义(完整契约见 `ai-hook tutorial`) |
| :--- | :--- | :--- |
| `ctx.platform` | `string` | 检测到的宿主:`"antigravity"` / `"claude_code"` / `"codebuddy"` / `"workbuddy"` / `"codex"` / `"gemini"` / `"opencode"` / `"generic"` |
| `ctx.mode` | `string?` | 宿主权限模式:`default`/`plan`/`acceptEdits`/`dontAsk`/`bypassPermissions` |
| `ctx.isYolo` | `boolean` | 免确认模式（自动感知 `AGY_DANGEROUSLY_SKIP_PERMISSIONS` 与 `CODEX_DANGEROUSLY_SKIP_PERMISSIONS` 环境变量，或 mode 含 bypassPermissions/dontAsk） |
| `ctx.event` | `string?` | **规范化事件名（跨宿主一致）**:`"PreToolUse"` / `"PostToolUse"` / `"UserPromptSubmit"` / `"Stop"`…。Gemini 的 `AfterTool`/`BeforeAgent` 会归一为 `PostToolUse`/`UserPromptSubmit`，规则写一次处处成立 |
| `ctx.eventRaw` | `string?` | 宿主原始事件拼写（如 Gemini 的 `"AfterTool"`），需要区分宿主时使用 |
| `ctx.prompt` | `string?` | 用户原始 Prompt 文本（仅在 `UserPromptSubmit` 等 Prompt 拦截事件中提供） |
| `ctx.session` | `{id, transcriptPath}?` | 会话 id 与全量对话记录路径(可用 `sys.fs.readText` 读取上下文) |
| `ctx.cwd` | `string` | 会话/命令工作目录 |
| `ctx.model` | `string?` | 宿主模型标识(如 Antigravity `modelName`) |
| `ctx.tool` | `string` | 宿主工具名原文(`"Bash"`/`"run_command"`/`"Write"`…) |
| `ctx.cmd` | `string?` | 仅命令类工具非空;其余为 `null` |
| `ctx.file` | `{path, action}?` | 仅文件类工具;`action`: `read`/`write`/`edit`/`delete`/`list`(按工具名归一;Codex `apply_patch` 的路径由引擎从 patch 文本提取) |
| `ctx.mcp` | `{server, tool}?` | 仅 MCP 工具;两种宿主拼写(`mcp__server__tool` / `mcp_server_tool`)归一为同一对——server 自定义的参数仍在 `ctx.args` 原文里。`server`/`tool` 已小写归一以跨宿主一致;若某 MCP 工具名的大小写有实际语义,请改用 `ctx.tool` 原文精确比较 |
| `ctx.web` | `{action, url, query}?` | 仅网页工具;`action`: `fetch`(WebFetch / AGY `read_url_content`,带 `url`)或 `search`(WebSearch / AGY `search_web`,带 `query`) |
| `ctx.search` | `{kind, path, pattern}?` | 仅代码搜索工具;`kind`: `glob`(Glob)或 `grep`(Grep / AGY `grep_search`) |
| `ctx.agent` | `{kind, description, prompt}?` | 仅委托类工具;`kind`: `agent`(Agent / Codex spawn)/ `workflow` / `task` |
| `ctx.args` | `object` | 宿主工具参数原文(`{command}`、`{file_path, content}`、`{CommandLine}`…) |
| `ctx.raw` | `object?` | 宿主完整原始 payload —— 逃生舱，`ctx` 字段不够用才用；**访问时才解析**，MB 级 transcript 不拖慢未用它的规则 |
| `ctx.rawInput` | `string` | payload 原始文本 |
> 设计原则:一语义一属性,无别名;非适用工具时 `cmd`/`file` 为 `null`(规则请先判空)。

#### 1.1 宿主事件名速查:规范名(`ctx.event`)× 各家 Agent 事件对照

`ctx.event` 一律采用 **Claude Code 拼写**,在所有宿主上含义一致。下表把每个规范名映射到各家 Agent 在同一生命周期节点实际触发的事件名(`—` = 该宿主无此事件):

| `ctx.event`(规范名) | Claude Code | OpenAI Codex | CodeBuddy / WorkBuddy | Google Antigravity | Gemini CLI | OpenCode(经桥) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `PreToolUse` | PreToolUse | PreToolUse | PreToolUse | PreToolUse(按载荷形状推断) | `BeforeTool` | PreToolUse |
| `PostToolUse` | PostToolUse | PostToolUse | PostToolUse | (官方有该事件;引擎**刻意不区分**——载荷归入 `PreToolUse` 分支,见注) | `AfterTool` | PostToolUse |
| `PostToolUseFailure` | PostToolUseFailure | — | — | — | — | — |
| `PermissionRequest` | PermissionRequest | PermissionRequest | — | — | — | — |
| `UserPromptSubmit` | UserPromptSubmit | UserPromptSubmit | UserPromptSubmit | — | `BeforeAgent` | — |
| `Stop` | Stop | Stop | Stop | Stop(按载荷形状推断) | `AfterAgent` | — |
| `SubagentStart` | SubagentStart | SubagentStart | SubagentStart | — | — | — |
| `SubagentStop` | SubagentStop | SubagentStop | SubagentStop | — | — | — |
| `PreCompact` | PreCompact | PreCompact | PreCompact | — | `PreCompress` | — |
| `PostCompact` | PostCompact | PostCompact | PostCompact | — | — | — |
| `SessionStart` | SessionStart | SessionStart | SessionStart | — | SessionStart | — |
| `SessionEnd` | SessionEnd | SessionEnd | SessionEnd | — | SessionEnd | — |
| `Setup` | Setup(仅可观测\*) | — | — | — | — | — |
| `PreInvocation` | — | — | — | PreInvocation(按载荷形状推断) | — | — |

让表格保持诚实的注记:

- **Gemini CLI** 使用自己的事件词汇(`BeforeTool`/`AfterTool`/`BeforeAgent`/`AfterAgent`/`PreCompress`),它们折叠进上表规范名——这正是 `ctx.event` 的意义;原始拼写仍可经 `ctx.eventRaw`(如 `"AfterTool"`)读取,具名导出也按规范名书写即可命中。
- **Antigravity 的 stdin 根本不携带事件名**(官方输入字段只有 `conversationId`/`workspacePaths`/`transcriptPath`…加 `toolCall`),ai-hook 按载荷形状推断事件;`PreInvocation` 与 `PostInvocation` 输入形状逐字节相同,故统一归类为 `PreInvocation`(AGY 的 `ctx.eventRaw` 保持 `null`——它确实没有宿主拼写可报告)。AGY 的 `PostToolUse` 也被**刻意不**用 `error` 键推断(`error` 在 PreToolUse 上是否出现无官方记载,误判会静默丢失 gate 能力),因此 post-tool 载荷会显示为 `PreToolUse`——规则仍可读取 tool/cwd,但其输出的任何决策都会被宿主忽略(AGY 的 PostToolUse 输出 schema 就是空对象 `{}`)。
- **OpenCode** 没有进程外 hook 协议;经 `opencode-claude-hooks` 桥转发 Claude Code 形态信封(`OPENCODE_COMPAT=1`),规范名列与 Claude Code 列一致。**但桥的能力比 Claude Code 窄得多**:`src/executor.ts` 只把 `exitCode === 2` 当阻断,`src/index.ts` 的 `tool.execute.before` 只判 `result.blocked`,所以 PreToolUse 的 deny 走**退出码 2 + stderr 原因**(发 `permissionDecision` 会被忽略 = fail open);`PermissionRequest` 用 `permissionDecision`(不是 `decision.behavior`)。桥未接线 `Stop` / `UserPromptSubmit`,且丢弃 `tool.execute.after` 的全部返回,也没有实现 `ask` —— 这些事件在 opencode 上没有任何能力,规则写 confirm 会降级为 GUI 弹窗或 fail-closed 拒绝。
- **`Setup`(\*)** 可观测但无决策/注入通道:Claude Code 官方 Setup decision control 丢弃 Setup hook 的全部 JSON 输出(含 `hookSpecificOutput.additionalContext`)。CodeBuddy / WorkBuddy 的官方事件表里根本没有 Setup,Codex 也没有,所以只有 Claude Code 会触发它。
- ai-hook 未建模的事件(如 Claude Code 的 `TaskCompleted`/`Notification`/`ConfigChange`/`WorktreeCreate`…)不会丢失:它们以**宿主原名**出现在 `ctx.event` 中可观测(记日志/分支判断),只是不能驱动决策。
- **CodeBuddy 与 WorkBuddy 共用同一内核**:WorkBuddy 以 CodeBuddy Code CLI 内核 + 独立配置目录运行,其 hooks 文档即 CodeBuddy 同一份文档。
- **按实现而非文档落地**:CodeBuddy 的 `hooks.md` 说 Stop/SubagentStop 用 `continue: false`,但随包 CLI 要求 `blocking === true`(`SessionHookManager.executeStopHooks`),只有 `decision:"block"` / permissionDecision deny / 退出码 2 能置位 —— `continue: false` 是空操作,宿主照常停止。ai-hook 在那里输出 `decision:"block"`;而 UserPromptSubmit / PreCompact 只需 `allowed=false`,故仍用 `continue: false`。
- **Gemini CLI 已并入 Antigravity CLI**:Google 自 2026-06-18 起对免费与 AI Pro/Ultra 档停止服务([公告](https://developers.googleblog.com/an-important-update-transitioning-gemini-cli-to-antigravity-cli)),Antigravity CLI 保留了 Hooks。Gemini 列保留给付费/自建场景,识别依据是官方的 `BeforeTool`/`AfterTool`/… 词表加上独有的 `timestamp` 输入字段。

#### 1.2 matcher:如何唤醒 ai-hook,以及如何写与工具名无关的规则

请把拦截想成**两个相互独立的过滤层**:

1. **宿主原生 `matcher`(粗筛)**——写在宿主配置文件里,决定"哪些工具调用会唤醒
   ai-hook"。语法与工具名都随宿主而变,写错会让 hook **静默不触发**(门禁形同
   虚设——Claude Code 官方文档称之为 silently disabled)。
2. **你的规则(精判)**——ai-hook 被唤醒后,由 JS 规则用**归一化后的 `ctx` 字段**
   决定放行/询问/拒绝/注入,这些字段在所有宿主上含义一致。

**原则:matcher 配宽,判断留在规则里。** matcher 反正要随宿主重写(语法与工具名
都不同),而规则可以到处走:规则只读 `ctx.cmd`(命令文本)与 `ctx.file.action`
(`read`/`write`/`edit`/`delete`/`list`),绝不依赖某个宿主的具体工具拼写。
把"要不要拦"的判断放进规则,就能用 `ai-hook test --platform <宿主>` 一处测试、
一处审计;matcher 只负责让无关工具调用不必付出进程开销。**配宽是安全的**:
误命中只多跑一次 hook,漏命中则整个门禁静默失效。

matcher **按事件生效**:配了 `PreToolUse` 不会作用于 `PostToolUse`/
`UserPromptSubmit`…;只有官方声明支持 matcher 的事件才会使用它。

##### 表 A — 按拦截目标的 matcher 值

| 拦截目标 | Claude Code | OpenAI Codex | CodeBuddy / WorkBuddy | Google Antigravity | Gemini CLI | OpenCode(经桥) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 执行命令 | `Bash`、`PowerShell`\* | `Bash`(官方示例 `^Bash$`) | `Bash` | `run_command` | `run_shell_command` | `bash` |
| 写文件 | `Write` | `Write`/`apply_patch`† | `Write` | `write_to_file` | `write_file` | `write` |
| 编辑文件 | `Edit` | `Edit`/`apply_patch`† | `Edit` | `replace_file_content`、`multi_replace_file_content` | `replace` | `edit` |
| 读文件 | `Read` | `Read`† | `Read` | `view_file` | `read_file`(批量 `read_many_files`) | `read` |
| 列目录 | — | — | — | `list_dir` | `list_directory` | —(无内置 list 工具,用 `bash`) |

\* Claude Code 注册 `Bash` 与 `PowerShell` 两个命令工具;Windows 且无 Git Bash
时只有 `PowerShell`。
† Codex 的 `apply_patch` 载荷恒报 `tool_name: "apply_patch"`,其官方别名含
`Edit`/`Write`(hooks 文档 matcher 示例还出现 `Bash`、`update_plan`、`Agent`、
`WebSearch`;读文件类工具名未在 hooks 文档出现,请以官方工具清单核对)。建议像
官方示例那样锚定(`^Bash$`)。

##### 表 B — 各家 matcher 语法

| 宿主 | matcher 语义 | 全匹配 | 备注 |
| :--- | :--- | :--- | :--- |
| Claude Code | 值仅含字母/数字/`_`/`-`/空格/`,`/`\|` → 精确串或 `\|`/`,` 列表;含其他字符 → **非锚定** JS 正则(`RegExp.prototype.test`,整名匹配需 `^…$`) | `"*"`、`""` 或省略 | 按工具名过滤的事件:PreToolUse/PostToolUse/PostToolUseFailure/PermissionRequest/PermissionDenied;SessionStart/Setup/SessionEnd/Notification 过滤的是别的字段(`source`/`trigger`/…);不支持 matcher 的事件上写 matcher 被静默忽略 |
| OpenAI Codex | 官方明文 "regex string";锚定/大小写未明示——官方示例锚定(`^Bash$`) | `"*"`、`""` 或省略 | UserPromptSubmit / Stop / Interrupt 忽略 matcher;MCP 名 `mcp__<server>__<tool>` |
| CodeBuddy / WorkBuddy | 正则、**大小写敏感**;裸 `Write` 匹配任何*包含* "Write" 的工具名——精确匹配要 `^Write$` | `"*"`、`""` 或省略 | 仅 PreToolUse / PostToolUse 支持;其余事件整字段可省;Windows 上 hook 命令强制 Git Bash 执行 |
| Google Antigravity | 正则(官方示例 `run_command`、`run_command\|view_file`、`browser_.*`) | `""` 或 `"*"` | 仅 PreToolUse / PostToolUse 支持;PreInvocation / PostInvocation / Stop 忽略 |
| Gemini CLI | 工具事件=正则;生命周期事件=精确串(官方 reference) | `""` 或 `"*"` | MCP 名 `mcp_<server>_<tool>` |
| OpenCode(经桥) | 桥把 CC matcher 编译成**大小写敏感、锚定**正则 `^(pattern)$`,对 `input.tool` 匹配——而它是 OpenCode 的*小写*工具 id | — | ⚠️ CC 风格 `"Bash"` 在 OpenCode 上**不会**命中 `bash` 工具;OpenCode 条目请用小写 matcher(`bash\|write\|edit\|read`),或单独维护一段 OpenCode 配置 |

##### MCP 工具——各家分隔符不同

MCP 工具名带 server 前缀,且分隔符**并不统一**(示例均出自官方):

| 宿主 | MCP 工具名格式 | 官方示例 |
| :--- | :--- | :--- |
| Claude Code | `mcp__<server>__<tool>` | `mcp__github__search_repositories`、`mcp__memory__.*` |
| OpenAI Codex | `mcp__<server>__<tool>` | `mcp__filesystem__read_file`、`mcp__filesystem__.*` |
| CodeBuddy / WorkBuddy | `mcp__<server>__<tool>` | `mcp__memory__.*`、`mcp__.*__write.*` |
| Gemini CLI | `mcp_<server>_<tool>`(**单**下划线) | reference matcher 文档 |
| Google Antigravity | MCP 命名官方未记载(matcher 只是对工具名的正则) | — |
| OpenCode(经桥) | 无原生 matcher;权限规则用 `"mymcp_*": "ask"` 通配;桥对 MCP `input.tool` 的匹配未核实 | — |

⚠️ Claude Code 官方点名的坑:匹配某 server 全部工具必须写 `mcp__memory__.*`——
裸 `mcp__memory` 只含精确集字符,会被按精确串比较,匹配不到任何工具(官方原文
"The `.*` is required");server 名带连字符同样要 `mcp__brave-search__.*`。
Gemini CLI 上请用单下划线形式。

##### 一条不需要知道任何 matcher 知识的规则(同一文件跑在所有宿主上)

```js
export default function (ctx, sys) {
  // 命令守卫:无论宿主把该工具叫 "Bash"、"run_command" 还是
  // "run_shell_command",ctx.cmd 拿到的都是命令文本。
  if (ctx.cmd && /rm\s+-rf\s+(\/|\*)/.test(ctx.cmd)) {
    return { deny: "禁止对根目录/通配符执行 rm -rf" };
  }
  // 文件守卫:action 跨宿主归一(Write/write_file/write_to_file/write → "write")。
  if (ctx.file && ctx.file.action === "write" &&
      /\.(env|pem|p12|pfx)$/i.test(ctx.file.path || "")) {
    return { deny: "拒绝覆写敏感文件: " + ctx.file.path };
  }
  return null;
}
```

该规则在各家的接线(matcher 配宽、事件逐层配置):

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
// Antigravity — .agents/hooks.json(顶层 hook 名,可选 enabled)
{ "ai-hook-gate": { "enabled": true, "PreToolUse": [
    { "matcher": "run_command|write_to_file|replace_file_content",
      "hooks": [{ "command": "ai-hook ./rules/guard.js" }] } ] } }
// Gemini CLI — ~/.gemini/settings.json(BeforeTool;timeout 单位是毫秒)
{ "hooks": { "BeforeTool": [ { "matcher": "run_shell_command|write_file|replace",
    "hooks": [{ "type": "command", "command": "ai-hook ./rules/guard.js",
                "timeout": 10000 }] } ] } }
// OpenCode — 经桥:复用上面的 Claude Code 配置,但 matcher 值要改成小写
// 内置 id(bash|write|edit|read|…)。
```

##### 常见错误

1. **把 matcher 原样从一家抄到另一家**:`run_command` 在 Claude Code 上永不触发,
   `Bash` 在 Gemini CLI 上永不触发(它的 shell 工具叫 `run_shell_command`)——
   工具名与 matcher 语法都随宿主而变。
2. **精确 vs 包含**:CC 的 `"Write"` 是精确工具名匹配;CB 的 `"Write"` 匹配任何
   *包含* "Write" 的名字(要锚定);OpenCode 桥对**小写** id 大小写敏感匹配——
   CC 风格的 `"Bash"` 在 OpenCode 上静默匹配不到任何东西。
3. **matcher 按事件生效**:保护了 `PreToolUse` 不等于配置了 `PostToolUse` 或
   `UserPromptSubmit`,每个关心的事件都要单独加条目。
4. **忽略 matcher 的事件会全量触发**(Codex 的 UserPromptSubmit/Stop/Interrupt,
   AGY 的 Stop/PreInvocation/PostInvocation):hook 照样被调用,请在规则内按
   `ctx.event`/prompt/载荷过滤,别指望宿主不叫你。
5. **规则里优先用 `ctx.file.action`/`ctx.cmd`,而不是 `ctx.tool === "Write"`**:
   同一个"写文件"逻辑分别是 Write(CC/CB)、apply_patch(Codex)、write_to_file
   (AGY)、write_file(Gemini)、write(OpenCode)。


### 2. `sys` 原生极速自治能力（微秒级原生数据获取与安全扩展）

`ai-hook` 提供原生微秒级 API，前置只读数据全部内存级解析；同时开放**进程调度与 HTTP 通信能力**（HTTP 出口基于内嵌 Rust 客户端而非 `curl` 子进程，务必显式设 `timeout`，默认 10s；适合内网可达性探测、在线封网/审批接口等实时上下文）。⚠️ `sys.exec` / `sys.http` 会跳出 QuickJS 沙箱（任意子进程 / 任意网络），仅当规则来源可信时使用：

| 方法 / 属性 | 返回类型 | 说明与性能 |
| :--- | :--- | :--- |
| `sys.git.branch()` | `string?` | **引擎内纯内存**解析 `.git/HEAD` 获取当前 Git 分支名（如 `"master"`、`"main"`），0 外部子进程 |
| `sys.git.root()` | `string?` | 获取当前 Git 仓库根目录绝对路径 |
| `sys.fs.exists(path)` | `boolean` | 引擎内检查相对/绝对路径文件是否存在(相对 `ctx.cwd` 解析) |
| `sys.fs.readText(path)` | `string?` | 引擎内原生文件读取（如 `.env`、`package.json`） |
| `sys.fs.list([dir])` | `string[]` | 列出目标目录下的所有文件名 |
| `sys.env("KEY")` | `string?` | **< 1 µs** 获取宿主环境变量 |
| `sys.ruleDir` | `string` | 当前规则脚本所在目录的绝对路径 |
| `sys.rulePath` | `string` | 当前规则脚本文件的绝对路径 |
| `sys.exec(target, args?, opt?)` | `object` | **通用命令/脚本/二进制调度（macOS/Linux/Windows 跨平台原生通用，零写死路径）**：支持系统 PATH 中任意命令、原生二进制（ELF/Mach-O/PE 直接原生执行）、任意脚本与 Shebang（`#!/bin/sh`、`#!/usr/bin/env bash/zsh/python3/node` 等，根据系统环境变量与可用解释器智能自适应调度，不绑定任何单一 shell 或特定安装路径）；支持 `cwd`/`env`/`input`/`timeout`（毫秒，默认 10000，超时终止整个进程组并返回 `ok:false`）；返回 `{ code, ok, stdout, stderr }` |
| `sys.http.get(url, opt?)` | `object` | **轻量同步 HTTP GET**：支持 `headers`/`timeout`，返回 `{ status, ok, headers, body }` |
| `sys.http.post(url, opt?)` | `object` | **轻量同步 HTTP POST**：支持 `headers`/`body`/`timeout`，返回 `{ status, ok, headers, body }` |
| `console.log(...)` | `void` | 调试日志到 stderr(绝不污染决策 JSON) |
| `sys.log(level, ...)` | `void` | 结构化日志:stderr **并**追加 `~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log`(JSONL;仅规则产生日志时写盘;默认保留最后 14 个文件;`AI_HOOK_LOG=0` 关闭,`AI_HOOK_LOG_FILE` 自定义,`AI_HOOK_LOG_MAX_FILES` 调整保留数量) |
| **标准 JS 原生能力** | - | `new Date()` 时钟（星期几/小时/封网期）、`JSON` / `RegExp` / `Math` / `Map` / `Set` 均为 QuickJS 原生内建，无需 sys —— sys 只补 JS 没有的 I/O 能力 |

### 3. 决策返回值：精确控制是强制阻断、弹窗确认还是提示注入

JS 规则文件通过返回值精确控制拦截行为：

#### 场景 A: 【直接强制不通过，绝对不弹窗】 (Direct Hard Block)
用于防御主分支强推、删除根目录、私钥外泄等**绝对禁止、无需用户复核**的致命操作：
```javascript
return {
  deny: "【硬阻断】核心生产分支严禁执行强制推送 (force-push) 操作！"
};
```
> **效果**：`ai-hook` 直接阻断 Agent 并回显错误原因，**完全不弹窗、零多余打扰**。

#### 场景 B: 【唤起桌面现代化吸附弹窗】 (Modern Fluent Card GUI Popup)
用于敏感但允许用户人工复核的操作（如清空开发数据库、全表重置）：
```javascript
return {
  ask: "检测到清库命令，请确认本地工作区所连接的环境与影响范围！",
  title: "数据库重置操作安全授权",   // 自定义弹窗标题
  gui: true,                     // 强制唤起桌面置顶吸附弹窗（穿透 --no-gui；默认不配置）
  timeout: 45                    // 自定义本次弹窗倒计时秒数（超时自动拒绝关闭）
};
```
> **效果**：屏幕中央立即弹出现代化卡片弹窗。用户点击【允许执行】或敲击 `Enter` 后 Agent 继续执行；点击【拒绝】、敲击 `Esc` 或倒计时超时自动阻断！

#### 场景 C: 【终端命令行确认，不唤起弹窗】 (Terminal-Only Ask)
若希望将确认交由 Agent 终端交互（如 Claude Code CLI 内的 `(y/n)` 提示）。宿主不支持协议 ask 时会直接自动拒绝（fail-closed）：
```javascript
return {
  ask: "检测到版本发布命令，是否确认推送到公共制品库？",
  gui: false // 不弹窗：宿主能 ask 走终端 ask，不能 ask 直接拒绝
};
```

#### 场景 D: 【零 Token 本地命令拦截阻断】 (UserPromptSubmit Zero-Token Intercept)
针对可直接在本地完成的查询或执行型命令（如 `/ai:balance`、`/ai:usage`、`/ai:sync`、`/ai:cache`）：
```javascript
return {
  deny: "余额信息为: ¥100.00" // 直接呈现给用户，免除大模型推理消耗
};
```
> **效果**：输出标准 `{"decision":"block","reason":"..."}`，阻断大模型推理调用，零 Token 消耗，直接在终端回显结果。

#### 场景 E: 【工具调用后规范注入与上下文提示】 (PostToolUse Context Injection)
针对工具执行完毕后的规范指引（如编辑数据库迁移文件后的应用层增改查联动提示）：
```javascript
return {
  inject: "刚编辑了 migration 文件，请遵循模型/应用层全链路规范补充往返测试！"
};
```
> **效果**：输出标准 `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"..."}}`，向大模型注入额外上下文提示。

#### 场景 F: 【安全放行】
```javascript
return null; // 或 return { allow: true };
```

> **规则执行失败的处理(fail-closed)**:任意规则出现语法错误、运行时异常、死循环超时或返回 Promise(async)时,ai-hook **默认直接拒绝**该命令,并把规则异常作为拒绝原因返回——绝不静默放行。每条规则受 5 秒执行超时保护(死循环会被自动中断)。如需出错放行,可显式传 `--allow-on-error` 或设置环境变量 `AI_HOOK_ALLOW_ON_ERROR=1`(不推荐用于生产安全门禁)。
> **输出语言**:弹窗、提示与日志语言跟随系统语言(Windows 系统区域 / `LANG`),可用 `AI_HOOK_LANG=zh|en` 强制指定;`ai-hook tutorial` 默认也跟随系统语言,`--lang en|zh` 可覆盖。

---

## 💡 规则示例 (Rule Demos)

下面的每个示例都是 [`examples/`](examples/) 目录里**可直接加载的规则文件**——
把它配进宿主(`ai-hook examples/01_basic_regex.js`),它就会守卫 §1.2 所列的工具;
同一个文件在所有 Agent 上行为一致。

### Demo 01 — 高危命令拦截(`examples/01_basic_regex.js`)

正则守卫破坏性命令:`rm -rf /`(含盘符根)硬阻断、Redis `FLUSHALL`/`FLUSHDB` 询问确认:

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

### Demo 02 — 动态时间窗口与封网期管控(`examples/02_time_freeze.js`)

纯 `new Date()` 自主取时:周五 16:00+ 发布封网期禁止生产库重置迁移,配置的节假日
封网日期禁止一切生产变更:

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

### Demo 03 — Git 分支感知保护(`examples/03_git_branch.js`)

`sys.git.branch()` 纯内存读 `.git/HEAD`(0 子进程):`master`/`main` 上禁止
force-push(`-f`/`--force`/`--force-with-lease`):

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

### Demo 04 — 动态配置与特权账户管控(`examples/04_env_context.js`)

`sys.fs.exists()` / `sys.fs.readText()` 读本地 `.env`(页缓存级速度,引擎无应用级
缓存):动用生产特权写账户 `xrapp_prod` 需确认(只读账户放行);本地 `.env` 绑定
生产时物理禁止清库/重置迁移:

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

### Demo 05 — 单文件全能力(`examples/demo_all_features.js`)

`demo_all_features.js` 端到端演示全部能力:平台/原始载荷/参数上下文、`sys`
自治读取、四种决策风格(硬 `deny`、桌面弹窗 `ask(gui:true)`、终端 ask
`ask(gui:false)`、Prompt 拦截与 `inject`)。源码已在上方链接,可用 `test`
子命令在任意宿主信封下回放:

```bash
# 把 "git push --force" 当作各宿主触发的事件回放,并打印该宿主会收到的确切 JSON:
ai-hook test --platform antigravity "git push origin master --force" examples/demo_all_features.js
ai-hook test --platform gemini       "git push origin master --force" examples/demo_all_features.js
ai-hook test --platform codex        "git push origin master --force" examples/demo_all_features.js
ai-hook test --platform opencode     "git push origin master --force" examples/demo_all_features.js
```

---
## 🛠️ CLI 命令行指南

```bash
# 1. 查看指定的规则脚本状态
ai-hook list ./rules/rule1.js ./rules/rule2.js

# 2. 模拟一条命令测试判定结果与耗时
ai-hook test "git push origin master --force" ./examples/demo_all_features.js

#    换一个宿主的信封重放同一条规则（默认 claude_code；
#    可选 codex / codebuddy / workbuddy / gemini / antigravity / opencode），
#    并打印该宿主真正会收到的 JSON
ai-hook test --platform gemini "npm run build" ./examples/demo_all_features.js

# 3. 压测规则性能（1,000 次循环评估）
ai-hook bench -i 1000 -c "git status" ./examples/demo_all_features.js

# 4. 安装为全局命令（自动探测系统现有 PATH 目录，零额外环境变量污染）
ai-hook install

# 5. 一键自我更新至 GitHub 最新 Release（自动匹配系统架构并安全替换自身）
ai-hook update

# 6. 查看内置交互式使用教程与规则开发指南
ai-hook tutorial
ai-hook tutorial --lang en

# 7. 主动清理历史日志文件（按分类默认保留最新 14 个文件，支持别名 ai-hook prune）
ai-hook clean
ai-hook clean --max-files 7
ai-hook clean --dry-run

# 强制重新下载覆盖
ai-hook update --force
```

---

## 📄 License

MIT License © 2026 [hughcube](https://github.com/hughcube)
