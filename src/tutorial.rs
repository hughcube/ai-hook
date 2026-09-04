/// Generates and prints the interactive user tutorial and rule authoring guide
pub fn print_tutorial(lang: &str) {
    if lang.eq_ignore_ascii_case("en") {
        print_english_tutorial();
    } else {
        print_chinese_tutorial();
    }
}

fn print_chinese_tutorial() {
    let tutorial = r#"================================================================================
  ai-hook 官方使用教程与规则开发全景指南 (v1.0.0)
================================================================================

一、核心定位与核心优势
--------------------------------------------------------------------------------
  ai-hook 是专为 AI Agent (Google Antigravity, Claude Code, CodeBuddy, OpenAI Codex 等)
  打造的高性能统一安全拦截与规则自治调度基座。

  1. ⚡ 物理级极速：
     - Rust 原生编译，冷启动 < 1.5ms。
     - 常见只读安全命令 (git status, ls, pwd 等) 由 Fast Path 在 < 0.01ms 内瞬发放行。
     - 复杂 JavaScript 规则评估仅需 1~2ms，比传统 Shell Hook 提速 200+ 倍。
  2. 🛡️ 零变量污染：
     - 每个规则文件在独立的 QuickJS 沙箱中执行，零代码合并，绝无环境变量泄露。
  3. 🧠 规则完全自治：
     - 内置微秒级 sys 原生 SDK，纯内存获取 Git 分支与文件，杜绝外部低效子进程。
  4. 🎨 现代化自适应弹窗：
     - 系统级 Fluent 浮动卡片，自适应代码框，全键盘 (Enter 允许 / Esc 拒绝)，
       60 秒倒计时自动拒绝保护。
  5. 🌐 零新环境变量全局安装：
     - 自动检测系统中已有的标准 PATH 目录进行安装，零环境变量污染。

二、在各大主流 AI Agent 中接入
--------------------------------------------------------------------------------
  通过命令行参数直接向 ai-hook 传入一个或多个规则脚本文件：

  1. Google Antigravity 体系 (~/.gemini/config/hooks.json):
     {
       "PreToolUse": [
         {
           "matcher": "run_command",
           "hooks": [
             {
               "type": "command",
               "command": "ai-hook ~/.agents/plugins/dev/hooks/protect-db.js ~/.agents/plugins/rd/hooks/protect-prod.js",
               "timeout": 70
             }
           ]
         }
       ]
     }

  2. Anthropic Claude Code / CodeBuddy 体系 (~/.claude/hooks.json):
     {
       "hooks": {
         "PreToolUse": [
           {
             "command": "ai-hook ./rules/protect-prod.js ./rules/protect-git.js"
           }
         ]
       }
     }

三、JavaScript 规则开发指南 (ES6+)
--------------------------------------------------------------------------------
  规则脚本采用标准 JavaScript (ES6+)，无需编译或打包，导出一个函数即可：

  export default function(ctx, sys) {
    // 编写自治防护逻辑...
    return null; // 默认放行
  }

  1. ctx 上下文对象属性全景：
     - ctx.agent / ctx.agentType : Agent 类型字符串
       ("antigravity" | "claude_code" | "codebuddy" | "codex" | "generic")
     - ctx.cmd                   : 待执行的命令行文本 (针对命令工具)
     - ctx.tool / ctx.toolName   : 当前调用的工具名称 (如 "run_command", "write_to_file")
     - ctx.file / ctx.targetFile : 操作的目标文件路径 (针对文件工具)
     - ctx.args                  : 工具参数对象 (如 ctx.args.CommandLine)
     - ctx.raw                   : 宿主下发的完整原始 JSON 对象 (支持任意深层字段读取)
     - ctx.rawInput              : 原始未经处理的 JSON 字符串
     - ctx.cwd                   : 当前宿主工作区绝对路径
     - ctx.isYolo                : 是否处于免确认模式 (如 AGY_DANGEROUSLY_SKIP_PERMISSIONS=1)
     - ctx.conversationId        : 当前会话 ID (若宿主提供)

  2. sys 原生极速 SDK (微秒级直读，杜绝子进程)：
     - sys.git.branch()          : 0.02ms 纯内存读取 .git/HEAD 获取当前分支名 (如 "master")
     - sys.git.root()            : 获取当前 Git 仓库根目录绝对路径
     - sys.git.status()          : 获取 Git 状态简报
     - sys.fs.readText(path)     : 0.01ms 极速读取文本文件 (单次请求自动单例缓存)
     - sys.fs.exists(path)       : 检查文件或目录是否存在 (带缓存)
     - sys.fs.list([dir])        : 列出目录下所有文件名
     - sys.env("KEY")            : < 1 µs 纯内存读取宿主环境变量 (亦可 sys.env.get("KEY"))
     - sys.cwd()                 : 获取当前工作目录
     - console.log(...)          : 规则内调试日志输出 (自动打到 stderr，不破坏协议输出)
     - new Date()                : 原生标准时钟，可用于周五封网期、夜间变更控制等

  3. 决策返回值与行为控制：
     - 🛑 场景 A：【硬阻断】(致命操作，直接拒绝，绝对不弹窗)
       return {
         action: "deny",
         reason: "【硬阻断】核心生产分支严禁执行 force-push 操作！"
       };

     - ⚠️ 场景 B：【桌面置顶吸附弹窗】(高危操作，呼出系统级弹窗人工复核)
       return {
         action: "confirm",
         title: "生产数据库写入授权",
         reason: "检测到直接写入生产数据库操作，请核实影响范围！",
         gui: true,      // 默认 true，呼出置顶自适应卡片弹窗
         timeout: 60     // 倒计时秒数 (默认 60，超时自动拒绝)
       };

     - 💬 场景 C：【终端命令行交互】(不弹窗，由终端交互式问询)
       return {
         action: "confirm",
         reason: "检测到版本发布命令，是否确认推送到公共制品库？",
         gui: false      // 显式禁用桌面弹窗
       };

     - 🔔 场景 E：【强制呼出弹窗】(支持 ask 的 Agent 如 Claude Code 亦强制弹窗，除非直接 deny)
       可在规则中声明 force_gui: true 或 action: "force_gui"，
       亦可在 CLI 启动时传入 --force-gui 或环境变量 AI_HOOK_FORCE_GUI=1：
       return {
         action: "confirm",
         reason: "高风险操作，强制呼出弹窗授权",
         force_gui: true // 忽略原生终端 ask，必须桌面弹窗；若规则为 deny 则直接硬阻断绝不弹窗
       };

     - ✅ 场景 D：【安全放行】
       return null; // 或 return { action: "allow" };

四、实战规则范例 (可直接参考或复制)
--------------------------------------------------------------------------------
  // 保护生产分支不被强推，同时周五下午禁止生产操作
  export default function(ctx, sys) {
    // 1. 防御生产分支 force push
    if (ctx.cmd && /git\s+push\b.*(-f|--force)\b/.test(ctx.cmd)) {
      const branch = sys.git.branch();
      if (branch === "master" || branch === "main" || branch === "release") {
        return {
          action: "deny",
          reason: `【硬阻断】分支 '${branch}' 属于受保护分支，严禁强推！`
        };
      }
    }

    // 2. 封网期防护 (周五 16:00 之后)
    const now = new Date();
    if (now.getDay() === 5 && now.getHours() >= 16) {
      if (ctx.cmd && /\b(prod|production|deploy)\b/i.test(ctx.cmd)) {
        return {
          action: "confirm",
          title: "周五封网期变更授权",
          reason: "当前处于周五封网期 (16:00+)，高危变更必须取得管理员二次确认！",
          gui: true,
          timeout: 45
        };
      }
    }

    return null;
  }

五、CLI 开发者命令行大全
--------------------------------------------------------------------------------
  ai-hook                         查看帮助、命令行选项以及二进制所在绝对路径
  ai-hook tutorial                打印本使用教程与规则开发指南
  ai-hook tutorial --lang en      打印英文版使用教程
  ai-hook list <script...>        查看指定或已配置的规则脚本
  ai-hook test <cmd> <script...>  模拟一条命令并分析各规则匹配判定与微秒耗时
  ai-hook bench -i 1000 -c <cmd>  对指定规则脚本执行高频压测评估
  ai-hook install                 安装为系统全局命令 (自动探测零环境变量 PATH 目录)
  ai-hook update                  从 GitHub 一键检查并自我原子更新至最新版本
  ai-hook update --force          强制重新下载最新 Release 二进制替换自身
  ai-hook --force-gui <scripts..> 强制所有确认操作呼出桌面弹窗 (即便 Agent 支持 ask)
================================================================================
"#;
    println!("{}", tutorial);
}

fn print_english_tutorial() {
    let tutorial = r#"================================================================================
  ai-hook Official Tutorial & Developer Guide (v1.0.0)
================================================================================

I. Core Value & Architecture
--------------------------------------------------------------------------------
  ai-hook is a high-performance, multi-agent unified hook dispatcher and
  autonomous rule engine built for AI Agents (Google Antigravity, Claude Code,
  CodeBuddy, OpenAI Codex, etc.).

  1. ⚡ Extreme Speed:
     - Pure Rust native executable with < 1.5ms cold boot.
     - Fast Path short-circuits safe read-only commands in < 0.01ms.
     - Full JavaScript rule evaluation in 1~2ms (200x faster than legacy Bash).
  2. 🛡️ Zero Variable Pollution:
     - Each rule runs in an isolated QuickJS sandbox. Zero code merging needed.
  3. 🧠 Autonomous Rules:
     - Built-in native sys SDK parses git branches and reads files in memory,
       eliminating slow external subprocess spawns.
  4. 🎨 Modern Adaptive UI:
     - Fluent floating card with auto-collapsing code view, full keyboard
       navigation (Enter to allow, Esc to deny), and 60s countdown auto-reject.
  5. 🌐 Zero New Environment Variable Installation:
     - Auto-detects existing, writable directories already present in PATH.

II. Integrating into AI Agents
--------------------------------------------------------------------------------
  Pass rule script paths directly as CLI positional arguments:

  1. Google Antigravity (~/.gemini/config/hooks.json):
     {
       "PreToolUse": [
         {
           "matcher": "run_command",
           "hooks": [
             {
               "type": "command",
               "command": "ai-hook ~/.agents/plugins/dev/hooks/protect-db.js ~/.agents/plugins/rd/hooks/protect-prod.js",
               "timeout": 70
             }
           ]
         }
       ]
     }

  2. Anthropic Claude Code / CodeBuddy (~/.claude/hooks.json):
     {
       "hooks": {
         "PreToolUse": [
           {
             "command": "ai-hook --force-gui ./rules/protect-prod.js"
           }
         ]
       }
     }

III. JavaScript Rule Authoring Guide (ES6+)
--------------------------------------------------------------------------------
  Export a default function taking (ctx, sys):

  export default function(ctx, sys) {
    // Safety guard logic...
    return null; // Pass
  }

  1. ctx Context Object:
     - ctx.agent / ctx.agentType : Agent type ("antigravity"|"claude_code"|"codex"|"codebuddy"|"generic")
     - ctx.cmd                   : Command line string
     - ctx.tool / ctx.toolName   : Tool name (e.g. "run_command", "write_to_file")
     - ctx.file / ctx.targetFile : Target file path
     - ctx.args                  : Tool arguments object
     - ctx.raw                   : Full raw JSON payload deserialized into JS object
     - ctx.rawInput              : Raw unprocessed JSON string
     - ctx.cwd                   : Current workspace directory path
     - ctx.isYolo                : True if running in unattended/skip-permissions mode
     - ctx.conversationId        : Conversation/session ID

  2. sys Native SDK:
     - sys.git.branch()          : 0.02ms memory parse of .git/HEAD
     - sys.git.root()            : Absolute path to current Git root
     - sys.git.status()          : Status summary string
     - sys.fs.readText(path)     : 0.01ms file read with request-scoped caching
     - sys.fs.exists(path)       : Check if file/directory exists
     - sys.fs.list([dir])        : List directory entries
     - sys.env("KEY")            : < 1 µs environment variable lookup
     - sys.cwd()                 : Current working directory
     - console.log(...)          : Debug logging to stderr
     - new Date()                : Standard JS date/time for freeze windows

  3. Decision Return Object:
     - Hard Block (no dialog, aborts immediately):
       return { action: "deny", reason: "Blocked reason" };

     - Modern Floating Card Popup (human confirmation):
       return {
         action: "confirm",
         title: "Authorization Required",
         reason: "Detailed explanation",
         gui: true,
         timeout: 60
       };

     - Terminal Interactive Ask (no GUI popup):
       return { action: "confirm", reason: "Question", gui: false };

     - Forced GUI Popup (forces GUI popup even on ask-capable agents like Claude Code, unless denied):
       return {
         action: "confirm",
         reason: "Critical operation requiring human confirmation",
         force_gui: true // or use action: "force_gui" or CLI flag --force-gui
       };

     - Safe Pass:
       return null; // or { action: "allow" }

IV. CLI Command Reference
--------------------------------------------------------------------------------
  ai-hook                         Display help and binary location
  ai-hook tutorial                Print this tutorial and developer guide
  ai-hook tutorial --lang en      Print English tutorial
  ai-hook list <script...>        Inspect specified rule scripts
  ai-hook test <cmd> <script...>  Test command against rules with latency profiling
  ai-hook bench -i 1000 -c <cmd>  Run benchmark on rules
  ai-hook install                 Install to system PATH (zero env variable modification)
  ai-hook update                  Self-update to latest GitHub Release
  ai-hook update --force          Force redownload and replace
  ai-hook --force-gui <scripts..> Force GUI popup for all confirmations
================================================================================
"#;
    println!("{}", tutorial);
}
