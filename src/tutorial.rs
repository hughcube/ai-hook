/// Renders the tutorial text for a language ("zh"/"en", anything else -> zh).
/// Kept separate from printing so tests can assert on content without
/// spamming stdout.
pub fn tutorial_text(lang: &str) -> String {
    let body = if lang.eq_ignore_ascii_case("en") {
        english_tutorial_body()
    } else {
        chinese_tutorial_body()
    };
    // Version placeholder keeps the big raw-string blocks free of format
    // interpolation (they are full of literal `{` from JSON examples).
    body.replace("@@VERSION@@", env!("CARGO_PKG_VERSION"))
}

/// Generates and prints the interactive user tutorial and rule authoring guide
pub fn print_tutorial(lang: &str) {
    println!("{}", tutorial_text(lang));
}

fn chinese_tutorial_body() -> String {
    let tutorial = r#"================================================================================
  ai-hook —— AI Agent 安全门禁:能力与边界契约 (v@@VERSION@@)
  阅读对象:接入的 AI Agent、规则脚本作者、安全审计者
================================================================================

一、它是什么 / 何时运行 / 何时不运行
--------------------------------------------------------------------------------
  ai-hook 是 PreToolUse 同步拦截门禁:在宿主(Claude Code / OpenAI Codex /
  Google Antigravity / 腾讯 CodeBuddy)每次调用工具之前,宿主把一次工具调用
  以单行 JSON 从 stdin 传入;ai-hook 依次执行你的 JavaScript 规则,并把决策
  以该宿主的协议 JSON 写回 stdout;宿主据此 allow / ask / deny。

  运行模型(必须理解,规则都建立在这之上):
  · 每次工具调用 = 一个全新进程、全新 QuickJS 沙箱;规则文件之间零状态共享。
    唯一例外:同一进程内多个规则共享 sys.fs / sys.git 的只读内存缓存。
  · 规则能力边界:无网络、无外部子进程、无任意写文件;sys 只读自治。
    stdout 只能承载协议 JSON——任何规则日志都不得写入 stdout。
  · fast path 旁路:命令形如白名单只读命令(如 git status/ls/cat/head/pwd
    且无元字符)时,在规则引擎之前被放行。任何含换行/`$(`/反引号/重定向/
    管道/`&&`/`;`/危险词的命令一律进入规则引擎,规则不会被旁路。
  · 引擎失效边界(fail-closed):规则语法错误、运行时异常、死循环超时、
    返回 Promise —— 一律按“拒绝”处理并把错误作为原因返回;绝不静默放行。
    显式传入 --allow-on-error(或 AI_HOOK_ALLOW_ON_ERROR=1)才恢复出错放行。

二、ctx —— 一次工具调用的完整归一化视图(唯一 schema,无别名)
--------------------------------------------------------------------------------
  {
    agent:  "claude_code"|"codex"|"antigravity"|"codebuddy"|"generic", // 检测到的宿主
    mode:   "default"|"plan"|"acceptEdits"|"dontAsk"|"bypassPermissions"|null,
            // 宿主权限模式(仅提供该字段的宿主)
    isYolo: bool,      // 免确认 = mode 为 bypassPermissions/dontAsk(或 AGY 免确认标志)
    session:{ id, transcriptPath } | null,
            // 会话 id;transcriptPath = 全量对话记录(JSONL),可用
            // sys.fs.readText() 读取以获得完整上下文做精准拦截
    cwd:    string,    // 会话/命令工作目录(宿主下发或进程目录)
    model:  string|null, // 宿主模型标识(如 Antigravity modelName)
    tool:   string,    // 宿主工具名原文:"Bash"|"run_command"|"Write"|"Edit"|…
    cmd:    string|null, // 仅命令类工具(Bash/run_command/…),其余为 null
    file:   { path: string|null, action: "read"|"write"|"edit"|"delete"|"list" } | null,
            // 仅文件类工具;action 由工具名归一(Read→read, Write→write,
            // Edit/apply_patch→edit, Delete→delete, list_dir→list)
    args:   object,    // 宿主工具参数原文(如 {command},{file_path,content},{CommandLine})
    raw:    object,    // 宿主下发完整 payload(字段以宿主文档为准,永远可用)
    rawInput: string,  // payload 原始文本
  }
  规则判空惯例:命令规则先 `if (ctx.cmd && …)`;文件规则先
  `if (ctx.file && ctx.file.action === "write" …)`——因为 cmd/file 对非适用
  工具恒为 null。
  宿主差异:Antigravity 工具名在 toolCall.name;Claude Code/Codex/CodeBuddy
  使用同一 envelope(tool_name+tool_input);Codex 特有 turn_id;antigravity
  特有 modelName/workspacePaths。

三、sys —— 只读自治 SDK(微秒级,禁止外部进程)
--------------------------------------------------------------------------------
  sys.git.branch()      string|null   当前分支名(.git/HEAD 纯内存解析)
  sys.git.root()        string|null   仓库根目录
  sys.git.status()      string        分支简报("branch: x" / "not a git repository")
  sys.fs.exists(path)   bool          相对 cwd 解析;单进程内缓存
  sys.fs.readText(path) string|null   文本读取;单进程内缓存
  sys.fs.list([dir])    string[]      目录条目
  sys.env("KEY")        string|null   进程环境变量(亦可 sys.env.get("KEY"))
  sys.cwd()             string        当前工作目录(与 ctx.cwd 一致)
  new Date()            标准 JS 时钟(周五封网、夜间窗口等)
  console.log(...)      stderr + 文件;错误也走 console.error(同通道)
  sys.log(level, ...)   结构化日志;level 自定(warn/info/debug…)
  日志文件:默认 ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log(UTC 按日切分),
  JSONL 每行含 ts/agent/sessionId/rule/level/msg;按会话可用
  grep '"sessionId":"…"' 还原。仅当规则真的产生日志时才写盘(零日志零 IO)。
  覆盖/关闭:AI_HOOK_LOG_FILE=自定义路径;AI_HOOK_LOG=0|false 完全关闭;
  超过 20MB 自动轮转为同文件 .1。
  权限边界:sys 全部只读且不产生副作用;规则无法发起网络或执行程序。

四、决策协议(规则返回值)
--------------------------------------------------------------------------------
  return null;                    → 通过,继续下一规则(等价未表态)
  return { action: "allow" };     → 明确放行,继续下一规则
  return { action: "deny",  reason: "…" };   → 硬拒绝,绝对不弹窗
  return { action: "confirm", reason, title?, gui?, timeout?, force_gui? };
      · gui: true(默认)→ 桌面置顶弹窗(Enter 允许 / Esc 拒绝 / 倒计时超时
        自动拒绝);gui: false → 交由宿主终端 ask(ask 能力见表五)
      · timeout: 秒(默认 60,<=0 视为默认);超时一律按拒绝处理
      · force_gui: true / action: "force_gui" → 即使宿主支持终端 ask 也强制弹窗
  return false;                   → 拒绝(reason 自动生成)
  引擎级硬边界:规则必须为同步函数;5 秒执行看门狗;64MB 内存上限;
  不支持 async/Promise、import、require、fetch;文件必须是单文件 ES 语法。
  规则顺序:按文件名字典序执行;首个 confirm 或 deny 立即短路;
  allow/无表态不短路。目录加载顺序已保证确定性。

五、宿主决策差异矩阵(输出由 ai-hook 自动映射)
--------------------------------------------------------------------------------
  agent 值       宿主 ask 能力        deny/allow 协议载体
  antigravity    ✓ force_ask        顶层 {decision, reason}
  claude_code    ✓ ask               hookSpecificOutput.permissionDecision(ask 亦可)
  codebuddy      ✓ ask               同上(CodeBuddy 亦接受 modifiedInput)
  codex          ✗ 无 ask(输出 deny)  hookSpecificOutput.permissionDecision
  generic        — 尽力输出 ask        hookSpecificOutput 形态
  因此:对 codex 的 confirm(gui:false) 会自动降级为 deny 并附原因;对
  claude_code/codebuddy 的 confirm(gui:false) 输出 ask,由宿主弹原生确认。
  YOLO/免确认(mode 含 bypass/dontAsk)下,凡未真正弹窗的 confirm 一律拒绝。

六、接入最小配置
--------------------------------------------------------------------------------
  Claude Code / CodeBuddy(~/.claude/hooks.json 或 settings.json):
    { "hooks": { "PreToolUse": [
        { "matcher": "Bash|Write|Edit|Read",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/protect.js" }] } ] } }
  Antigravity(~/.gemini/config/hooks.json):
    { "PreToolUse": [ { "matcher": "run_command|write_to_file|view_file",
        "hooks": [ { "command": "ai-hook ./rules/protect.js", "timeout": 70 } ] } ] }
  Codex(~/.codex/hooks.json):结构与 Claude Code 相同;matcher 支持正则。
  规则文件三种加载方式:显式传参 > AI_HOOK_RULES(路径列表,';' 或 ':' 分隔)>
  ./.ai-hook/rules.js 或 ./.ai-hook/rules/ 目录(仅一层,按名排序)。
  目录内以下划线开头的文件与 *.tmp.js / *.test.js 会被忽略。

七、调试与运维
--------------------------------------------------------------------------------
  ai-hook test <命令> <rules…>      单条命令过所有规则,显示每规则决策与耗时
  ai-hook bench -i 1000 -c <命令>   压测
  ai-hook list [<rules…>]           列出实际加载的规则
  ai-hook tutorial --lang en        英文版本文档
  --dry-run 不弹窗;--no-gui 禁用弹窗;--force-gui 强制弹窗;
  --allow-on-error 规则出错放行;AI_HOOK_LANG=zh|en 固定语言;
  弹窗语言/日志语言跟随系统(Windows 区域或 LANG),可被 AI_HOOK_LANG 覆盖。
  console.log 与 sys.log 永远不进入 stdout,不会破坏协议。

八、安全模型小结(给审计者)
--------------------------------------------------------------------------------
  1) 白名单 fast path 只放行“无任何元字符的单条只读命令”,其余全走规则;
  2) 规则失败默认关闭(fail-closed),错误即拒绝并附原因;
  3) 每条规则 5s 看门狗 + 64MB 沙箱,死循环/超内存被中断;
  4) 规则仅能读取(sys.fs/env/git),无网络无执行能力;
  5) 协议输出仅 JSON;日志双通道(stderr+文件)不污染 stdout;
  6) deny 的 reason 会回传给宿主与用户,便于审计与追溯。
================================================================================
"#;
    tutorial.to_string()
}

fn english_tutorial_body() -> String {
    let tutorial = r#"================================================================================
  ai-hook — AI Agent Security Gate: Capability & Boundary Contract (v@@VERSION@@)
  Audience: integrating AI agents, rule authors, security reviewers
================================================================================

I. What it is / when it runs / when it does not
--------------------------------------------------------------------------------
  ai-hook is a synchronous PreToolUse gate: before the host (Claude Code,
  OpenAI Codex, Google Antigravity, Tencent CodeBuddy) invokes a tool, the host
  feeds one tool call as a single JSON line on stdin; ai-hook runs your
  JavaScript rules in order and writes the decision back to stdout in that
  host's protocol; the host then allows / asks / denies.

  Execution model (rules build on this):
  · One tool call = one fresh process and one fresh QuickJS sandbox; rule
    files share zero state. Only exception: rules in the same process share
    the read-only in-memory caches of sys.fs / sys.git.
  · Rule capability boundary: no network, no subprocesses, no arbitrary file
    writes; sys is a read-only autonomous SDK. stdout carries protocol JSON
    only — rule logging must never go to stdout.
  · Fast-path bypass: commands that are provably single read-only invocations
    (whitelist like git status/ls/cat/head/pwd and no shell metacharacters)
    are allowed BEFORE the rule engine. Anything containing newlines, `$( )`,
    backticks, redirections, pipes, `&&`, `;`, or dangerous words always goes
    through the engine — rules are never bypassed for those.
  · Engine failure boundary (fail-closed): syntax errors, runtime exceptions,
    watchdog timeouts, or returned Promises are DENIED with the error as the
    reason; a broken gate never silently opens. Pass --allow-on-error
    (or AI_HOOK_ALLOW_ON_ERROR=1) explicitly to restore allow-on-error.

II. ctx — one normalized view of a tool call (single schema, no aliases)
--------------------------------------------------------------------------------
  {
    agent:  "claude_code"|"codex"|"antigravity"|"codebuddy"|"generic", // detected host
    mode:   "default"|"plan"|"acceptEdits"|"dontAsk"|"bypassPermissions"|null,
            // host permission mode (hosts that provide it)
    isYolo: bool,       // no-confirm = mode bypassPermissions/dontAsk (or AGY flag)
    session:{ id, transcriptPath } | null,
            // session id; transcriptPath = full conversation log (JSONL);
            // read it with sys.fs.readText() for context-aware decisions
    cwd:    string,     // command/session working directory
    model:  string|null, // host model identifier (e.g. Antigravity modelName)
    tool:   string,     // host tool name verbatim: "Bash"|"run_command"|"Write"|…
    cmd:    string|null, // command tools only (Bash/run_command/…); null otherwise
    file:   { path: string|null, action: "read"|"write"|"edit"|"delete"|"list" } | null,
            // file tools only; action normalized from tool name
            // (Read→read, Write→write, Edit/apply_patch→edit, Delete→delete, list_dir→list)
    args:   object,     // host tool arguments verbatim ({command},{file_path,…})
    raw:    object,     // full host payload (host fields win; always available)
    rawInput: string,   // raw payload text
  }
  Rule idiom: guard command rules with `if (ctx.cmd && …)` and file rules with
  `if (ctx.file && ctx.file.action === "write" …)` — cmd/file are null for
  tools they do not describe.
  Host differences: Antigravity names its tool in toolCall.name; Claude Code /
  Codex / CodeBuddy share one envelope (tool_name + tool_input); turn_id is
  Codex-only; modelName/workspacePaths are Antigravity-only.

III. sys — read-only autonomous SDK (microsecond, no external processes)
--------------------------------------------------------------------------------
  sys.git.branch()      string|null   current branch (pure .git/HEAD parse)
  sys.git.root()        string|null   repository root
  sys.git.status()      string        "branch: x" / "not a git repository"
  sys.fs.exists(path)   bool          resolved against cwd; cached per process
  sys.fs.readText(path) string|null   text read; cached per process
  sys.fs.list([dir])    string[]      directory entries
  sys.env("KEY")        string|null   process environment (or sys.env.get)
  sys.cwd()             string        current working directory (= ctx.cwd)
  new Date()            standard JS clock (freeze windows, night rules…)
  console.log(...)      stderr + file; console.error shares the channel
  sys.log(level, ...)   structured log; level is free-form (warn/info/debug…)
  Log files: default ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log (UTC day
  rollover), JSONL per line with ts/agent/sessionId/rule/level/msg; rebuild a
  session's story with grep '"sessionId":"…"'. Disk I/O happens only when a
  rule actually logs (zero logs = zero I/O). Overrides: AI_HOOK_LOG_FILE=<path>;
  disable with AI_HOOK_LOG=0|false; >20MB auto-rotates to <name>.1.
  Permission boundary: sys is read-only with no side effects; rules cannot
  reach the network or spawn programs.

IV. Decision protocol (rule return values)
--------------------------------------------------------------------------------
  return null;                    → pass, continue to the next rule
  return { action: "allow" };     → allow explicitly, keep going
  return { action: "deny", reason: "…" };  → hard block, never a popup
  return { action: "confirm", reason, title?, gui?, timeout?, force_gui? };
      · gui: true (default) → topmost desktop dialog
        (Enter allow / Esc deny / countdown timeout auto-denies)
        gui: false → host terminal ask (see matrix in V)
      · timeout: seconds (default 60; <=0 treated as default); timeout = deny
      · force_gui: true / action: "force_gui" → force the desktop dialog even
        when the host supports terminal ask
  return false;                   → deny (auto-generated reason)
  Engine hard limits: rules MUST be synchronous; 5s watchdog; 64MB heap cap;
  no async/Promise, no import/require/fetch; single-file ES syntax only.
  Order: rules run in file-name lexicographic order; the first confirm or deny
  short-circuits; allow / no-opinion never short-circuit. Directory loading
  order is deterministic.

V. Host decision matrix (output is mapped automatically)
--------------------------------------------------------------------------------
  agent value    host ask support   deny/allow transport
  antigravity    ✓ force_ask        top-level {decision, reason}
  claude_code    ✓ ask              hookSpecificOutput.permissionDecision (ask ok)
  codebuddy      ✓ ask              same (CodeBuddy also accepts modifiedInput)
  codex          ✗ no ask → deny    hookSpecificOutput.permissionDecision
  generic        — best-effort ask  hookSpecificOutput shape
  Consequence: for codex a confirm(gui:false) degrades to deny with reason;
  for claude_code/codebuddy it emits ask and the host shows its own prompt.
  In YOLO / no-confirm mode (mode contains bypass or dontAsk) any confirm that
  did not show a real dialog is DENIED.

VI. Minimal integration
--------------------------------------------------------------------------------
  Claude Code / CodeBuddy (~/.claude/hooks.json or settings.json):
    { "hooks": { "PreToolUse": [
        { "matcher": "Bash|Write|Edit|Read",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/protect.js" }] } ] } }
  Antigravity (~/.gemini/config/hooks.json):
    { "PreToolUse": [ { "matcher": "run_command|write_to_file|view_file",
        "hooks": [ { "command": "ai-hook ./rules/protect.js", "timeout": 70 } ] } ] }
  Codex (~/.codex/hooks.json): same envelope as Claude Code; matcher is regex.
  Rule loading precedence: explicit CLI paths > AI_HOOK_RULES (path list, ';'
  or ':' separated) > ./.ai-hook/rules.js or ./.ai-hook/rules/ directory
  (one level, name-sorted). Files starting with '_' and *.tmp.js/*.test.js
  are ignored.

VII. Debug & operations
--------------------------------------------------------------------------------
  ai-hook test <command> <rules…>    run one command through all rules
  ai-hook bench -i 1000 -c <command> benchmark
  ai-hook list [<rules…>]            show actually loaded rules
  ai-hook tutorial --lang zh         this document in Chinese
  --dry-run no dialogs; --no-gui disable dialogs; --force-gui force dialogs;
  --allow-on-error allow on rule failure; AI_HOOK_LANG=zh|en pins language.
  Dialog/log language follows the system (Windows locale or LANG), overridable
  with AI_HOOK_LANG. console.log/sys.log never touch stdout.

VIII. Security model summary (for reviewers)
--------------------------------------------------------------------------------
  1) Whitelist fast path only passes metacharacter-free single read-only
     commands; everything else goes through the rules.
  2) Rule failure is fail-closed by default: an error denies with its reason.
  3) Each rule has a 5s watchdog and a 64MB sandbox; runaway loops are
     interrupted, over-memory is bounded.
  4) Rules can only read (sys.fs/env/git); no network, no execution.
  5) Protocol output is JSON only; logs go to stderr + file, never stdout.
  6) Deny reasons are returned to the host and user for auditability.
================================================================================
"#;
    tutorial.to_string()
}
