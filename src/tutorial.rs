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
  ai-hook —— AI Agent 安全门禁与生命周期基座:能力与边界契约 (v@@VERSION@@)
  阅读对象:接入的 AI Agent、规则脚本作者、安全审计者
================================================================================

一、它是什么 / 何时运行 / 何时不运行
--------------------------------------------------------------------------------
  ai-hook 是跨客户端统一的生命周期与门禁基座:在宿主(Claude Code / OpenAI
  Codex / Google Antigravity / 腾讯 CodeBuddy)的生命周期节点(PreToolUse、
  PostToolUse、UserPromptSubmit)拦截调用或用户输入。宿主把单次上下文以单行
  JSON 从 stdin 传入;ai-hook 依次执行你的 JavaScript 规则,并把决策以该宿主
  的协议 JSON 写回 stdout;宿主据此 allow / ask / deny / block / 注入上下文。

  运行模型(必须理解,规则都建立在这之上):
  · 每次调用 = 一个全新进程、全新 QuickJS 沙箱;规则文件之间零状态共享。
    唯一例外:同一进程内多个规则共享 sys.fs / sys.git 的只读内存缓存。
  · 规则能力:内置 sys 增强 SDK,包括 git/fs/env 内存查询,以及为 0-Token 命令
    拦截和自动化联动提供的同步外部进程执行 sys.exec() 与轻量 HTTP 请求
    sys.http。stdout 严格保留承载协议 JSON——任何规则日志都不得写入 stdout。
  · fast path 旁路:命令形如白名单只读命令(如 git status/ls/cat/head/pwd
    且无元字符)时,在规则引擎之前被放行,并会向 stderr 提示"规则被旁路"。
    任何含换行/`$(`/反引号/重定向/管道/`&&`/`;`/危险词的命令一律进入规则
    引擎。需要让白名单命令也经过规则时,用 --no-fast-path(或
    AI_HOOK_FAST_PATH=0)关闭旁路。
  · 引擎失效边界(fail-closed):规则语法错误、运行时异常、死循环超时、
    返回 Promise、漏写 return(返回 undefined)或返回无法识别的值 —— 一律
    按"拒绝"处理并把错误作为原因返回;绝不静默放行。规则的"放行"必须
    显式写 return null。显式传入 --allow-on-error(或
    AI_HOOK_ALLOW_ON_ERROR=1)才恢复出错放行。
  · 输入失效边界:stdin 为空或不可读时一律按"拒绝"处理(空输出会被宿主
    解读为放行,因此不可静默返回);能读入但无法解析为 JSON 的 payload 会被
    转为人机确认(桌面弹窗;禁用弹窗时输出 ask),绝不静默放行。

二、ctx —— 一次调用的完整归一化视图(唯一 schema,无别名)
--------------------------------------------------------------------------------
  {
    agent:  "claude_code"|"codex"|"antigravity"|"codebuddy"|"generic", // 检测到的宿主
    event:  "PreToolUse"|"PostToolUse"|"UserPromptSubmit"|string, // 生命周期事件
    prompt: string|null, // 仅在 UserPromptSubmit 时存在用户输入的 Prompt 文本
    mode:   "default"|"plan"|"acceptEdits"|"dontAsk"|"bypassPermissions"|null,
            // 宿主权限模式(仅提供该字段的宿主)
    isYolo: bool,      // 免确认 = mode 为 bypassPermissions/dontAsk,或宿主配置了
                       // AGY_DANGEROUSLY_SKIP_PERMISSIONS / CODEX_DANGEROUSLY_SKIP_PERMISSIONS
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
  规则判空惯例:
  - 拦截 Prompt 命令先 `if (ctx.prompt && ...)` 或 `if (ctx.event === "UserPromptSubmit")`;
  - 命令规则先 `if (ctx.cmd && …)`;文件规则先
  `if (ctx.file && ctx.file.action === "write" …)`——因为 cmd/file 对非适用
  工具恒为 null。

三、sys —— 自治增强 SDK(只读内存缓存 + 受控执行与网络)
--------------------------------------------------------------------------------
  sys.git.branch()      string|null   当前分支名(.git/HEAD 纯内存解析)
  sys.git.root()        string|null   仓库根目录
  sys.git.status()      string        分支简报("branch: x" / "not a git repository")
  sys.fs.exists(path)   bool          相对 cwd 解析;单进程内缓存
  sys.fs.readText(path) string|null   文本读取;单进程内缓存
  sys.fs.list([dir])    string[]      目录条目
  sys.env("KEY")        string|null   进程环境变量(亦可 sys.env.get("KEY"))
  sys.cwd()             string        当前工作目录(与 ctx.cwd 一致)
  sys.ruleDir / sys.__dirname   string 当前正在执行的规则脚本所在目录绝对路径
  sys.rulePath / sys.__filename string 当前正在执行的规则脚本文件绝对路径
  sys.exec(cmd, args?, opts?)   object 同步执行外部命令/脚本/二进制(跨平台原生+Shebang智能调度):
                                       返回 { code: number, stdout: string, stderr: string }
  sys.http.get(url, opts?)      object 同步 HTTP GET,返回 { status, body, headers }
  sys.http.post(url, body?, opt)object 同步 HTTP POST,返回 { status, body, headers }
  new Date()            标准 JS 时钟(周五封网、夜间窗口等)
  console.log(...)      stderr + 文件;错误也走 console.error(同通道)
  sys.log(level, ...)   结构化日志;level 自定(warn/info/debug…)
  日志文件:默认 ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log(UTC 按日切分),
  JSONL 每行含 ts/agent/sessionId/rule/level/msg;按会话可用
  grep '"sessionId":"…"' 还原。仅当规则真的产生日志时才写盘(零日志零 IO)。
  覆盖/关闭:AI_HOOK_LOG_FILE=自定义路径;AI_HOOK_LOG=0|false 完全关闭;
  超过 20MB 自动轮转为同文件 .1。

四、决策协议(规则返回值)
--------------------------------------------------------------------------------
  return null;                    → 通过,继续下一规则(等价未表态)
  return undefined / 漏写 return  → 视为引擎错误,按"拒绝"处理;
                                  想放行请显式 return null
  return { action: "allow" };     → 明确放行,继续下一规则
  return { action: "deny",  reason: "…" };   → 硬拒绝,绝对不弹窗
  return { action: "block", reason: "…" };   → 拦截大模型推理,在终端直接向用户输出
                                              reason 文本(UserPromptSubmit 零 Token 拦截)
  return { additionalContext: "…" };         → 向宿主注入上下文规范提示(PostToolUse 提示注入)
  return { action: "confirm", reason, title?, gui?, timeout?, force_gui? };
      · gui 三态(2026-09-05 约定,默认不配置):
          gui: true    → 强制桌面置顶弹窗(穿透 --no-gui,不可禁;仅 --dry-run
                         演练不弹);与 force_gui 同级
          不配置/缺省  → 宿主能 ask 直接走协议 ask(见表五);不能 ask 时
                         GUI 可用则弹窗兜底,GUI 不可用则自动拒绝
          gui: false   → 禁止弹窗:宿主能 ask 走 ask;不能 ask 直接拒绝
                         (fail-closed)
      · timeout: 秒(默认 60,<=0 视为默认);弹窗超时一律按拒绝处理
      · force_gui: true / action: "force_gui" → 强制桌面弹窗(与 gui:true 同级)
  return false;                   → 拒绝(reason 自动生成)
  引擎级硬边界:规则必须为同步函数;5 秒执行看门狗;64MB 内存上限;
  不支持 async/Promise、import、require;文件必须是单文件 ES 语法。
  规则顺序:按文件名字典序执行;首个 confirm、deny 或 block 立即短路;
  allow/无表态不短路。目录加载顺序已保证确定性。

五、宿主决策差异矩阵(can_ask × 模式;输出由 ai-hook 自动映射)
--------------------------------------------------------------------------------
  agent 值       普通模式 ask 能力    YOLO/bypass(免确认)   deny/allow 协议载体
  claude_code    ✓ ask(终端)         ✓ ask(官方:ask 在免确认
                                      模式仍拥有最高决策优先级)
                                                          hookSpecificOutput.permissionDecision
  codebuddy      ✓ ask(终端)         ✓ ask(同上)          同上
  codex          ✓ ask(0.152+ 起)    ✗(免确认下无 ask)     hookSpecificOutput.permissionDecision
  antigravity    ✓ force_ask         ✗(ask 被静默放行)     顶层 {decision, reason}
  generic        ✗ 无 ask 协议       ✗                    hookSpecificOutput 形态(尽力)
  confirm 通道选择(gui 三态 × can_ask):
  · 缺省(不配置):can_ask 宿主直接走协议 ask;不能 ask 的宿主 GUI 可用则
    弹窗兜底,不可用(CI/--no-gui/测试)自动拒绝;
  · gui:true / force_gui:全宿主强制弹窗(穿透 --no-gui);
  · gui:false:can_ask 宿主走 ask;不能 ask 宿主直接拒绝(禁弹窗 fail-closed)。

六、接入最小配置
--------------------------------------------------------------------------------
  Claude Code / CodeBuddy(~/.claude/hooks.json 或 settings.json):
    { "hooks": { "PreToolUse": [
        { "matcher": "Bash|Write|Edit|Read",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/protect.js" }] } ],
      "UserPromptSubmit": [
        { "matcher": ".*",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/intercept.js" }] } ] } }
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
  --allow-on-error 规则出错放行;--no-fast-path 关闭只读白名单旁路;
  AI_HOOK_LANG=zh|en 固定语言;
  AI_HOOK_LOG_EXTERNAL=1|true:把每次宿主传入的原始 payload(stdin 原文,解析
  前)记入 ~/.ai-hook/logs/ai-hook-inbound-{日期}.log(JSONL,>1MiB 截断头部,
  20MB 轮转)——调试 payload 形状/平台判别/解析问题用;默认关闭,关闭时零 IO;
  弹窗语言/日志语言跟随系统(Windows 区域或 LANG),可被 AI_HOOK_LANG 覆盖。
  console.log 与 sys.log 永远不进入 stdout,不会破坏协议。

八、安全模型小结(给审计者)
--------------------------------------------------------------------------------
  1) 白名单 fast path 只放行“无任何元字符的单条只读命令”,其余全走规则;
  2) 规则失败默认关闭(fail-closed),错误即拒绝并附原因;
  3) 每条规则 5s 看门狗 + 64MB 沙箱,死循环/超内存被中断;
  4) 规则提供受控同步只读 SDK、外部执行(sys.exec)与 HTTP 接口(sys.http),
     专供 0-Token 拦截与自动化注入;
  5) 协议输出仅 JSON;日志双通道(stderr+文件)不污染 stdout;
  6) deny 的 reason 会回传给宿主与用户,便于审计与追溯。
================================================================================
"#;
    tutorial.to_string()
}

fn english_tutorial_body() -> String {
    let tutorial = r#"================================================================================
  ai-hook — AI Agent Security Gate & Lifecycle Base: Capability & Boundary Contract (v@@VERSION@@)
  Audience: integrating AI agents, rule authors, security reviewers
================================================================================

I. What it is / when it runs / when it does not
--------------------------------------------------------------------------------
  ai-hook is a cross-client unified lifecycle and security gate: at host lifecycle
  hook points (PreToolUse, PostToolUse, UserPromptSubmit in Claude Code,
  OpenAI Codex, Google Antigravity, Tencent CodeBuddy), the host feeds single-call
  context as a single JSON line on stdin; ai-hook runs your JavaScript rules in
  order and writes the decision back to stdout in that host's protocol; the host
  then allows / asks / denies / blocks / injects additional context.

  Execution model (rules build on this):
  · One invocation = one fresh process and one fresh QuickJS sandbox; rule
    files share zero state. Only exception: rules in the same process share
    the read-only in-memory caches of sys.fs / sys.git.
  · Rule capability: built-in sys enhanced SDK, including in-memory git/fs/env
    queries, plus synchronous external process execution via sys.exec() and
    lightweight HTTP requests via sys.http for 0-Token prompt interception and
    automated workflows. stdout strictly carries protocol JSON only — rule logging
    must never touch stdout.
  · Fast-path bypass: commands that are provably single read-only invocations
    (whitelist like git status/ls/cat/head/pwd and no shell metacharacters)
    are allowed BEFORE the rule engine, with a stderr notice. Anything
    containing newlines, `$( )`, backticks, redirections, pipes, `&&`, `;`, or
    dangerous words always goes through the engine. To route whitelisted
    commands through the rules too, disable the bypass with --no-fast-path or
    AI_HOOK_FAST_PATH=0.
  · Engine failure boundary (fail-closed): syntax errors, runtime exceptions,
    watchdog timeouts, returned Promises, a missing return (yielding
    `undefined`) or any unparsable return value are DENIED with the error as
    the reason; a broken gate never silently opens. To pass, a rule must say
    `return null` explicitly. Pass --allow-on-error
    (or AI_HOOK_ALLOW_ON_ERROR=1) explicitly to restore allow-on-error.
  · Input failure boundary: an empty or unreadable stdin is DENIED (empty
    output would read as "allow", so ai-hook never returns silently); a
    readable but non-JSON payload is routed to a human confirmation (a desktop
    dialog, or a terminal "ask" when dialogs are disabled) — never silently
    allowed.

II. ctx — one normalized view of an invocation (single schema, no aliases)
--------------------------------------------------------------------------------
  {
    agent:  "claude_code"|"codex"|"antigravity"|"codebuddy"|"generic", // detected host
    event:  "PreToolUse"|"PostToolUse"|"UserPromptSubmit"|string, // lifecycle event
    prompt: string|null, // user input prompt string (UserPromptSubmit only)
    mode:   "default"|"plan"|"acceptEdits"|"dontAsk"|"bypassPermissions"|null,
            // host permission mode (hosts that provide it)
    isYolo: bool,       // no-confirm = mode bypassPermissions/dontAsk, or host configured
                        // AGY_DANGEROUSLY_SKIP_PERMISSIONS / CODEX_DANGEROUSLY_SKIP_PERMISSIONS
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
  Rule idiom:
  - Guard prompt interception with `if (ctx.prompt && ...)` or `if (ctx.event === "UserPromptSubmit")`;
  - Guard command rules with `if (ctx.cmd && …)` and file rules with
    `if (ctx.file && ctx.file.action === "write" …)` — cmd/file are null for
    tools they do not describe.

III. sys — autonomous SDK (in-memory cached + controlled execution & network)
--------------------------------------------------------------------------------
  sys.git.branch()      string|null   current branch (pure .git/HEAD parse)
  sys.git.root()        string|null   repository root
  sys.git.status()      string        "branch: x" / "not a git repository"
  sys.fs.exists(path)   bool          resolved against cwd; cached per process
  sys.fs.readText(path) string|null   text read; cached per process
  sys.fs.list([dir])    string[]      directory entries
  sys.env("KEY")        string|null   process environment (or sys.env.get)
  sys.cwd()             string        current working directory (= ctx.cwd)
  sys.ruleDir / sys.__dirname   string absolute directory path of running rule file
  sys.rulePath / sys.__filename string absolute file path of running rule file
  sys.exec(cmd, args?, opts?)   object synchronous command/script/binary execution (cross-platform & Shebang aware):
                                       returns { code: number, stdout: string, stderr: string }
  sys.http.get(url, opts?)      object synchronous HTTP GET, returns { status, body, headers }
  sys.http.post(url, body?, opt)object synchronous HTTP POST, returns { status, body, headers }
  new Date()            standard JS clock (freeze windows, night rules…)
  console.log(...)      stderr + file; console.error shares the channel
  sys.log(level, ...)   structured log; level is free-form (warn/info/debug…)
  Log files: default ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log (UTC day
  rollover), JSONL per line with ts/agent/sessionId/rule/level/msg; rebuild a
  session's story with grep '"sessionId":"…"'. Disk I/O happens only when a
  rule actually logs (zero logs = zero I/O). Overrides: AI_HOOK_LOG_FILE=<path>;
  disable with AI_HOOK_LOG=0|false; >20MB auto-rotates to <name>.1.

IV. Decision protocol (rule return values)
--------------------------------------------------------------------------------
  return null;                    → pass, continue to the next rule
  return undefined / no return    → engine error, DENIED;
                                   say `return null` to pass explicitly
  return { action: "allow" };     → allow explicitly, keep going
  return { action: "deny", reason: "…" };  → hard block, never a popup
  return { action: "block", reason: "…" }; → block LLM inference, output reason directly
                                             to user in terminal (UserPromptSubmit 0-Token)
  return { additionalContext: "…" };       → inject guidance context to host (PostToolUse)
  return { action: "confirm", reason, title?, gui?, timeout?, force_gui? };
      · gui tri-state (2026-09-05 contract; by default NOT set):
          gui: true    → force the topmost desktop dialog (pierces --no-gui;
                         only --dry-run skips it); same strength as force_gui
          unset/null   → host can ask: emit the host protocol ask (see V);
                         host cannot ask: GUI dialog as fallback, or an
                         auto-deny when no dialog is available
          gui: false   → no dialog: ask when the host can ask; otherwise
                         auto-deny (fail-closed)
      · timeout: seconds (default 60; <=0 treated as default); timeout = deny
      · force_gui: true / action: "force_gui" → force the desktop dialog
        (same strength as gui: true)
  return false;                   → deny (auto-generated reason)
  Engine hard limits: rules MUST be synchronous; 5s watchdog; 64MB heap cap;
  no async/Promise, no import/require; single-file ES syntax only.
  Order: rules run in file-name lexicographic order; the first confirm, deny, or block
  short-circuits; allow / no-opinion never short-circuit. Directory loading
  order is deterministic.

V. Host decision matrix (can_ask × mode; output is mapped automatically)
--------------------------------------------------------------------------------
  agent value    normal mode ask    YOLO / no-confirm        deny/allow transport
  claude_code    ✓ ask (terminal)   ✓ ask (official: hook ask
                                    keeps top priority even
                                    in no-confirm mode)
                                                            hookSpecificOutput.permissionDecision
  codebuddy      ✓ ask (terminal)   ✓ ask (same as CC)       same
  codex          ✓ ask (since 0.152) ✗ (no ask in bypass)    hookSpecificOutput.permissionDecision
  antigravity    ✓ force_ask        ✗ (ask silently allowed) top-level {decision, reason}
  generic        ✗ no ask protocol ✗                         hookSpecificOutput shape
  Confirm channel selection (gui tri-state × can_ask):
  · unset: can-ask hosts get the protocol ask directly; hosts that cannot
    ask fall back to the GUI dialog when available, or auto-deny when it is
    not (CI / --no-gui / tests);
  · gui:true / force_gui: force the dialog on every host (pierces --no-gui);
  · gui:false: can-ask hosts get ask; hosts that cannot ask are denied
    (no dialog, fail-closed).

VI. Minimal integration
--------------------------------------------------------------------------------
  Claude Code / CodeBuddy (~/.claude/hooks.json or settings.json):
    { "hooks": { "PreToolUse": [
        { "matcher": "Bash|Write|Edit|Read",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/protect.js" }] } ],
      "UserPromptSubmit": [
        { "matcher": ".*",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/intercept.js" }] } ] } }
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
  --allow-on-error allow on rule failure; --no-fast-path disable the read-only
  whitelist bypass; AI_HOOK_LANG=zh|en pins language.
  AI_HOOK_LOG_EXTERNAL=1|true: record every host stdin payload verbatim
  (before parsing) to ~/.ai-hook/logs/ai-hook-inbound-{YYYYMMDD}.log as JSONL
  (head-truncated over 1MiB, 20MB rotation) — for debugging payload shape,
  platform detection and parse issues. Off by default; zero I/O when off.
  Dialog/log language follows the system (Windows locale or LANG), overridable
  with AI_HOOK_LANG. console.log/sys.log never touch stdout.

VIII. Security model summary (for reviewers)
--------------------------------------------------------------------------------
  1) Whitelist fast path only passes metacharacter-free single read-only
     commands; everything else goes through the rules.
  2) Rule failure is fail-closed by default: an error denies with its reason.
  3) Each rule has a 5s watchdog and a 64MB sandbox; runaway loops are
     interrupted, over-memory is bounded.
  4) Rules provide controlled synchronous read SDK, external execution (sys.exec)
     and HTTP (sys.http) strictly for 0-Token interception and automation.
  5) Protocol output is JSON only; logs go to stderr + file, never stdout.
  6) Deny reasons are returned to the host and user for auditability.
================================================================================
"#;
    tutorial.to_string()
}
