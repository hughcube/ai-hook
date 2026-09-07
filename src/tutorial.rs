/// Renders the tutorial text for a language ("zh"/"en", anything else -> zh).
/// Kept separate from printing so tests can assert on content without
/// spamming stdout.
use crate::outln;

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
    outln!("{}", tutorial_text(lang));
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
    sys.fs / sys.git 是无状态直读:重复读同一文件由 OS page cache 兜底为
    纯内存操作,引擎不做应用级缓存。
  · 规则能力:内置 sys 增强 SDK,包括 git/fs/env 内存查询,以及为 0-Token 命令
    拦截和自动化联动提供的同步外部进程执行 sys.exec() 与轻量 HTTP 请求
    sys.http。stdout 严格保留承载协议 JSON——任何规则日志都不得写入 stdout。
  · fast path 旁路:命令形如白名单只读命令(如 git status/ls/cat/head/pwd
    且无元字符)时,在规则引擎之前被放行,并会向 stderr 提示"规则被旁路"。
    任何含换行/`$(`/反引号/重定向/管道/`&&`/`;`/危险词的命令一律进入规则
    引擎。需要让白名单命令也经过规则时,用 --no-fast-path(或
    AI_HOOK_FAST_PATH=0)关闭旁路。
  · 引擎失效边界(fail-closed):规则语法错误、运行时异常、死循环超时、
    返回 Promise 或返回无法识别的值 —— 一律按"拒绝"处理并把错误作为
    原因返回;绝不静默放行(null / undefined / 漏写 return 是"未表态",
    继续评估下一规则)。显式传入 --allow-on-error(或
    AI_HOOK_ALLOW_ON_ERROR=1)才恢复出错放行。
  · 输入失效边界:stdin 为空或不可读时一律按"拒绝"处理(空输出会被宿主
    解读为放行,因此不可静默返回);能读入但无法解析为 JSON 的 payload 会被
    转为人机确认(桌面弹窗;禁用弹窗时输出 ask),绝不静默放行。

二、ctx —— 一次调用的完整归一化视图(唯一 schema,无别名)
--------------------------------------------------------------------------------
  {
    platform: "claude_code"|"codex"|"antigravity"|"codebuddy"|"workbuddy"|"gemini"|"opencode"|"generic", // 检测到的宿主
    event:  "PreToolUse"|"PostToolUse"|"UserPromptSubmit"|"Stop"|"SessionStart"|…,
            // 规范化事件名,跨宿主一致:Gemini 的 AfterTool/BeforeAgent 会归一为
            // PostToolUse/UserPromptSubmit,规则写一次处处成立
    eventRaw: string|null, // 宿主原始事件拼写(如 Gemini 的 "AfterTool")
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
            // Edit/apply_patch→edit, Delete→delete, list_dir→list)。
            // Codex apply_patch 的目标路径由引擎从 patch 文本提取,
            // 规则无需解析 ctx.rawInput
    mcp:    { server: string|null, tool: string|null } | null,
            // 仅 MCP 工具(mcp__server__tool 双下划线 / mcp_server_tool 单
            // 下划线,两形态均归一,跨宿主一致);参数由 server 自定义,
            // 引擎不归一 —— 仍在 ctx.args 原文里。server/tool 已小写归一;
            // 需要精确大小写时用 ctx.tool 原文
    web:    { action: "fetch"|"search", url: string|null, query: string|null } | null,
            // 仅网页工具:WebFetch/read_url_content→fetch(带 url),
            // WebSearch/search_web→search(带 query)
    search: { kind: "glob"|"grep", path: string|null, pattern: string|null } | null,
            // 仅代码搜索工具:Glob/Grep(CC/Codex)、grep_search(AGY)
    agent:  { kind: "agent"|"workflow"|"task", description: string|null,
              prompt: string|null } | null,
            // 仅委托类工具:Agent/spawn_agent→agent、Workflow→workflow、
            // Task→task;description/prompt 跨宿主键提取
    args:   object,    // 宿主工具参数原文(如 {command},{file_path,content},{CommandLine})
    raw:    object|null, // 宿主下发完整 payload —— 逃生舱,ctx 字段不够用才用;
                       // 访问时才解析(lazy),MB 级 transcript 不拖慢未用它的规则
    rawInput: string,  // payload 原始文本
  }
  规则判空惯例:
  - 拦截 Prompt 命令先 `if (ctx.prompt && ...)` 或 `if (ctx.event === "UserPromptSubmit")`;
  - 命令规则先 `if (ctx.cmd && …)`;文件规则先
  `if (ctx.file && ctx.file.action === "write" …)`——因为 cmd/file 对非适用
  工具恒为 null。mcp/web/search/agent 同理:一次工具调用至多命中一个语义
  视图(命中者非 null,其余恒 null),未建模的工具(如 ExitPlanMode)四个视图
  全为 null,只能经 ctx.tool/ctx.args 访问。

三、sys —— 宿主能力 SDK(一个能力一个名字;exec/http 是沙箱逃逸点)
--------------------------------------------------------------------------------
  JS 原生可用,无需 sys:new Date() / Date.now()(周五封网、夜间窗口等)、
  JSON / RegExp / Math / Map / Set —— QuickJS 内建,引擎零参与。
  sys 只补 JS 没有的 I/O 能力:

  sys.git.branch()      string|null   当前分支名(.git/HEAD 纯内存解析)
  sys.git.root()        string|null   仓库根目录
  sys.fs.exists(path)   bool          相对 ctx.cwd 解析
  sys.fs.readText(path) string|null   文本读取
  sys.fs.list([dir])    string[]      目录条目
  sys.env("KEY")        string|null   进程环境变量
  sys.ruleDir           string        当前规则脚本所在目录绝对路径
  sys.rulePath          string        当前规则脚本文件绝对路径
  sys.exec(cmd, args?, opts?)   object ⚠️沙箱逃逸点(任意子进程)。
                                       同步执行外部命令/脚本/二进制(跨平台原生+Shebang智能调度):
                                       返回 { code, ok, stdout, stderr }。
                                       内置硬超时:opts.timeout 毫秒(默认 10000),
                                       超时终止整个进程组并返回 ok:false ——
                                       JS 看门狗管不到原生阻塞调用,由 exec 自身兜底
  sys.http.get(url, opts?)      object ⚠️沙箱逃逸点(任意网络)。
                                       同步 HTTP GET,返回 { status, ok, headers, body }
  sys.http.post(url, opts?)     object ⚠️沙箱逃逸点。同步 HTTP POST(body 放 opts.body)
  无请求级缓存:重复读同一文件时 OS page cache 已是纯内存操作,
  应用层再缓存只会多一个需要解释的概念。
  console.log(...)      stderr + 文件;错误也走 console.error(同通道)
  sys.log(level, ...)   结构化日志;level 自定(warn/info/debug…)
  日志文件:默认 ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log(UTC 按日切分),
  JSONL 每行含 ts/agent/sessionId/rule/level/msg;按会话可用
  grep '"sessionId":"…"' 还原。仅当规则真的产生日志时才写盘(零日志零 IO)。
  覆盖/关闭:AI_HOOK_LOG_FILE=自定义路径;AI_HOOK_LOG=0|false 完全关闭;
  超过 20MB 自动轮转为同文件 .1。

四、决策协议(规则返回值)
--------------------------------------------------------------------------------
  return null / undefined / 漏写 return → 未表态,继续下一规则
  return { allow: true };        → 明确放行,继续下一规则
  return { deny: "…" };          → 硬拒绝,绝对不弹窗
  return { keepGoing: "…" };     → Stop 类事件:让宿主继续执行(附原因)。
                                   ⚠️ Stop 类事件上写 deny 的语义随宿主而异:
                                   claude_code 恰好也输出 decision:block(=继续),
                                   antigravity 则输出 decision:deny
                                   (官方:非 continue 一律允许停止);
                                   要"别停下"必须用 keepGoing。
  return { inject: "…" };        → 向宿主注入上下文规范提示(PostToolUse 提示注入)
  return { mutateInput: {...} };             → 改写工具参数(PreToolUse)。
                                   仅 PreToolUse 类 gate 事件可用;宿主/事件无改写
                                   通道时(如在 PostToolUse 或不支持改参的事件上)由引擎
                                   丢弃并输出 stderr 提示,绝不输出宿主不认识的键。
                                   ⚠️ Codex(官方:updatedInput 必须与
                                   permissionDecision:"allow" 同发)与 CodeBuddy(实现
                                   同样要求)上,引擎会一并输出该放行标记 —— 即改写参数
                                   的同时也会跳过本次权限确认。Antigravity 官方输出字段
                                   表没有改参通道,该项会被丢弃
  return { replaceOutput: "…" };             → 替换工具结果(PostToolUse)。
                                   值可以是字符串(文本块宿主会用文本包裹),
                                   也可以是对象/数组 —— Claude Code 内置工具的
                                   updatedToolOutput 必须匹配工具输出形状
                                   (如 Bash 是 {stdout,stderr,interrupted,isImage}),
                                   形状不符会被忽略,只有结构化值才能替换
  return { ask: "…", title?, gui?, timeout?, forceGui? };
      · gui 三态(默认不配置):
          gui: true    → 强制桌面置顶弹窗(穿透 --no-gui,不可禁;仅 --dry-run
                         演练不弹);与 forceGui:true 同级
          不配置/缺省  → 宿主能 ask 直接走协议 ask(见表五);不能 ask 时
                         GUI 可用则弹窗兜底,GUI 不可用则自动拒绝
          gui: false   → 禁止弹窗:宿主能 ask 走 ask;不能 ask 直接拒绝
                         (fail-closed)
      · timeout: 秒(默认 60,<=0 视为默认);弹窗超时一律按拒绝处理
      · forceGui: true → 强制桌面弹窗(与 gui:true 同级)
  return false;                   → 拒绝(reason 自动生成)
  引擎级硬边界:规则必须为同步函数;5 秒执行看门狗;64MB 内存上限;
  不支持 async/Promise、import、require;文件必须是单文件 ES 语法。
  规则顺序:按文件名字典序执行;首个 ask、deny、inject/modify 或 keepGoing 立即短路;
  allow/无表态不短路。目录加载顺序已保证确定性。
  ⚠️ 排序有语义:inject / mutateInput / replaceOutput 同样会短路。若"注入提示"类
  规则的文件名排在"硬阻断"规则之前,命中提示后阻断规则将不再执行。需要两者叠加时,
  请把阻断类规则的文件名排在前面。
  ⚠️ 同一规则内 deny/ask/keepGoing 与 inject/mutateInput/replaceOutput 同时返回时,
  门控决策优先、修饰项被忽略——引擎会向 stderr 输出提示,不要依赖被吞掉的修饰项。

五、宿主决策差异矩阵(can_ask × 模式;输出由 ai-hook 自动映射)
--------------------------------------------------------------------------------
  platform 值    普通模式 ask 能力    YOLO/bypass(免确认)   deny/allow 协议载体
  claude_code    ✓ ask(终端)         ✓ ask(官方:ask 提示用户确认;
                                      且 ask 在免确认模式下同样强制弹窗)
                                                          hookSpecificOutput.permissionDecision
  codebuddy      ✓ ask(终端)         ✓ ask(同上)          同上
  codex          ✗ 协议无 ask(输出 ask 会被判 unsupported 并 fail open:宿主
                   标记 hook failed 后继续执行工具调用)→ confirm 一律走 GUI,
                   无 GUI 时 fail-closed 拒绝   hookSpecificOutput.permissionDecision
  workbuddy      ✓ ask(终端)         ✓ ask(同上)          同上
  gemini         ✗ 协议无 ask        ✗                    顶层 {decision, reason}
  antigravity    ✓ force_ask         ✗(bypass 不弹,走 GUI) 顶层 {decision, reason}
  generic        ✗ 无 ask 协议       ✗                    hookSpecificOutput 形态(尽力)
  confirm 通道选择(gui 三态 × can_ask):
  · 缺省(不配置):can_ask 宿主直接走协议 ask;不能 ask 的宿主 GUI 可用则
    弹窗兜底,不可用(CI/--no-gui/测试)自动拒绝;
  · gui:true / forceGui:true:全宿主强制弹窗(穿透 --no-gui);
  · gui:false:can_ask 宿主走 ask;不能 ask 宿主直接拒绝(禁弹窗 fail-closed)。

  ── 事件名速查:ctx.event 的宿主差异 ─────────────────────────────
  ctx.event 一律采用 Claude Code 拼写;Codex / CodeBuddy / WorkBuddy /
  OpenCode(桥)同名同形,仅下列宿主不同:
    PreToolUse        ← Gemini: BeforeTool
    PostToolUse       ← Gemini: AfterTool
    UserPromptSubmit  ← Gemini: BeforeAgent
    Stop              ← Gemini: AfterAgent;AGY:无事件名,按载荷形状推断
    PreCompact        ← Gemini: PreCompress
    PreInvocation     ← AGY:按形状推断(Pre/PostInvocation 输入同形,统一归此类)
  Antigravity 的 stdin 没有事件名(官方无 hook_event_name),上表是其按信封
  形状推断的结果;其 PostToolUse 被刻意不推断(用 error 键推断未文档化,误判
  会丢 gate),post-tool 载荷显示为 PreToolUse,且该期规则决策会被宿主忽略
  (官方 PostToolUse 输出固定 {})。未建模的宿主事件(如 TaskCompleted /
  Notification / ConfigChange)以宿主原名透传 ctx.event,可观测但不可决策。
  ── 原生 matcher 速查:拦截目标 × 各家工具注册名 ─────────────────
  执行命令:CC Bash|PowerShell、Codex Bash、CB Bash、AGY run_command、
  Gemini run_shell_command、OpenCode bash(小写);写文件:Write / Write(别名
  apply_patch)/ Write / write_to_file / write_file / write;编辑:Edit /
  Edit(或 apply_patch)/ Edit / replace_file_content / replace / edit;
  读文件:Read / Read / Read / view_file / read_file / read。
  matcher 语法随宿主:CC 值仅含 [A-Za-z0-9_ ,|-] 时=精确串/列表,否则为非
  锚定正则(整名匹配要 ^…$);Codex 官方 "regex string"(示例锚定 ^Bash$);
  CB 正则且大小写敏感,裸 Write 是"包含"匹配(精确需 ^Write$);AGY/Gemini
  正则,"" 或 "*" 全匹配(Gemini 仅工具事件用正则);OpenCode 桥按 CC 配置
  对**小写**工具 id 做大小写敏感锚定匹配——CC 式大写 "Bash" 不命中 opencode
  的 bash,请用小写 matcher。
  MCP 工具名:CC/Codex/CB 是 mcp__server__tool(双下划线;匹配整 server 必须
  mcp__server__.*),Gemini 是 mcp_server_tool(单下划线)。规则层统一经
  ctx.mcp.server / ctx.mcp.tool 读取,感知不到分隔符差异。
  规则侧无需感知任何工具名:判断一律用归一视图(ctx.cmd / ctx.file /
  ctx.mcp / ctx.web / ctx.search / ctx.agent);matcher 只需"配宽",让无关
  工具调用不付进程开销。示例规则见 examples/(README §Rule Demos 已内嵌)。

六、接入最小配置
--------------------------------------------------------------------------------
  Claude Code(~/.claude/settings.json 用户级,或 <项目>/.claude/settings.json
  项目级;官方不使用单独的 hooks.json):
    { "hooks": { "PreToolUse": [
        { "matcher": "Bash|Write|Edit|Read",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/protect.js" }] } ],
      "UserPromptSubmit": [
        { "hooks": [{ "type": "command", "command": "ai-hook ./rules/intercept.js" }] } ] } }
  CodeBuddy(~/.codebuddy/settings.json 或 <项目>/.codebuddy/settings.json):
    结构同上。
  Antigravity(~/.gemini/config/hooks.json 或工作区 .agents/hooks.json;
  官方要求顶层多一层 hook 名,可配 enabled):
    { "ai-hook-gate": { "enabled": true,
        "PreToolUse": [ { "matcher": "run_command|write_to_file|view_file",
          "hooks": [ { "command": "ai-hook ./rules/protect.js", "timeout": 70 } ] } ] } }
  Codex(~/.codex/hooks.json 或 config.toml 内联):结构与 Claude Code 相同;
  matcher 支持正则。注意 Codex 要求先在 /hooks 面板信任 hook,新增或变更的
  hook 未信任前会被静默跳过。
  Gemini CLI(~/.gemini/settings.json 的 hooks 段):事件为 BeforeTool/
  AfterTool 等自有命名;shell 工具名为 run_shell_command。
  规则文件三种加载方式:显式传参 > AI_HOOK_RULES(路径列表,分隔符与平台 PATH
  一致:Windows 用 ';',Unix 用 ':')> ./.ai-hook/rules.js 或 ./.ai-hook/rules/
  目录(仅一层,按名排序)。
  目录内以下划线开头的文件与 *.tmp.js / *.test.js 会被忽略。

七、调试与运维
--------------------------------------------------------------------------------
  ai-hook test <命令> <rules…>      单条命令过所有规则,显示每规则决策、耗时与
                                    宿主真实输出 JSON;--platform 指定模拟宿主
                                    (默认 claude_code,可选 codex/codebuddy/
                                    workbuddy/gemini/antigravity/opencode)
  ai-hook bench -i 1000 -c <命令>   压测
  ai-hook list [<rules…>]           列出实际加载的规则
  ai-hook clean [-n 14] [--dry-run] 主动清理历史日志文件(每类日志默认保留最新 14 个文件;
                                    支持别名 ai-hook prune)
  ai-hook tutorial --lang en        英文版本文档
  --dry-run 不弹窗;--no-gui 禁用弹窗;--force-gui 强制弹窗;
  --allow-on-error 规则出错放行;--no-fast-path 关闭只读白名单旁路;
  --debug 开启调试模式;
  AI_HOOK_LANG=zh|en 固定语言;
  AI_HOOK_DEBUG=1|true|on:全量记录原生宿主输入(raw_input)、规则上下文(context)、
  执行链与处理结果到 ~/.ai-hook/logs/ai-hook-debug-{agent}-{YYYYMMDD}.log
  (JSONL, 20MB 轮转, 零热路径删除开销;可用 ai-hook clean 清理并保留最后 14 个文件;
  可通过 AI_HOOK_DEBUG_MAX_FILES 或 AI_HOOK_LOG_MAX_FILES 调整保留数量,或用 AI_HOOK_DEBUG_FILE 覆盖写入路径);
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
    files share zero state. sys.fs / sys.git are stateless direct reads:
    repeat reads of the same file are already pure in-memory operations via
    the OS page cache — the engine adds no application-level cache.
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
    watchdog timeouts, returned Promises, or any unparsable return value are
    DENIED with the error as the reason; a broken gate never silently opens.
    (null / undefined / a missing return count as "no opinion" and evaluation
    continues with the next rule.) Pass --allow-on-error
    (or AI_HOOK_ALLOW_ON_ERROR=1) explicitly to restore allow-on-error.
  · Input failure boundary: an empty or unreadable stdin is DENIED (empty
    output would read as "allow", so ai-hook never returns silently); a
    readable but non-JSON payload is routed to a human confirmation (a desktop
    dialog, or a terminal "ask" when dialogs are disabled) — never silently
    allowed.

II. ctx — one normalized view of an invocation (single schema, no aliases)
--------------------------------------------------------------------------------
  {
    platform: "claude_code"|"codex"|"antigravity"|"codebuddy"|"workbuddy"|"gemini"|"opencode"|"generic", // detected host
    event:  "PreToolUse"|"PostToolUse"|"UserPromptSubmit"|"Stop"|"SessionStart"|…,
            // canonical event name, identical across hosts: Gemini's
            // AfterTool/BeforeAgent fold into PostToolUse/UserPromptSubmit so a
            // rule written once holds everywhere
    eventRaw: string|null, // the host's own event spelling (e.g. Gemini "AfterTool")
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
            // (Read→read, Write→write, Edit/apply_patch→edit, Delete→delete, list_dir→list).
            // Codex apply_patch targets are extracted from the patch text by
            // the engine — rules never need to regex ctx.rawInput for them
    mcp:    { server: string|null, tool: string|null } | null,
            // MCP tools only (mcp__server__tool / mcp_server_tool — both
            // spellings normalize identically); parameters are server-defined
            // and stay verbatim in ctx.args. server/tool are lower-cased; use
            // ctx.tool verbatim when exact case matters
    web:    { action: "fetch"|"search", url: string|null, query: string|null } | null,
            // web tools only: WebFetch/read_url_content→fetch (url),
            // WebSearch/search_web→search (query)
    search: { kind: "glob"|"grep", path: string|null, pattern: string|null } | null,
            // code-search tools only: Glob/Grep (CC/Codex), grep_search (AGY)
    agent:  { kind: "agent"|"workflow"|"task", description: string|null,
              prompt: string|null } | null,
            // delegation tools only: Agent/spawn_agent→agent, Workflow→
            // workflow, Task→task; description/prompt keys per host
    args:   object,     // host tool arguments verbatim ({command},{file_path,…})
    raw:    object|null, // full host payload — escape hatch, prefer cmd/file/args;
                        // parsed on first access (lazy), so MB-sized transcripts
                        // cost nothing to rules that never touch it
    rawInput: string,   // raw payload text
  }
  Rule idiom:
  - Guard prompt interception with `if (ctx.prompt && ...)` or `if (ctx.event === "UserPromptSubmit")`;
  - Guard command rules with `if (ctx.cmd && …)` and file rules with
    `if (ctx.file && ctx.file.action === "write" …)` — cmd/file are null for
    tools they do not describe. mcp/web/search/agent work the same way: one
    tool call populates at most one semantic view (the hit one is non-null,
    the others stay null); tools we do not model (e.g. ExitPlanMode) leave all
    four null and stay reachable through ctx.tool / ctx.args.

III. sys — host-capability SDK (one name per capability; exec/http escape the sandbox)
--------------------------------------------------------------------------------
  Plain JS already covers pure computation — new Date() / Date.now() (freeze
  windows, night rules…), JSON / RegExp / Math / Map / Set are QuickJS builtins.
  sys only adds the I/O that JS has no primitive for:

  sys.git.branch()      string|null   current branch (pure .git/HEAD parse)
  sys.git.root()        string|null   repository root
  sys.fs.exists(path)   bool          resolved against ctx.cwd
  sys.fs.readText(path) string|null   text read
  sys.fs.list([dir])    string[]      directory entries
  sys.env("KEY")        string|null   process environment
  sys.ruleDir           string        absolute directory of the running rule file
  sys.rulePath          string        absolute path of the running rule file
  sys.exec(cmd, args?, opts?)   object ⚠️ sandbox escape (arbitrary processes).
                                       Synchronous command/script/binary execution (cross-platform & Shebang aware):
                                       returns { code, ok, stdout, stderr }.
                                       Hard timeout built in: opts.timeout in ms
                                       (default 10000); on expiry the whole
                                       process group is killed and ok:false is
                                       returned — the JS watchdog cannot fire
                                       during a native blocking call, so exec
                                       bounds itself.
  sys.http.get(url, opts?)      object ⚠️ sandbox escape (arbitrary network).
                                       synchronous HTTP GET, returns { status, ok, headers, body }
  sys.http.post(url, opts?)     object ⚠️ sandbox escape. synchronous HTTP POST (body in opts.body)
  No request-level cache: repeat reads of the same file are already pure
  in-memory operations via the OS page cache; an app-level cache would only add
  a concept that needs explaining.
  console.log(...)      stderr + file; console.error shares the channel
  sys.log(level, ...)   structured log; level is free-form (warn/info/debug…)
  Log files: default ~/.ai-hook/logs/ai-hook-{agent}-{YYYYMMDD}.log (UTC day
  rollover), JSONL per line with ts/agent/sessionId/rule/level/msg; rebuild a
  session's story with grep '"sessionId":"…"'. Disk I/O happens only when a
  rule actually logs (zero logs = zero I/O). Overrides: AI_HOOK_LOG_FILE=<path>;
  disable with AI_HOOK_LOG=0|false; >20MB auto-rotates to <name>.1.

IV. Decision protocol (rule return values)
--------------------------------------------------------------------------------
  return null / undefined / no return → no opinion, continue to the next rule
  return { allow: true };        → allow explicitly, keep going
  return { deny: "…" };          → hard block, never a popup
  return { keepGoing: "…" };     → on Stop-like events: tell the host to keep
                                   going (with reason). ⚠️ A `deny` on Stop-like
                                   events means different things per host:
                                   claude_code happens to emit decision:block
                                   (= keep going), while antigravity emits
                                   decision:deny (official: any value other
                                   than "continue" allows the stop). To prevent
                                   stopping you must use keepGoing.
  return { inject: "…" };        → inject guidance context to host (PostToolUse)
  return { mutateInput: {...} };             → rewrite tool arguments
                                   (PreToolUse). Only gate events expose a
                                   rewrite channel; when the host/event has
                                   none (e.g. on non-PreToolUse events), the engine drops it
                                   with a stderr notice and never emits a key
                                   the host does not know.
                                   ⚠️ On Codex (official: updatedInput must be
                                   returned with permissionDecision:"allow") and
                                   CodeBuddy (same requirement in its
                                   implementation) the engine emits that allow
                                   marker too — rewriting the arguments also
                                   skips this call's permission prompt.
                                   Antigravity has no rewrite channel in its
                                   official output fields, so it is dropped there
  return { replaceOutput: "…" };             → replace the tool result (PostToolUse).
                                   The value may be a string (text-block hosts
                                   wrap it) or an object/array — Claude Code
                                   built-in tools ignore an updatedToolOutput
                                   whose value does not match the tool's
                                   output shape (Bash is
                                   {stdout,stderr,interrupted,isImage}), so
                                   only a structured value can replace those
  return { ask: "…", title?, gui?, timeout?, forceGui? };
      · gui tri-state (by default NOT set):
          gui: true    → force the topmost desktop dialog (pierces --no-gui;
                         only --dry-run skips it); same strength as forceGui:true
          unset/null   → host can ask: emit the host protocol ask (see V);
                         host cannot ask: GUI dialog as fallback, or an
                         auto-deny when no dialog is available
          gui: false   → no dialog: ask when the host can ask; otherwise
                         auto-deny (fail-closed)
      · timeout: seconds (default 60; <=0 treated as default); timeout = deny
      · forceGui: true → force the desktop dialog
        (same strength as gui: true)
  return false;                   → deny (auto-generated reason)
  Engine hard limits: rules MUST be synchronous; 5s watchdog; 64MB heap cap;
  no async/Promise, no import/require; single-file ES syntax only.
  Order: rules run in file-name lexicographic order; the first ask, deny, modify or
  keep-going short-circuits; allow / no-opinion never short-circuit. Directory loading
  order is deterministic.
  ⚠️ Order is semantic: inject / mutateInput / replaceOutput short-circuit too. If a
  "context injection" rule sorts before a "hard block" rule, the block never runs.
  Put blocking rules first when both must apply.
  ⚠️ Within one rule, deny/ask/keepGoing together with inject/mutateInput/
  replaceOutput: the gate decision wins and the modifiers are ignored — the
  engine prints a stderr notice, so never rely on a swallowed modifier.

V. Host decision matrix (can_ask × mode; output is mapped automatically)
--------------------------------------------------------------------------------
  platform       normal mode ask    YOLO / no-confirm        deny/allow transport
  claude_code    ✓ ask (terminal)   ✓ ask (official: "ask"
                                    prompts the user to confirm, and also
                                    forces the prompt in no-confirm modes)
                                                            hookSpecificOutput.permissionDecision
  codebuddy      ✓ ask (terminal)   ✓ ask (same as CC)       same
  codex          ✗ no ask in protocol ✗                      hookSpecificOutput.permissionDecision
                 (official: emitting an ask is parsed but unsupported — the
                  hook run is marked failed and the tool call CONTINUES, i.e.
                  fail open. Confirmations fall back to the GUI dialog, or
                  fail-closed deny when no dialog is available)
  workbuddy      ✓ ask (terminal)   ✓ ask (same as CC)       same
  gemini         ✗ no ask in protocol ✗                      top-level {decision, reason}
  antigravity    ✓ force_ask        ✗ (bypass: no prompt,
                                    GUI fallback)          top-level {decision, reason}
  generic        ✗ no ask protocol ✗                         hookSpecificOutput shape
  Confirm channel selection (gui tri-state × can_ask):
  · unset: can-ask hosts get the protocol ask directly; hosts that cannot
    ask fall back to the GUI dialog when available, or auto-deny when it is
    not (CI / --no-gui / tests);
  · gui:true / forceGui:true: force the dialog on every host (pierces --no-gui);
  · gui:false: can-ask hosts get ask; hosts that cannot ask are denied
    (no dialog, fail-closed).

  ── Event-name cheat sheet: host differences of ctx.event ──────────
  ctx.event always uses the Claude Code spelling; Codex / CodeBuddy /
  WorkBuddy / OpenCode (bridge) share the name verbatim. Only these hosts
  differ:
    PreToolUse        ← Gemini: BeforeTool
    PostToolUse       ← Gemini: AfterTool
    UserPromptSubmit  ← Gemini: BeforeAgent
    Stop              ← Gemini: AfterAgent;AGY: no event name, shape-inferred
    PreCompact        ← Gemini: PreCompress
    PreInvocation     ← AGY: shape-inferred (Pre/PostInvocation share one
                       input shape and are merged into this class)
  Antigravity's stdin carries no event name (official schema has no
  hook_event_name); the table above is what ai-hook infers from the envelope
  shape. AGY's PostToolUse is deliberately NOT inferred (the `error` key is
  undocumented for PreToolUse and a misclassification would drop the gate):
  post-tool payloads report as PreToolUse and any decision a rule emits there
  is ignored by the host (official PostToolUse output is `{}`). Host events
  ai-hook does not model (TaskCompleted / Notification / ConfigChange / …)
  surface with the host's own spelling in ctx.event — observable, not
  decidable.
  ── Native matcher cheat sheet: intercept goal × host tool names ───
  Run a command: CC Bash|PowerShell, Codex Bash, CB Bash, AGY run_command,
  Gemini run_shell_command, OpenCode bash (lowercase); write a file: Write /
  Write (alias apply_patch) / Write / write_to_file / write_file / write;
  edit: Edit / Edit (or apply_patch) / Edit / replace_file_content /
  replace / edit; read: Read / Read / Read / view_file / read_file / read.
  matcher syntax is host-specific: CC treats a value containing only
  [A-Za-z0-9_ ,|-] as an exact string/list, anything else as an unanchored
  regex (anchor with ^…$ for whole-name); Codex is officially a "regex
  string" (example anchors ^Bash$); CB is regex + case-sensitive, and a bare
  Write is a *containment* match (anchor ^Write$ for exact); AGY/Gemini use
  regex with "" or "*" matching all (Gemini regex only on tool events);
  OpenCode's bridge matches CC configs against *lowercase* tool ids,
  case-sensitively anchored — a CC-style "Bash" never hits opencode's bash,
  so write lowercase matchers there.
  MCP tool names: CC/Codex/CB use mcp__server__tool (double underscore; to
  match a whole server write mcp__server__.*), Gemini uses mcp_server_tool
  (single underscore). Rules read ctx.mcp.server / ctx.mcp.tool and never see
  the separator difference.
  Rules never need tool names: judge through the normalized views (ctx.cmd /
  ctx.file / ctx.mcp / ctx.web / ctx.search / ctx.agent); keep the native
  matcher wide so unrelated tool calls do not pay the hook's process cost.
  Example rules: examples/ (embedded in README §Rule Demos).

VI. Minimal integration
--------------------------------------------------------------------------------
  Claude Code (~/.claude/settings.json user-level, or <project>/.claude/settings.json
  project-level; the official docs do not use a standalone hooks.json):
    { "hooks": { "PreToolUse": [
        { "matcher": "Bash|Write|Edit|Read",
          "hooks": [{ "type": "command", "command": "ai-hook ./rules/protect.js" }] } ],
      "UserPromptSubmit": [
        { "hooks": [{ "type": "command", "command": "ai-hook ./rules/intercept.js" }] } ] } }
  CodeBuddy (~/.codebuddy/settings.json or <project>/.codebuddy/settings.json):
    same structure as above.
  Antigravity (~/.gemini/config/hooks.json or workspace .agents/hooks.json;
  the official schema wraps events in a top-level hook name with `enabled`):
    { "ai-hook-gate": { "enabled": true,
        "PreToolUse": [ { "matcher": "run_command|write_to_file|view_file",
          "hooks": [ { "command": "ai-hook ./rules/protect.js", "timeout": 70 } ] } ] } }
  Codex (~/.codex/hooks.json or inline config.toml): same envelope as Claude
  Code; matcher is regex. Codex requires trusting the hook via the /hooks
  panel — new or changed hooks are silently skipped until trusted.
  Gemini CLI (~/.gemini/settings.json hooks section): events use Gemini's own
  names (BeforeTool/AfterTool/...); the shell tool is named run_shell_command.
  Rule loading precedence: explicit CLI paths > AI_HOOK_RULES (path list,
  separator matches the platform PATH convention: ';' on Windows, ':' on
  Unix) > ./.ai-hook/rules.js or ./.ai-hook/rules/ directory (one level,
  name-sorted). Files starting with '_' and *.tmp.js/*.test.js are ignored.

VII. Debug & operations
--------------------------------------------------------------------------------
  ai-hook test <command> <rules…>    run one command through all rules; prints
                                     each rule's decision, timing and the exact
                                     host JSON. --platform picks the simulated
                                     host (default claude_code; also codex /
                                     codebuddy / workbuddy / gemini /
                                     antigravity / opencode)
  ai-hook bench -i 1000 -c <command> benchmark
  ai-hook list [<rules…>]            show actually loaded rules
  ai-hook clean [-n 14] [--dry-run]  actively clean and prune historical log files
                                     (keeps latest 14 files per category by default;
                                     alias ai-hook prune)
  ai-hook tutorial --lang zh         this document in Chinese
  --dry-run no dialogs; --no-gui disable dialogs; --force-gui force dialogs;
  --allow-on-error allow on rule failure; --no-fast-path disable the read-only
  whitelist bypass; --debug enable debug mode; AI_HOOK_LANG=zh|en pins language.
  AI_HOOK_DEBUG=1|true|on: record full raw host input, rule context,
  execution chain, and result to ~/.ai-hook/logs/ai-hook-debug-{agent}-{YYYYMMDD}.log
  (JSONL, 20MB rotation, zero hot-path deletion overhead; use ai-hook clean to prune
  and retain the latest 14 files; configure via AI_HOOK_DEBUG_MAX_FILES or
  AI_HOOK_LOG_MAX_FILES, or override destination with AI_HOOK_DEBUG_FILE).
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
