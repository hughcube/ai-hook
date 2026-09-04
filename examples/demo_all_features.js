/**
 * demo_all_features.js
 * 
 * ai-hook 全能力与上下文演示规则脚本 (Comprehensive Feature Demo)
 * 演示：
 * 1. 如何直接读取当前是什么类型 AI Agent (ctx.agent / ctx.agentType)
 * 2. 如何获取 AI 原始输入 (ctx.raw, ctx.rawInput) 与参数 (ctx.args)
 * 3. 如何调用 sys 极速自治能力 (时间/Git/文件/环境变量)
 * 4. 如何控制：直接强制阻断(不弹窗) vs 唤起吸附倒计时弹窗 vs 命令行终端确认
 */

export default function(ctx, sys) {
  // =========================================================================
  // 1. 获取当前是什么类型的 AI Agent
  // =========================================================================
  // ctx.agent / ctx.agentType 可取值：
  // - "antigravity" : Google Antigravity
  // - "claude_code"  : Anthropic Claude Code
  // - "codebuddy"    : CodeBuddy
  // - "codex"        : OpenAI Codex
  // - "generic"      : 通用/其他未知 Agent
  console.log(`[Demo] 当前 AI Agent: ${ctx.agent} (agentType: ${ctx.agentType})`);

  // =========================================================================
  // 2. 获取 AI 原始输入与工具上下文
  // =========================================================================
  // ctx.raw      : 宿主传入的完整原始 payload（已自动反序列化为 JS 对象）
  // ctx.rawInput : 宿主传入的原始 JSON 字符串
  // ctx.tool     : 当前调用的工具名称（如 "run_command", "write_to_file"）
  // ctx.cmd      : 命令行指令文本（如果是 run_command 等命令行工具）
  // ctx.file     : 目标文件路径（如果是文件读写工具）
  // ctx.cwd      : 当前工作目录
  // ctx.args     : 工具调用的完整参数对象（如 ctx.args.CommandLine, ctx.args.TargetFile）
  // ctx.isYolo   : 是否处于免确认/自动授权模式 (YOLO mode)
  console.log(`[Demo] 工具: ${ctx.tool}, 目录: ${ctx.cwd}`);
  if (ctx.cmd) console.log(`[Demo] 命令: ${ctx.cmd}`);
  if (ctx.raw) console.log(`[Demo] 原始 Payload Keys: ${Object.keys(ctx.raw).join(", ")}`);

  // =========================================================================
  // 3. 极速规则自治数据获取能力 (sys 原生内存级 API)
  // =========================================================================
  // 3.1 时间自治判断 (原生 JS new Date()，毫秒级获取周几、时段、封网期)
  const now = new Date();
  const isWeekend = now.getDay() === 0 || now.getDay() === 6;
  const isFridayAfternoon = now.getDay() === 5 && now.getHours() >= 16;

  // 3.2 Git 仓库自治感知 (0.02ms 纯内存读取，不启动 git.exe 子进程)
  const currentBranch = sys.git.branch(); // 返回当前分支名，如 "master", "main", "feature/..."
  const gitStatus = sys.git.status();     // 返回工作区状态信息

  // 3.3 文件与配置极速读取 (带单次请求单例内存缓存，0.01ms)
  const hasEnv = sys.fs.exists(".env");
  const envContent = hasEnv ? sys.fs.readText(".env") : "";

  // 3.4 环境变量获取
  const appEnv = sys.env("APP_ENV") || "local";

  // =========================================================================
  // 4. 决策控制：直接强制不通过 vs 弹窗确认 vs 终端确认 vs 放行
  // =========================================================================

  // 场景 A: 【直接强制不通过，绝对不弹窗】 (Direct Hard Block)
  // 核心分支强推等致命高危动作，直接拒绝，零弹窗打扰！
  if (ctx.cmd && /git\s+push\b.*(-f|--force)\b/.test(ctx.cmd)) {
    if (currentBranch === "master" || currentBranch === "main") {
      return {
        action: "deny", // 或 "block", "reject"
        reason: `【硬阻断】核心分支 '${currentBranch}' 严禁执行强制推送操作 (force-push)！`
      };
    }
  }

  // 场景 B: 【控制弹窗授权确认】 (Modern Fluent Card GUI Popup)
  // 敏感但允许人工复核的操作，唤起现代化置顶吸附卡片弹窗，支持自定义标题、超时倒计时：
  if (ctx.cmd && /\b(migrate|wipe|reset)\b/i.test(ctx.cmd)) {
    return {
      action: "confirm",   // 触发确认门禁
      title: "数据库结构变更授权", // 自定义弹窗标题
      reason: "检测到数据库重置或变更命令，可能影响现有数据！",
      gui: true,           // 显式指定呼出桌面现代化吸附弹窗 (默认 true)
      timeout: 45          // 自定义本次弹窗倒计时（秒），超时自动拒绝关闭
    };
  }

  // 场景 C: 【终端内交互确认，不唤起弹窗】 (Terminal-Only Ask)
  // 命令行内交互问询（如 Claude Code ask / Antigravity force_ask），不弹窗：
  if (ctx.cmd && /\b(npm\s+publish|cargo\s+publish)\b/i.test(ctx.cmd)) {
    return {
      action: "confirm",
      reason: "检测到版本发布命令，是否确认推送到公共制品库？",
      gui: false           // 设置为 false 则绝不弹窗，转为终端命令行提示
    };
  }

  // 场景 D: 【放行】 (Pass / Allow)
  return null;
}
