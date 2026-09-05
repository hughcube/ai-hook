/**
 * Example 01: Basic High-Risk Command Interception (基础高危命令拦截)
 *
 * Demonstrates:
 * - Simple regex testing against `ctx.cmd` (对命令进行正则匹配)
 * - Returning action "deny" (硬阻断) or "confirm" (弹窗确认)
 */
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // 1. Block root deletion (绝对禁止删除根目录或盘符根)
  if (/rm\s+-rf\s+(\/|[a-zA-Z]:[/\\]|\*|\/\*)(\s+|$)/i.test(cmd)) {
    return {
      action: "deny",
      reason: "【硬阻断】严禁在 Agent 中执行整盘或根目录物理删除命令！"
    };
  }

  // 2. Confirm Redis flushall/flushdb (清空缓存需要确认)
  if (/\b(FLUSHALL|FLUSHDB)\b/i.test(cmd)) {
    return {
      action: "confirm",
      reason: "检测到清空全库 Redis 缓存操作，请确认环境与影响范围。"
    };
  }

  // Pass (放行)
  return null;
}
