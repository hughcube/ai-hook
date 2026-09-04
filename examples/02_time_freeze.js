/**
 * Example 02: Dynamic Time Window & Freeze Period Control (动态时间窗口与封网期管控)
 *
 * Demonstrates:
 * - Autonomous time fetching using JavaScript standard `new Date()` (自主获取时间与计算)
 * - Friday afternoon freeze protection (周五封网期保护：16:00 后严禁生产写操作与数据库迁移)
 * - Holiday date freeze list (特定节假日封网名单控制)
 */
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";
  const now = new Date();

  const dayOfWeek = now.getDay(); // 0 is Sunday, 5 is Friday
  const hour = now.getHours();

  // 1. Friday 16:00+ Deployment Freeze (周五下午 16:00 后禁止生产环境数据库迁移)
  if (dayOfWeek === 5 && hour >= 16) {
    if (/migrate:(fresh|reset|refresh)|db:wipe/i.test(cmd)) {
      return {
        action: "deny",
        reason: `【封网期保护】当前为周五下午 (${hour}:00)，系统处于发布封网期，严禁执行数据库重置或迁移！`
      };
    }
  }

  // 2. Specific calendar freeze dates (特定节假日封网日期)
  const todayStr = now.toISOString().slice(0, 10); // e.g. "2026-10-01"
  const freezeDates = ["2026-10-01", "2026-10-02", "2026-10-03"];

  if (freezeDates.includes(todayStr) && /production|prod/i.test(cmd)) {
    return {
      action: "deny",
      reason: `【节日封网】当前处于重要保障期(${todayStr})，禁止任何生产环境变更操作！`
    };
  }

  return null;
}
