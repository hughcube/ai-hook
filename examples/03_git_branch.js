/**
 * Example 03: Git Branch-Aware Protection (Git 分支感知与保护)
 *
 * Demonstrates:
 * - Ultra-fast branch query via `sys.git.branch()` (Rust pure-memory HEAD read, 0.02ms, 0 external processes)
 * - Block force-push to main/master branches (严禁向主分支强制推送)
 */
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // Check if current command is a git push
  if (/git\s+push\b/i.test(cmd)) {
    // Autonomously query current Git branch
    const currentBranch = sys.git.branch();
    console.log("Current Git branch:", currentBranch);

    if (currentBranch === "master" || currentBranch === "main") {
      // Check for force push flags
      if (/\s+(-f|--force|--force-with-lease)\b/.test(cmd)) {
        return {
          action: "deny",
          reason: `【分支安全门禁】当前处于核心生产分支 '${currentBranch}'，严禁执行强制推送操作！`
        };
      }
    }
  }

  return null;
}
