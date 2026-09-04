/**
 * Example 04: Dynamic Configuration & Environment Context (动态配置与特权账户管控)
 *
 * Demonstrates:
 * - Autonomous file existence check and content reading via `sys.fs.exists()` and `sys.fs.readText()`
 * - Request-scoped I/O caching (single-disk read per hook evaluation)
 * - Fine-grained identity-based access control (特权写账户管控，放行只读账户)
 */
export default function(ctx, sys) {
  const cmd = ctx.cmd || "";

  // 1. Check if database client is invoked
  if (/\b(mysql|mariadb|psql)\b/i.test(cmd)) {
    // 2. Privilege account check: xrapp_prod
    if (/(-u\s*|--user(=|\s+))xrapp_prod\b/i.test(cmd) || /psql.*-U\s*xrapp_prod\b/i.test(cmd)) {
      // Exclude readonly account
      if (!cmd.includes("xrapp_prod_readonly")) {
        return {
          action: "confirm",
          reason: "【生产特权写账户门禁】动用生产主账户 xrapp_prod 访问数据库，请核验 SQL 影响并确认！"
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
          action: "deny",
          reason: "【灾难防御】当前工作区 .env 绑定生产数据库，物理级严禁执行清库与重置迁移！"
        };
      }
    }
  }

  return null;
}
