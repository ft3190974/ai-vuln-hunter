// migrations/migrate.js — 数据库迁移执行器
//
// 按顺序执行 migrations/*.sql，跟踪已应用的版本（schema_migrations 表）。
// 幂等：已执行的跳过。
//
// 用法：
//   node migrations/migrate.js                              # 跑全部未应用迁移
//   DATABASE_URL=postgres://... node migrations/migrate.js   # 指定数据库
//   node migrations/migrate.js --dry-run                     # 只打印不执行

const fs = require("fs");
const path = require("path");

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("错误：请设置 DATABASE_URL 环境变量");
    console.error("例：DATABASE_URL=postgres://user:pass@host:5432/db node migrations/migrate.js");
    process.exit(1);
  }

  let pg;
  try { pg = require("pg"); } catch {
    console.error("错误：缺少 pg 依赖。在 orchestrator/ 下 npm install pg，或在 web/server/ 下。");
    process.exit(1);
  }

  const pool = new pg.Pool({ connectionString: databaseUrl });
  const migrationsDir = __dirname;

  // 列出所有迁移文件（按文件名排序）
  const files = fs.readdirSync(migrationsDir)
    .filter((f) => /^\d+_.*\.sql$/.test(f))
    .sort();

  console.log(`找到 ${files.length} 个迁移文件${dryRun ? "（dry-run 模式）" : ""}`);

  try {
    // 确保版本表存在
    await pool.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, name VARCHAR(200) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    const applied = (await pool.query("SELECT version FROM schema_migrations")).rows.map((r) => r.version);

    for (const file of files) {
      const version = parseInt(file.match(/^(\d+)_/)[1], 10);
      if (applied.includes(version)) {
        console.log(`  ✓ ${file}（已应用，跳过）`);
        continue;
      }
      const sql = fs.readFileSync(path.join(migrationsDir, file), "utf-8");
      if (dryRun) {
        console.log(`  [DRY] 将执行 ${file} (${sql.length} 字符)`);
        continue;
      }
      console.log(`  ▶ 执行 ${file} ...`);
      await pool.query(sql);
      await pool.query("INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", [version, file]);
      console.log(`  ✓ ${file} 完成`);
    }
    console.log("迁移完成");
  } catch (e) {
    console.error("迁移失败:", e.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
