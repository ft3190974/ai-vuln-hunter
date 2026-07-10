// repository/pg-fp-store.js — Postgres 版 FalsePositiveStore

class PgFpStore {
  constructor(pool) {
    this.pool = pool;
    this._seeded = false;
  }

  async _seed() {
    if (this._seeded) return;
    this._seeded = true;
    const seeds = [
      { category: "sqli", pattern: "PreparedStatement|prepareStatement|\\?\\s*[,)]|@Query|@Param", reason: "已使用参数化查询/ORM 注解" },
      { category: "cmdi", pattern: "ProcessBuilder|whitelist\\s*\\(|allowList", reason: "已使用白名单/ProcessBuilder" },
      { category: "xss", pattern: "escapeHtml|sanitize\\(|DOMPurify", reason: "已做输出编码/转义" },
    ];
    for (const s of seeds) {
      await this.pool.query(
        `INSERT INTO false_positives (category, pattern, action, reason, source) VALUES ($1,$2,'drop',$3,'seed')
         ON CONFLICT DO NOTHING`,
        [s.category, s.pattern, s.reason]
      );
    }
  }

  async add(entry) {
    const pattern = entry.pattern instanceof RegExp ? entry.pattern.source : String(entry.pattern);
    const r = await this.pool.query(
      `INSERT INTO false_positives (category, pattern, action, reason, source) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [entry.category, pattern, entry.action || "drop", entry.reason || "", entry.source || "manual"]
    );
    return { id: `FP-${r.rows[0].id}`, ...entry, pattern };
  }

  async match(code, category) {
    await this._seed();
    const r = await this.pool.query(
      `SELECT id, pattern, action, reason FROM false_positives WHERE category=$1 OR category='*'`
    );
    for (const row of r.rows) {
      try {
        if (new RegExp(row.pattern).test(code)) {
          return { hit: true, action: row.action, reason: row.reason, fpId: `FP-${row.id}` };
        }
      } catch { /* 非法正则跳过 */ }
    }
    return { hit: false };
  }

  async list() {
    const r = await this.pool.query("SELECT id, category, pattern, action, reason, source, created_at FROM false_positives ORDER BY id");
    return r.rows.map((row) => ({
      id: `FP-${row.id}`, category: row.category, pattern: row.pattern,
      action: row.action, reason: row.reason, source: row.source, createdAt: row.created_at,
    }));
  }
}

module.exports = { PgFpStore };
