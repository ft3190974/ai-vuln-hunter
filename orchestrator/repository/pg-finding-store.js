// repository/pg-finding-store.js — Postgres 版 FindingStore
//
// 与内存版接口完全一致（全 async），可无感替换。
// Finding 整体存 JSONB，关键字段冗余列方便索引查询。

class PgFindingStore {
  constructor(pool) {
    this.pool = pool;
    this.counter = 0;
  }

  async nextId() {
    this.counter += 1;
    const year = new Date().getFullYear();
    return `F-${year}-${String(this.counter).padStart(6, "0")}`;
  }

  async create(partial) {
    const finding = {
      findingId: await this.nextId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      status: "candidate",
      ...partial,
    };
    await this.pool.query(
      `INSERT INTO findings (finding_id, data, status, category, severity, confidence, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, now())`,
      [finding.findingId, JSON.stringify(finding), finding.status,
       finding.category || null, finding.severity || null, finding.confidence || null]
    );
    return finding;
  }

  async update(findingId, patch) {
    const cur = await this.get(findingId);
    if (!cur) return null;
    const updated = { ...cur, ...patch, updatedAt: new Date().toISOString() };
    await this.pool.query(
      `UPDATE findings SET data=$2, status=$3, category=$4, severity=$5, confidence=$6 WHERE finding_id=$1`,
      [findingId, JSON.stringify(updated), updated.status, updated.category || null,
       updated.severity || null, updated.confidence || null]
    );
    return updated;
  }

  async get(findingId) {
    const r = await this.pool.query("SELECT data FROM findings WHERE finding_id=$1", [findingId]);
    return r.rows[0] ? r.rows[0].data : null;
  }

  async query(filter = {}) {
    let sql = "SELECT data FROM findings WHERE 1=1";
    const params = [];
    if (filter.status) { params.push(filter.status); sql += ` AND status=$${params.length}`; }
    if (filter.category) { params.push(filter.category); sql += ` AND category=$${params.length}`; }
    if (filter.minConfidence) { params.push(filter.minConfidence); sql += ` AND confidence>=$${params.length}`; }
    const r = await this.pool.query(sql, params);
    return r.rows.map((row) => row.data);
  }

  async all() {
    const r = await this.pool.query("SELECT data FROM findings");
    return r.rows.map((row) => row.data);
  }

  async stats() {
    const r = await this.pool.query(
      "SELECT status, count(*) AS n FROM findings GROUP BY status"
    );
    const byStatus = {};
    let total = 0;
    for (const row of r.rows) { byStatus[row.status] = Number(row.n); total += Number(row.n); }
    return { total, byStatus };
  }
}

module.exports = { PgFindingStore };
