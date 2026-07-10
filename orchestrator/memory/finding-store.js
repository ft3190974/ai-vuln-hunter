// memory/finding-store.js — Finding 持久化（内存版，全 async）
//
// 所有方法均为 async，与 DB 版（pg-finding-store.js）接口一致，可无感替换。
// 生产环境用 Postgres（JSONB 存整个 Finding 对象），此处用内存数组演示。

class FindingStore {
  constructor() {
    /** @type {Array<Object>} */
    this.findings = [];
    this.counter = 0;
  }

  /** 生成下一个 findingId（格式 F-YYYY-NNNNNN） */
  async nextId() {
    this.counter += 1;
    const year = new Date().getFullYear();
    return `F-${year}-${String(this.counter).padStart(6, "0")}`;
  }

  /**
   * 创建并保存 Finding
   * @param {Object} partial  部分 Finding 字段（不含 findingId/createdAt）
   */
  async create(partial) {
    const finding = {
      findingId: await this.nextId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      status: "candidate",
      ...partial,
    };
    this.findings.push(finding);
    return finding;
  }

  async update(findingId, patch) {
    const f = this.findings.find((x) => x.findingId === findingId);
    if (!f) return null;
    Object.assign(f, patch, { updatedAt: new Date().toISOString() });
    return f;
  }

  async get(findingId) {
    return this.findings.find((x) => x.findingId === findingId) || null;
  }

  async query(filter = {}) {
    return this.findings.filter((f) => {
      if (filter.status && f.status !== filter.status) return false;
      if (filter.category && f.category !== filter.category) return false;
      if (filter.minConfidence && f.confidence < filter.minConfidence) return false;
      if (filter.scanId && f.scanId !== filter.scanId) return false;
      return true;
    });
  }

  async all() {
    return [...this.findings];
  }

  async stats() {
    const byStatus = {};
    for (const f of this.findings) {
      byStatus[f.status] = (byStatus[f.status] || 0) + 1;
    }
    return { total: this.findings.length, byStatus };
  }
}

module.exports = { FindingStore };
