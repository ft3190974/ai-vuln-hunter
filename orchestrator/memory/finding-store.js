// memory/finding-store.js — Finding 持久化（内存 + JSON 文件，重启不丢）
//
// 所有方法均为 async，与 DB 版接口一致。
// 启动时从 JSON 文件加载，每次变更后自动保存。

const fs = require("fs");
const path = require("path");

const PERSIST_FILE = process.env.FINDING_STORE_FILE || path.join(process.cwd(), "data", "findings.json");

class FindingStore {
  constructor() {
    this.findings = [];
    this.counter = 0;
    this._load();
  }

  /** 从文件加载（启动时） */
  _load() {
    try {
      if (fs.existsSync(PERSIST_FILE)) {
        const data = JSON.parse(fs.readFileSync(PERSIST_FILE, "utf-8"));
        this.findings = data.findings || [];
        this.counter = data.counter || this.findings.length;
      }
    } catch (e) {
      console.warn("[FindingStore] 加载持久化文件失败:", e.message);
    }
  }

  /** 保存到文件（每次变更后调用） */
  _save() {
    try {
      const dir = path.dirname(PERSIST_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(PERSIST_FILE, JSON.stringify({ findings: this.findings, counter: this.counter }, null, 2));
    } catch (e) {
      console.warn("[FindingStore] 保存持久化文件失败:", e.message);
    }
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
    this._save();
    return finding;
  }

  async update(findingId, patch) {
    const f = this.findings.find((x) => x.findingId === findingId);
    if (!f) return null;
    Object.assign(f, patch, { updatedAt: new Date().toISOString() });
    this._save();
    return f;
  }

  async get(findingId) {
    return this.findings.find((x) => x.findingId === findingId) || null;
  }

  async remove(findingId) {
    const idx = this.findings.findIndex((x) => x.findingId === findingId);
    if (idx === -1) return false;
    this.findings.splice(idx, 1);
    this._save();
    return true;
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
    const bySeverity = {};
    for (const f of this.findings) {
      byStatus[f.status] = (byStatus[f.status] || 0) + 1;
      if (f.severity) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    }
    return { total: this.findings.length, byStatus, bySeverity };
  }
}

module.exports = { FindingStore };
