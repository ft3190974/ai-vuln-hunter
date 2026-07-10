// memory/false-positive-store.js — 误报库（内存版，全 async）
//
// 存储已知安全模式（SAST 误报）与 LLM 幻觉样本。
// 检测 Agent 在 LLM 深判前查询此库，命中即降级/丢弃，避免幻觉放大。
// 与 DB 版（pg-fp-store.js）接口一致。

class FalsePositiveStore {
  constructor() {
    /** @type {Array<{id,category,pattern,action,reason,source}>} */
    this.items = [];
    this._seed();
  }

  _seed() {
    this.items.push(
      this._make({
        category: "sqli",
        pattern: /PreparedStatement|prepareStatement|\?\s*[,)]|@Query|@Param/i,
        action: "drop",
        reason: "已使用参数化查询/ORM 注解，无 SQL 注入",
        source: "seed",
      }),
      this._make({
        category: "cmdi",
        pattern: /ProcessBuilder|whitelist\s*\(|allowList/i,
        action: "drop",
        reason: "已使用白名单/ProcessBuilder 安全构造",
        source: "seed",
      }),
      this._make({
        category: "xss",
        pattern: /escapeHtml|sanitize\(|DOMPurify|@CrossOrigin/i,
        action: "drop",
        reason: "已做输出编码/转义",
        source: "seed",
      })
    );
  }

  _make(entry) {
    return {
      id: `FP-${this.items.length + 1}`,
      category: entry.category,
      pattern: entry.pattern instanceof RegExp ? entry.pattern : new RegExp(entry.pattern),
      action: entry.action || "drop",
      reason: entry.reason || "",
      source: entry.source || "manual",
      createdAt: new Date().toISOString(),
    };
  }

  async add(entry) {
    const item = this._make(entry);
    this.items.push(item);
    return item;
  }

  async match(code, category) {
    for (const item of this.items) {
      if (item.category !== category && item.category !== "*") continue;
      if (item.pattern.test(code)) {
        return { hit: true, action: item.action, reason: item.reason, fpId: item.id };
      }
    }
    return { hit: false };
  }

  async list() {
    return [...this.items];
  }
}

module.exports = { FalsePositiveStore };
