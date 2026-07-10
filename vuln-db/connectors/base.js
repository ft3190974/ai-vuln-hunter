// vuln-db/connectors/base.js — Connector 基类
//
// 所有数据源 connector 的统一接口。模板方法模式：
//   ingest() = fetch() → normalize() → 灌入图谱/规则库
// 子类只需实现 fetch() 和 normalize()，灌入逻辑由基类统一。

class BaseConnector {
  /**
   * @param {string} name  数据源标识（nvd/osv/capec/nuclei）
   * @param {object} config  该源的配置（来自 vuln-db/config.js）
   */
  constructor(name, config) {
    this.name = name;
    this.config = config || {};
    this.lastSyncAt = null;
    this.lastSyncCount = 0;
    this.lastError = null;
  }

  /**
   * 拉取原始数据（子类必须实现）
   * @param {string|Date} [since]  增量起点（支持的数据源用）
   * @returns {Promise<object|array>}  原始数据
   */
  async fetch(_since) {
    throw new Error(`${this.name} connector 必须实现 fetch()`);
  }

  /**
   * 提供 mock 数据（测试用，子类覆盖）
   * @returns {object|array}
   */
  mockData() {
    throw new Error(`${this.name} connector 必须实现 mockData()`);
  }

  /**
   * 原始数据 → 统一结构（子类必须实现）
   * @returns {{nodes:Array, edges:Array, rules?:Array}}
   *   nodes: [{id, title, categories[], signature, ...}]
   *   edges: [{from, to, type}]
   *   rules: [{ruleId, ...}] （可选，nuclei 用）
   */
  normalize(_raw) {
    throw new Error(`${this.name} connector 必须实现 normalize()`);
  }

  /**
   * 模板方法：完整灌入流程
   * @param {object} deps  { knowledgeGraph, ruleEngine, live }
   * @param {string|Date} [since]
   * @returns {Promise<{source, fetched, nodes, edges, rules, error?}>}
   */
  async ingest(deps, since) {
    const { knowledgeGraph, ruleEngine, live = false } = deps;
    let raw;
    try {
      // live=true 才真实联网；否则用 mockData
      raw = live ? await this.fetch(since) : this.mockData();
    } catch (e) {
      this.lastError = e.message;
      return {
        source: this.name,
        fetched: 0,
        nodes: 0,
        edges: 0,
        rules: 0,
        error: e.message,
      };
    }

    const { nodes = [], edges = [], rules = [] } = this.normalize(raw);

    // 灌入知识图谱（store 已 async 化，用新接口 hasNode/setNodeField）
    if (knowledgeGraph) {
      for (const n of nodes) {
        await knowledgeGraph.addNode(n.id, n.title, n.categories, n.signature);
        // 补充节点扩展字段（attackPattern 等）
        if (n.attackPattern && await knowledgeGraph.hasNode(n.id)) {
          await knowledgeGraph.setNodeField(n.id, "attackPattern", n.attackPattern);
        }
      }
      for (const e of edges) {
        await knowledgeGraph.addEdge(e.from, e.to, e.type);
      }
    }

    // 灌入规则库（nuclei 用；ruleEngine.add 已 async 化）
    if (ruleEngine && rules.length > 0) {
      for (const r of rules) {
        await ruleEngine.add(r);
      }
    }

    this.lastSyncAt = new Date().toISOString();
    this.lastSyncCount = nodes.length + rules.length;
    this.lastError = null;

    return {
      source: this.name,
      fetched: nodes.length + edges.length + rules.length,
      nodes: nodes.length,
      edges: edges.length,
      rules: rules.length,
    };
  }

  /** 返回当前同步状态 */
  status() {
    return {
      source: this.name,
      enabled: this.config.enabled !== false,
      lastSyncAt: this.lastSyncAt,
      lastSyncCount: this.lastSyncCount,
      lastError: this.lastError,
    };
  }
}

module.exports = { BaseConnector };
