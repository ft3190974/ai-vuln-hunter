// memory/knowledge-graph.js — 漏洞知识图谱（内存版，全 async）
//
// 所有方法均为 async，与 DB 版（neo4j-knowledge-graph.js）接口一致。
// 生产环境用 Neo4j；此处用内存 Map 演示，保留图遍历接口。
//
// ★ 接口增强：新增显式方法替换对 nodes/edges 的直接属性访问，
//   使 DB 版可以无感替换（DB 不能暴露内部 Map/Array）：
//   getNode(id) / hasNode(id) / listNodes() / listEdges() / setNodeField(id,field,value)
//
// 关系类型（边）：VARIANT_OF / BYPASS_OF / SAME_ROOT / DUAL_USE

class KnowledgeGraph {
  constructor() {
    /** CVE/CWE 节点（保留为内部 Map，外部用 listNodes/getNode 访问） */
    this.nodes = new Map();
    /** 边：[{from, to, type}]（保留为内部 Array，外部用 listEdges 访问） */
    this.edges = [];
    this._seed();
  }

  _seed() {
    // 预置几条 CVE 与变种关系，演示 0-day 挖掘的图谱遍历
    this.nodes.set("CVE-2021-44228", {
      id: "CVE-2021-44228", title: "log4j JNDI 注入",
      categories: ["sqli", "deserialization"],
      signature: { source: ["http.header.*", "http.param.*"], sink: ["JndiLookup.lookup"] },
      createdAt: new Date().toISOString(),
    });
    this.nodes.set("CVE-2022-23305", {
      id: "CVE-2022-23305", title: "log4j 变种（绕过修复）",
      categories: ["deserialization"],
      signature: { source: ["http.body.*"], sink: ["JndiLookup.lookup"] },
      createdAt: new Date().toISOString(),
    });
    this.nodes.set("CVE-2023-XXXX", {
      id: "CVE-2023-XXXX", title: "未知变种（0-day 候选）",
      categories: ["deserialization"],
      signature: { source: ["http.param.data"], sink: ["readObject"] },
      createdAt: new Date().toISOString(),
    });
    this.edges.push({ from: "CVE-2022-23305", to: "CVE-2021-44228", type: "VARIANT_OF", createdAt: new Date().toISOString() });
    this.edges.push({ from: "CVE-2022-23305", to: "CVE-2021-44228", type: "BYPASS_OF", createdAt: new Date().toISOString() });
    this.edges.push({ from: "CVE-2023-XXXX", to: "CVE-2021-44228", type: "VARIANT_OF", createdAt: new Date().toISOString() });
  }

  async addNode(id, title, categories, signature) {
    this.nodes.set(id, {
      id, title, categories: categories || [], signature: signature || {},
      createdAt: new Date().toISOString(),
    });
  }

  async addEdge(from, to, type) {
    this.edges.push({ from, to, type, createdAt: new Date().toISOString() });
  }

  /** 查询单个节点（替换原 nodes.get(id)） */
  async getNode(id) {
    return this.nodes.get(id) || null;
  }

  /** 节点是否存在（替换原 nodes.has(id)） */
  async hasNode(id) {
    return this.nodes.has(id);
  }

  /** 设置节点的扩展字段（替换原 nodes.get(id).field = value） */
  async setNodeField(id, field, value) {
    const node = this.nodes.get(id);
    if (node) node[field] = value;
    return node;
  }

  /** 列出所有节点快照（替换原 [...nodes.values()]） */
  async listNodes() {
    return [...this.nodes.values()];
  }

  /** 列出所有边快照（替换原直接遍历 edges） */
  async listEdges() {
    return [...this.edges];
  }

  /**
   * 查询某 CVE 的所有变种（沿 VARIANT_OF / BYPASS_OF 边遍历）
   */
  async findVariants(cveId) {
    const related = this.edges
      .filter((e) => (e.from === cveId || e.to === cveId) &&
        (e.type === "VARIANT_OF" || e.type === "BYPASS_OF"))
      .map((e) => (e.from === cveId ? e.to : e.from));
    return [...new Set(related)].map((id) => this.nodes.get(id)).filter(Boolean);
  }

  /**
   * 按 source/sink 签名检索相似漏洞
   */
  async findBySignature(signature) {
    const sinkSet = new Set(signature.sink || []);
    return [...this.nodes.values()].filter((n) => {
      const nodeSinks = n.signature?.sink || [];
      return nodeSinks.some((s) => [...sinkSet].some((x) => s.includes(x) || x.includes(s)));
    });
  }

  async stats() {
    return { nodes: this.nodes.size, edges: this.edges.length };
  }
}

module.exports = { KnowledgeGraph };
