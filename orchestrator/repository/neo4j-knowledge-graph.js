// repository/neo4j-knowledge-graph.js — Neo4j 版 KnowledgeGraph
//
// 与内存版接口完全一致（全 async）。
// 节点 label: Vulnerability；关系类型：VARIANT_OF / BYPASS_OF / SAME_ROOT / DUAL_USE。
//
// 需要：neo4j-driver。本地无 Neo4j 时由 factory 降级到内存版。

class Neo4jKnowledgeGraph {
  constructor(driver) {
    this.driver = driver;
    this._seeded = false;
  }

  async _seed() {
    if (this._seeded) return;
    this._seeded = true;
    const session = this.driver.session();
    try {
      // 建约束 + 种子数据
      await session.run("CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE");
      const seeds = [
        { id: "CVE-2021-44228", title: "log4j JNDI 注入", cats: ["sqli", "deserialization"], sink: "JndiLookup.lookup", source: "http.header.*" },
        { id: "CVE-2022-23305", title: "log4j 变种（绕过修复）", cats: ["deserialization"], sink: "JndiLookup.lookup", source: "http.body.*" },
        { id: "CVE-2023-XXXX", title: "未知变种（0-day 候选）", cats: ["deserialization"], sink: "readObject", source: "http.param.data" },
      ];
      for (const s of seeds) {
        await session.run(
          `MERGE (v:Vulnerability {id: $id}) SET v.title=$title, v.categories=$cats, v.signature=$sig`,
          { id: s.id, title: s.title, cats: s.cats, sig: JSON.stringify({ source: [s.source], sink: [s.sink] }) }
        );
      }
      await session.run(`MATCH (a:Vulnerability {id:"CVE-2022-23305"}), (b:Vulnerability {id:"CVE-2021-44228"}) MERGE (a)-[:VARIANT_OF]->(b)`);
      await session.run(`MATCH (a:Vulnerability {id:"CVE-2022-23305"}), (b:Vulnerability {id:"CVE-2021-44228"}) MERGE (a)-[:BYPASS_OF]->(b)`);
      await session.run(`MATCH (a:Vulnerability {id:"CVE-2023-XXXX"}), (b:Vulnerability {id:"CVE-2021-44228"}) MERGE (a)-[:VARIANT_OF]->(b)`);
    } finally {
      await session.close();
    }
  }

  async addNode(id, title, categories, signature) {
    const session = this.driver.session();
    try {
      await session.run(
        `MERGE (v:Vulnerability {id: $id}) SET v.title=$title, v.categories=$cats, v.signature=$sig, v.createdAt=timestamp()`,
        { id, title, cats: categories || [], sig: JSON.stringify(signature || {}) }
      );
    } finally { await session.close(); }
  }

  async addEdge(from, to, type) {
    const session = this.driver.session();
    try {
      await session.run(
        `MATCH (a:Vulnerability {id:$from}), (b:Vulnerability {id:$to})
         MERGE (a)-[r:%TYPE%]->(b) SET r.createdAt=timestamp()`,
        { from, to, type }
      );
    } finally { await session.close(); }
  }

  async getNode(id) {
    const session = this.driver.session();
    try {
      const r = await session.run("MATCH (v:Vulnerability {id:$id}) RETURN v", { id });
      if (r.records.length === 0) return null;
      return this._recordToNode(r.records[0].get("v"));
    } finally { await session.close(); }
  }

  async hasNode(id) {
    const session = this.driver.session();
    try {
      const r = await session.run("MATCH (v:Vulnerability {id:$id}) RETURN count(v) AS n", { id });
      return r.records[0].get("n").toNumber() > 0;
    } finally { await session.close(); }
  }

  async setNodeField(id, field, value) {
    const session = this.driver.session();
    try {
      await session.run(`MATCH (v:Vulnerability {id:$id}) SET v.$field=$value`, { id, field, value: JSON.stringify(value) });
    } finally { await session.close(); }
    return await this.getNode(id);
  }

  async listNodes() {
    const session = this.driver.session();
    try {
      const r = await session.run("MATCH (v:Vulnerability) RETURN v");
      return r.records.map((rec) => this._recordToNode(rec.get("v")));
    } finally { await session.close(); }
  }

  async listEdges() {
    const session = this.driver.session();
    try {
      const r = await session.run("MATCH (a:Vulnerability)-[rel]->(b:Vulnerability) RETURN a.id AS from, b.id AS to, type(rel) AS type");
      return r.records.map((rec) => ({ from: rec.get("from"), to: rec.get("to"), type: rec.get("type") }));
    } finally { await session.close(); }
  }

  async findVariants(cveId) {
    await this._seed();
    const session = this.driver.session();
    try {
      const r = await session.run(
        `MATCH (n:Vulnerability {id:$id})-[:VARIANT_OF|BYPASS_OF*1..5]-(m:Vulnerability)
         WHERE m.id <> $id RETURN DISTINCT m`,
        { id: cveId }
      );
      return r.records.map((rec) => this._recordToNode(rec.get("m")));
    } finally { await session.close(); }
  }

  async findBySignature(signature) {
    const session = this.driver.session();
    try {
      // 简化：拉全部节点在内存做 sink 包含匹配（小规模够用；大规模用全文索引）
      const r = await session.run("MATCH (v:Vulnerability) RETURN v");
      const sinkSet = new Set(signature.sink || []);
      return r.records.map((rec) => this._recordToNode(rec.get("v"))).filter((n) => {
        const nodeSinks = n.signature?.sink || [];
        return nodeSinks.some((s) => [...sinkSet].some((x) => s.includes(x) || x.includes(s)));
      });
    } finally { await session.close(); }
  }

  async stats() {
    const session = this.driver.session();
    try {
      const nodes = await session.run("MATCH (v:Vulnerability) RETURN count(v) AS n");
      const edges = await session.run("MATCH (:Vulnerability)-[r]->(:Vulnerability) RETURN count(r) AS n");
      return { nodes: nodes.records[0].get("n").toNumber(), edges: edges.records[0].get("n").toNumber() };
    } finally { await session.close(); }
  }

  _recordToNode(v) {
    const props = v.properties || {};
    let sig = props.signature;
    if (typeof sig === "string") { try { sig = JSON.parse(sig); } catch { sig = {}; } }
    return { id: props.id, title: props.title, categories: props.categories || [], signature: sig || {}, createdAt: props.createdAt };
  }
}

module.exports = { Neo4jKnowledgeGraph };
