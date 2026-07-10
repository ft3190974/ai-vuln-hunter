// vuln-db/connectors/osv-connector.js — OSV.dev（Google 开源漏洞聚合）连接器
//
// 数据源：https://api.osv.dev/v1
// 覆盖生态最全（PyPI/npm/Maven/Go/Rust/Linux），NVD 的补充。
// 查询方式：POST /v1/query/batch（按 package 批量）或 GET /v1/vulns/:id

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class OsvConnector extends BaseConnector {
  constructor() {
    super("osv", vulnDbConfig.sources.osv);
  }

  /**
   * 真实拉取：用 seedPackages 批量查询
   */
  async fetch(_since) {
    const { apiUrl, seedPackages, timeoutMs } = this.config;
    const all = [];
    // OSV 批量查询接口（最多 1000 个 package/请求）
    const batchBody = {
      queries: (seedPackages || []).map((p) => ({ package: p.package })),
    };
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetch(`${apiUrl}/querybatch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batchBody),
        signal: ctrl.signal,
      });
      if (!resp.ok) throw new Error(`OSV API ${resp.status}`);
      const data = await resp.json();
      // data.results 是每个 query 的 vuln id 列表，需逐个拉详情（简化：直接用 id 当节点）
      for (const r of data.results || []) {
        for (const v of r.vulns || []) {
          all.push({ id: v.id, queryPackage: "seed" });
        }
      }
    } finally {
      clearTimeout(timer);
    }
    return all;
  }

  /**
   * Mock 数据：跨生态两条（Python + npm）
   */
  mockData() {
    return [
      {
        id: "GHSA-jfh8-c2jp-5v3q",
        queryPackage: "python-pillow",
        summary: "Pillow buffer overflow in ICCProfile",
        details: "Pillow before 8.3.2 has a buffer overflow in IccProfile.",
        affected: [
          {
            package: { name: "Pillow", ecosystem: "PyPI" },
            ranges: [{ events: [{ fixed: "8.3.2" }] }],
          },
        ],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      },
      {
        id: "OSV-2022-001",
        queryPackage: "node-express",
        summary: "Express prototype pollution via query string parser",
        details: "Express before 4.17.3 allows prototype pollution.",
        affected: [
          {
            package: { name: "express", ecosystem: "npm" },
            ranges: [{ events: [{ fixed: "4.17.3" }] }],
          },
        ],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      },
    ];
  }

  normalize(rawList) {
    const nodes = [];
    for (const v of rawList) {
      const id = v.id;
      if (!id) continue;
      const title = v.summary || v.details?.slice(0, 200) || id;
      // affected 包作为 sink 启发
      const sink = (v.affected || []).map((a) => a.package?.name).filter(Boolean);
      const cvssScore = v.severity?.[0]?.score;
      nodes.push({
        id,
        title: typeof title === "string" ? title.slice(0, 200) : id,
        categories: this._inferCategory(title + " " + (v.details || "")),
        signature: {
          source: [],
          sink,
        },
        cvss: cvssScore ? { vector: cvssScore } : undefined,
      });
    }
    return { nodes, edges: [] };
  }

  /** 从描述推断类别（OSV 不一定有 CWE，靠关键词） */
  _inferCategory(text) {
    const t = (text || "").toLowerCase();
    const cats = [];
    if (t.includes("sql injection") || t.includes("sqli")) cats.push("sqli");
    if (t.includes("command injection") || t.includes("rce")) cats.push("cmdi");
    if (t.includes("xss") || t.includes("cross-site scripting")) cats.push("xss");
    if (t.includes("buffer overflow") || t.includes("heap overflow")) cats.push("overflow");
    if (t.includes("use-after-free")) cats.push("uaf");
    if (t.includes("deserialization") || t.includes("deserialize")) cats.push("deserialization");
    if (t.includes("prototype pollution")) cats.push("business_logic");
    if (t.includes("path traversal") || t.includes("directory traversal")) cats.push("path_traversal");
    if (t.includes("ssrf")) cats.push("ssrf");
    return cats.length > 0 ? cats : ["unknown"];
  }
}

module.exports = { OsvConnector };
