// vuln-db/connectors/vulncheck-connector.js — Vulncheck NVD++（威胁情报增强漏洞库）
//
// Vulncheck 是 NVD 的商业化增强版，含威胁情报（CPE 影响范围、EPSS、利用状态等）。
// 数据获取：Vulncheck API（需 API key）
// 官网：https://vulncheck.com/

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class VulncheckConnector extends BaseConnector {
  constructor() {
    super("vulncheck", vulnDbConfig.sources.vulncheck);
  }

  async fetch(since) {
    const { apiUrl, apiKey, timeoutMs } = this.config;
    if (!apiKey) throw new Error("Vulncheck 需要 API key（设置 VULNDB_VULNCHECK_API_KEY）");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const headers = { "Accept": "application/json" };
      const params = new URLSearchParams({ limit: "100" });
      if (since) params.set("lastModStartDate", since.slice(0, 10));
      const resp = await fetch(`${apiUrl}?${params}`, {
        signal: ctrl.signal,
        headers: { ...headers, "Authorization": `Bearer ${apiKey}` },
      });
      if (!resp.ok) throw new Error(`Vulncheck API ${resp.status}`);
      const data = await resp.json();
      return data.data || data._embedded?.vulncheck_nvd_objects || [];
    } finally { clearTimeout(timer); }
  }

  mockData() {
    return [
      { cveId: "CVE-2023-23397", title: "Microsoft Outlook Elevation of Privilege",
        cvssScore: 9.8, epssScore: 0.97,
        threatIntel: { exploitedInTheWild: true, ransomwareUse: true },
        description: "Microsoft Outlook 权限提升漏洞，已被 APT 组织在野利用。",
        affectedProducts: ["Microsoft Outlook 2016", "Microsoft Office 2019"] },
      { cveId: "CVE-2023-34362", title: "MOVEit Transfer SQL Injection",
        cvssScore: 9.8, epssScore: 0.99,
        threatIntel: { exploitedInTheWild: true, ransomwareUse: true, c2Servers: ["example.com"] },
        description: "MOVEit Transfer SQL 注入，Cl0p 勒索组织大规模利用。",
        affectedProducts: ["MOVEit Transfer < 15.0.2"] },
      { cveId: "CVE-2023-4966", title: "Citrix NetScaler Info Disclosure",
        cvssScore: 9.4, epssScore: 0.85,
        threatIntel: { exploitedInTheWild: true, ransomwareUse: false },
        description: "Citrix NetScaler（ADC/Gateway）信息泄露，会话令牌可被窃取。",
        affectedProducts: ["Citrix NetScaler ADC 14.1"] },
    ];
  }

  normalize(rawList) {
    const nodes = [];
    for (const v of rawList) {
      const id = v.cveId || v.id;
      if (!id) continue;
      // 威胁情报作为图谱节点的额外信息
      const ti = v.threatIntel || {};
      const epss = v.epssScore || 0;
      nodes.push({
        id,
        title: v.title || v.description?.slice(0, 200) || id,
        categories: this._inferCategory(v.title || "", v.description || ""),
        signature: { source: [], sink: v.affectedProducts || [] },
        // 威胁情报（供 LLM 做优先级判断）
        threatIntel: {
          epss: epss,
          exploitedInTheWild: ti.exploitedInTheWild || false,
          ransomwareUse: ti.ransomwareUse || false,
        },
      });
    }
    return { nodes, edges: [] };
  }

  _inferCategory(title, desc) {
    const t = (title + " " + desc).toLowerCase();
    const cats = [];
    if (t.includes("sql")) cats.push("sqli");
    if (t.includes("rce") || t.includes("code execution")) cats.push("cmdi");
    if (t.includes("privilege") || t.includes("权限")) cats.push("authz");
    if (t.includes("overflow") || t.includes("溢出")) cats.push("overflow");
    if (t.includes("xss")) cats.push("xss");
    if (t.includes("deserialization")) cats.push("deserialization");
    if (t.includes("info") && t.includes("disclos")) cats.push("config");
    return cats.length > 0 ? cats : ["unknown"];
  }
}

module.exports = { VulncheckConnector };
