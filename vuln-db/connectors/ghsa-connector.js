// vuln-db/connectors/ghsa-connector.js — GitHub Security Advisory（GitHub 安全公告）
//
// GitHub 维护的安全公告库（GHSA），含修复 commit 链接。
// 数据获取：GraphQL API（需 token）或 REST API /advisories

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class GhsaConnector extends BaseConnector {
  constructor() {
    super("ghsa", vulnDbConfig.sources.ghsa);
  }

  async fetch(since) {
    const { apiUrl, token, timeoutMs } = this.config;
    const headers = { "Accept": "application/vnd.github+json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const params = new URLSearchParams({ per_page: "100" });
    if (since) params.set("published", `>=${since.slice(0, 10)}`);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetch(`${apiUrl}?${params}`, { signal: ctrl.signal, headers });
      if (!resp.ok) throw new Error(`GHSA API ${resp.status}`);
      return await resp.json();
    } finally { clearTimeout(timer); }
  }

  mockData() {
    return [
      { ghsaId: "GHSA-jfh8-c2jp-5v3q", summary: "Pillow buffer overflow in ICCProfile",
        severity: "high", cveId: "CVE-2023-50447",
        package: { ecosystem: "PyPI", name: "Pillow" },
        references: [{ url: "https://github.com/python-pillow/Pillow/commit/..." }] },
      { ghsaId: "GHSA-72xf-g2v4-qvf2", summary: "Next.js SSRF in middleware",
        severity: "high", cveId: "CVE-2025-29927",
        package: { ecosystem: "npm", name: "next" },
        references: [] },
      { ghsaId: "GHSA-c2hr-8mnc-9gpq", summary: "Okta Auth Java SDK token leak",
        severity: "critical", cveId: null,
        package: { ecosystem: "Maven", name: "com.okta.auth:okta-auth-sdk" },
        references: [] },
    ];
  }

  normalize(rawList) {
    const nodes = [];
    for (const v of rawList) {
      const id = v.ghsaId || v.id;
      if (!id) continue;
      const sink = v.package ? [v.package.name] : [];
      nodes.push({
        id,
        title: v.summary || id,
        categories: this._inferCategory(v.summary || ""),
        signature: { source: [], sink },
      });
    }
    return { nodes, edges: [] };
  }

  _inferCategory(text) {
    const t = (text || "").toLowerCase();
    const cats = [];
    if (t.includes("buffer") || t.includes("overflow")) cats.push("overflow");
    if (t.includes("ssrf")) cats.push("ssrf");
    if (t.includes("sql")) cats.push("sqli");
    if (t.includes("rce") || t.includes("command injection")) cats.push("cmdi");
    if (t.includes("deserialization") || t.includes("deserialize")) cats.push("deserialization");
    if (t.includes("xss")) cats.push("xss");
    return cats.length > 0 ? cats : ["unknown"];
  }
}

module.exports = { GhsaConnector };
