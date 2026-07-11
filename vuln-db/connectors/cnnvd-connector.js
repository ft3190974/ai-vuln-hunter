// vuln-db/connectors/cnnvd-connector.js — CNNVD（中国国家信息安全漏洞库）
//
// CNNVD 是中国官方的国家级漏洞库（国家信息安全漏洞库）。
// 数据获取：CNNVD 公开页面（无官方 REST API，需爬虫/解析 XML）

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class CnnvdConnector extends BaseConnector {
  constructor() {
    super("cnnvd", vulnDbConfig.sources.cnnvd);
  }

  async fetch(_since) {
    const { apiUrl, timeoutMs } = this.config;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      // CNNVD 的漏洞列表页面（HTML，需解析）
      const resp = await fetch(`${apiUrl}?maxCount=100`, {
        signal: ctrl.signal, headers: { "User-Agent": "ai-vuln-hunter/1.0" },
      });
      if (!resp.ok) throw new Error(`CNNVD API ${resp.status}`);
      return await resp.json();
    } finally { clearTimeout(timer); }
  }

  mockData() {
    return [
      { cnnvdId: "CNNVD-202405-001", title: "Apache Log4j 任意代码执行漏洞", severity: "critical",
        cveId: "CVE-2021-44228", vulnType: "反序列化",
        description: "Apache Log4j2 JNDI 注入漏洞（Log4Shell），可远程代码执行。",
        affectedProduct: "Apache Log4j 2.0-beta9 到 2.14.1" },
      { cnnvdId: "CNNVD-202405-002", title: "Spring Framework 远程代码执行", severity: "critical",
        cveId: "CVE-2022-22965", vulnType: "RCE",
        description: "Spring Framework 存在 RCE 漏洞（Spring4Shell）。",
        affectedProduct: "Spring Framework 5.3.x < 5.3.18" },
      { cnnvdId: "CNNVD-202405-003", title: "OpenSSL 缓冲区溢出", severity: "high",
        cveId: "CVE-2022-3602", vulnType: "缓冲区溢出",
        description: "OpenSSL X.509 证书验证缓冲区溢出。",
        affectedProduct: "OpenSSL 3.0.0-3.0.6" },
    ];
  }

  normalize(rawList) {
    const nodes = [];
    for (const v of rawList) {
      const id = v.cnnvdId || v.id;
      if (!id) continue;
      const linkedCve = v.cveId || null;
      nodes.push({
        id,
        title: v.title || id,
        categories: this._inferCategory(v.vulnType || v.title || ""),
        signature: { source: [], sink: [v.affectedProduct || ""].filter(Boolean) },
      });
    }
    return { nodes, edges: [] };
  }

  _inferCategory(text) {
    const t = (text || "").toLowerCase();
    const cats = [];
    if (t.includes("反序列")) cats.push("deserialization");
    if (t.includes("rce") || t.includes("代码执行") || t.includes("命令")) cats.push("cmdi");
    if (t.includes("溢出") || t.includes("overflow")) cats.push("overflow");
    if (t.includes("注入")) cats.push("sqli");
    if (t.includes("xss")) cats.push("xss");
    return cats.length > 0 ? cats : ["unknown"];
  }
}

module.exports = { CnnvdConnector };
