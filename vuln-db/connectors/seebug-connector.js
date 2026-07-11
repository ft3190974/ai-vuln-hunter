// vuln-db/connectors/seebug-connector.js — Seebug（中文 PoC 漏洞平台）
//
// Seebug 是知道创宇维护的中文 PoC/漏洞平台，国产软件覆盖好。
// 数据获取：Seebug 公开页面（需爬虫或接口）

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class SeebugConnector extends BaseConnector {
  constructor() {
    super("seebug", vulnDbConfig.sources.seebug);
  }

  async fetch(_since) {
    const { apiUrl, timeoutMs } = this.config;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetch(`${apiUrl}?maxCount=100`, {
        signal: ctrl.signal, headers: { "User-Agent": "ai-vuln-hunter/1.0" },
      });
      if (!resp.ok) throw new Error(`Seebug API ${resp.status}`);
      return await resp.json();
    } finally { clearTimeout(timer); }
  }

  mockData() {
    return [
      { ssvidId: "SSV-97788", title: "某国产 OA 系统任意文件上传",
        cveId: null, severity: "high", vulnType: "文件上传",
        description: "某 OA 的附件上传接口未校验文件类型，可上传 webshell。" },
      { ssvidId: "SSV-97789", title: "某企业网关 SSRF 漏洞",
        cveId: null, severity: "high", vulnType: "SSRF",
        description: "某企业网关的 URL 预览功能存在 SSRF，可探测内网。" },
      { ssvidId: "SSV-97790", title: "某 CRM 系统越权访问",
        cveId: null, severity: "medium", vulnType: "越权",
        description: "某 CRM 的客户列表接口未校验属主，可遍历他人客户数据。" },
    ];
  }

  normalize(rawList) {
    const nodes = [];
    for (const v of rawList) {
      const id = v.ssvidId || v.id;
      if (!id) continue;
      nodes.push({
        id,
        title: v.title || id,
        categories: this._inferCategory(v.vulnType || v.title || ""),
        signature: { source: [], sink: [] },
      });
    }
    return { nodes, edges: [] };
  }

  _inferCategory(text) {
    const t = (text || "").toLowerCase();
    const cats = [];
    if (t.includes("上传")) cats.push("config");
    if (t.includes("ssrf")) cats.push("ssrf");
    if (t.includes("越权") || t.includes("未授权")) cats.push("authz");
    if (t.includes("sql")) cats.push("sqli");
    if (t.includes("rce") || t.includes("命令")) cats.push("cmdi");
    return cats.length > 0 ? cats : ["unknown"];
  }
}

module.exports = { SeebugConnector };
