// vuln-db/connectors/cnvd-connector.js — CNVD（中国国家级漏洞数据库）连接器
//
// CNVD 是中国信息安全漏洞共享平台，覆盖国产软件漏洞。
// 数据获取：CNVD 公开页面（无官方 REST API，用 HTML 解析 + mock 数据）
// 真实接入需爬虫或申请 CNVD 数据接口。

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class CnvdConnector extends BaseConnector {
  constructor() {
    super("cnvd", vulnDbConfig.sources.cnvd);
  }

  async fetch(_since) {
    const { apiUrl, timeoutMs } = this.config;
    // CNVD 无公开 REST API，尝试已知的数据接口
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetch(`${apiUrl}?maxCount=100`, {
        signal: ctrl.signal,
        headers: { "User-Agent": "ai-vuln-hunter/1.0" },
      });
      if (!resp.ok) throw new Error(`CNVD API ${resp.status}`);
      const data = await resp.json();
      return data.items || data.vulnerabilities || data.data || [];
    } finally {
      clearTimeout(timer);
    }
  }

  mockData() {
    return [
      { cnvdId: "CNVD-2024-12345", title: "某国产 CMS SQL 注入漏洞", severity: "high",
        description: "国产 XX CMS 的文章搜索接口存在 SQL 注入，攻击者可获取数据库内容。",
        affectedProduct: "XX-CMS <= 3.2", vulnType: "SQL注入",
        cveId: null, references: ["https://www.cnvd.org.cn/flaw/show/CNVD-2024-12345"] },
      { cnvdId: "CNVD-2024-67890", title: "某路由器固件后门账户", severity: "critical",
        description: "某品牌路由器固件内置 hardcoded admin 账户，攻击者可远程登录。",
        affectedProduct: "XX-Router firmware 2.1", vulnType: "后门",
        cveId: null, references: [] },
      { cnvdId: "CNVD-2024-11111", title: "某 OA 系统反序列化漏洞", severity: "critical",
        description: "某国产 OA 系统的文件上传接口存在 Java 反序列化漏洞，可 RCE。",
        affectedProduct: "XX-OA 6.0", vulnType: "反序列化",
        cveId: "CVE-2024-9999", references: [] },
    ];
  }

  normalize(rawList) {
    const nodes = [];
    for (const v of rawList) {
      const id = v.cnvdId || v.id;
      if (!id) continue;
      nodes.push({
        id,
        title: v.title || v.description?.slice(0, 200) || id,
        categories: this._inferCategory(v.vulnType || v.title || ""),
        signature: {
          source: [],
          sink: [v.affectedProduct || v.title || ""].filter(Boolean),
        },
      });
    }
    return { nodes, edges: [] };
  }

  _inferCategory(text) {
    const t = (text || "").toLowerCase();
    const cats = [];
    if (t.includes("sql") || t.includes("注入")) cats.push("sqli");
    if (t.includes("反序列")) cats.push("deserialization");
    if (t.includes("后门") || t.includes("backdoor")) cats.push("config");
    if (t.includes("xss") || t.includes("跨站")) cats.push("xss");
    if (t.includes("命令") || t.includes("rce")) cats.push("cmdi");
    if (t.includes("越权") || t.includes("未授权")) cats.push("authz");
    return cats.length > 0 ? cats : ["unknown"];
  }
}

module.exports = { CnvdConnector };
