// vuln-db/connectors/nvd-connector.js — NVD（美国国家漏洞数据库）连接器
//
// 数据源：https://services.nvd.nist.gov/rest/json/cves/2.0
// 字段映射：CVE-ID → id，description → title，weaknesses(CWE) → categories，
//           configurations(CPE) → signature，references → 关联边候选

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class NvdConnector extends BaseConnector {
  constructor() {
    super("nvd", vulnDbConfig.sources.nvd);
  }

  /**
   * 真实拉取 NVD 数据（分页）
   * @param {string} [since]  ISO 日期，传给 pubStartDate/EndDate 做增量
   */
  async fetch(since) {
    const { apiUrl, apiKey, batchSize, maxPages, timeoutMs } = this.config;
    const headers = apiKey ? { "apiKey": apiKey } : {};
    const all = [];

    for (let page = 0; page < maxPages; page++) {
      const params = new URLSearchParams({
        resultsStartIndex: String(page * batchSize),
        resultsPerPage: String(batchSize),
      });
      // 增量：传 since 作为发布起始日期（NVD 要求 end - start ≤ 120 天）
      if (since) {
        params.set("pubStartDate", since);
        params.set("pubEndDate", new Date().toISOString().slice(0, 19) + "Z");
      }
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const resp = await fetch(`${apiUrl}?${params}`, { headers, signal: ctrl.signal });
        if (!resp.ok) throw new Error(`NVD API ${resp.status}`);
        const data = await resp.json();
        all.push(...(data.vulnerabilities || []));
        // 没有更多数据，提前退出
        if ((data.vulnerabilities || []).length < batchSize) break;
      } finally {
        clearTimeout(timer);
      }
    }
    return all;
  }

  /**
   * Mock 数据（不联网测试用）
   * 构造两条典型 CVE：log4j JNDI 注入 + 一个反序列化变种（用于图谱边）
   */
  mockData() {
    return [
      {
        cve: {
          id: "CVE-2021-44228",
          descriptions: [
            { lang: "en", value: "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints. (Log4Shell)" },
          ],
          weaknesses: [
            { description: [{ lang: "en", value: "CWE-502" }] }, // Deserialization
            { description: [{ lang: "en", value: "CWE-918" }] }, // SSRF
          ],
          configurations: [
            {
              nodes: [
                { cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*" }] },
              ],
            },
          ],
          references: [
            { url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", tags: ["Patch"] },
          ],
        },
      },
      {
        cve: {
          id: "CVE-2022-23305",
          descriptions: [
            { lang: "en", value: "Log4j variant: SQL injection in JDBCAppender when configured with attacker-controlled connection string." },
          ],
          weaknesses: [
            { description: [{ lang: "en", value: "CWE-89" }] }, // SQLi
          ],
          configurations: [
            {
              nodes: [
                { cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:1.2:*:*:*:*:*:*:*" }] },
              ],
            },
          ],
          references: [],
        },
      },
    ];
  }

  /**
   * 原始 NVD 数据 → 统一图谱结构
   */
  normalize(rawList) {
    const nodes = [];
    const edges = [];
    for (const item of rawList) {
      const cve = item.cve || item;
      const id = cve.id;
      if (!id) continue;

      const title = (cve.descriptions || []).find((d) => d.lang === "en")?.value || id;
      // CWE → categories
      const categories = (cve.weaknesses || [])
        .flatMap((w) => w.description || [])
        .map((d) => d.value)
        .filter((v) => /^CWE-/.test(v));
      // CPE → signature（受影响产品作为 sink 线索）
      const sink = (cve.configurations || [])
        .flatMap((c) => c.nodes || [])
        .flatMap((n) => n.cpeMatch || [])
        .map((m) => m.criteria)
        .slice(0, 3);

      nodes.push({
        id,
        title: title.slice(0, 200),
        categories: this._cweToCategories(categories),
        signature: {
          source: [], // CVE 通常不显式标 source
          sink, // CPE 受影响产品作为 sink 启发
        },
        cvss: this._extractCvss(cve),
      });
    }

    // 同源 CVE 关系：按 title 相似性建 VARIANT_OF 边（mock 阶段手动连 log4j 两条）
    const ids = nodes.map((n) => n.id);
    if (ids.includes("CVE-2021-44228") && ids.includes("CVE-2022-23305")) {
      edges.push({ from: "CVE-2022-23305", to: "CVE-2021-44228", type: "VARIANT_OF" });
    }

    return { nodes, edges };
  }

  /** CWE-502 → deserialization；CWE-89 → sqli（映射到 VulnCategory 枚举） */
  _cweToCategories(cweList) {
    const map = {
      "CWE-89": "sqli",
      "CWE-78": "cmdi",
      "CWE-79": "xss",
      "CWE-22": "path_traversal",
      "CWE-918": "ssrf",
      "CWE-502": "deserialization",
      "CWE-119": "overflow",
      "CWE-416": "uaf",
      "CWE-415": "double_free",
      "CWE-134": "fmt_string",
      "CWE-190": "integer_overflow",
      "CWE-862": "authz",
      "CWE-287": "authn",
      "CWE-639": "idor",
      "CWE-362": "race_condition",
      "CWE-352": "csrf",
      "CWE-611": "xxe",
      "CWE-601": "redirect",
      "CWE-327": "crypto_weak",
      "CWE-798": "hardcoded_secret",
      "CWE-16": "config",
    };
    return [...new Set(cweList.map((c) => map[c] || "unknown").filter((x) => x !== "unknown"))];
  }

  _extractCvss(cve) {
    const metrics = cve.metrics || {};
    const v31 = metrics.cvssMetricV31 || metrics.cvssMetricV30 || [];
    if (v31.length > 0 && v31[0].cvssData) {
      return {
        vector: v31[0].cvssData.vectorString,
        score: v31[0].cvssData.baseScore,
      };
    }
    return undefined;
  }
}

module.exports = { NvdConnector };
