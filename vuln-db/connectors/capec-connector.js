// vuln-db/connectors/capec-connector.js — CAPEC（MITRE 攻击模式库）连接器
//
// 数据源：https://capec.mitre.org/data/xml/capec_latest.xml
// CAPEC 不是 CVE，而是"攻击者怎么打"的方法论。
// 转为图谱的 attackPattern 节点，驱动 finding 的 attackPattern 字段。

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class CapecConnector extends BaseConnector {
  constructor() {
    super("capec", vulnDbConfig.sources.capec);
  }

  /**
   * 真实拉取 CAPEC XML（体积大，下载后解析）
   * 注意：XML 解析用 DOMParser（Node 无内置，需 fast-xml-parser）。
   * 这里返回原始 XML 字符串，解析在 normalize 里做。
   */
  async fetch(_since) {
    const { xmlUrl, timeoutMs } = this.config;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetch(xmlUrl, { signal: ctrl.signal });
      if (!resp.ok) throw new Error(`CAPEC fetch ${resp.status}`);
      return await resp.text();
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Mock 数据：3 条典型攻击模式（含与 CWE 的映射）
   */
  mockData() {
    return [
      {
        id: "CAPEC-66",
        name: "SQL Injection",
        description: "The attacker injects SQL commands into input vectors to manipulate the database.",
        relatedWeaknesses: ["CWE-89"],
        execution: ["Find input vectors", "Inject SQL syntax", "Observe DB response"],
        typicalSeverity: "High",
      },
      {
        id: "CAPEC-88",
        name: "OS Command Injection",
        description: "The attacker injects OS commands into input to execute arbitrary code.",
        relatedWeaknesses: ["CWE-78"],
        execution: ["Identify command sinks", "Craft command separators", "Execute payloads"],
        typicalSeverity: "High",
      },
      {
        id: "CAPEC-108",
        name: "Command Line Execution through SQL Injection",
        description: "Chain SQL injection with xp_cmdshell or COPY to execute OS commands.",
        relatedWeaknesses: ["CWE-89", "CWE-78"],
        execution: ["SQLi to write file", "Invoke file via SQL", "Get RCE"],
        typicalSeverity: "Critical",
      },
    ];
  }

  normalize(rawList) {
    // rawList 是 attack pattern 数组（mock 形式；真实 XML 需先解析）
    const nodes = [];
    const edges = [];

    for (const ap of rawList) {
      const id = ap.id;
      if (!id) continue;
      const relatedCwe = ap.relatedWeaknesses || [];
      nodes.push({
        id,
        title: ap.name || id,
        categories: this._cweToCategories(relatedCwe),
        signature: { source: [], sink: [] },
        attackPattern: {
          description: ap.description,
          execution: ap.execution,
          severity: ap.typicalSeverity,
          relatedCwe,
        },
      });
      // CAPEC 与 CWE 的关联边（CAPEC-108 → CWE-89，CWE-78）
      for (const cwe of relatedCwe) {
        // CWE 节点可能在 NVD 入库时已存在；这里先建虚边，图谱自然连接
        edges.push({ from: id, to: cwe, type: "SAME_ROOT" });
      }
    }
    return { nodes, edges };
  }

  _cweToCategories(cweList) {
    const map = { "CWE-89": "sqli", "CWE-78": "cmdi", "CWE-79": "xss" };
    return [...new Set(cweList.map((c) => map[c] || "unknown").filter((x) => x !== "unknown"))];
  }
}

module.exports = { CapecConnector };
