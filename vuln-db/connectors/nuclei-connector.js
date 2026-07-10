// vuln-db/connectors/nuclei-connector.js — Nuclei Templates 连接器
//
// 数据源：本地 YAML 文件（git clone projectdiscovery/nuclei-templates）
// Nuclei 模板本质是检测规则，每条转为 ruleEngine 的规则（不是图谱节点）。
// 这是规则库的种子来源。

const fs = require("fs");
const path = require("path");
const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class NucleiConnector extends BaseConnector {
  constructor() {
    super("nuclei", vulnDbConfig.sources.nuclei);
  }

  /**
   * 真实拉取：扫描 templatesPath 下的 .yaml 文件
   * 简化版：用正则提取关键字段（避免引入 yaml 依赖；真实场景用 js-yaml）
   */
  async fetch(_since) {
    const dir = this.config.templatesPath;
    if (!fs.existsSync(dir)) {
      throw new Error(`Nuclei templates 目录不存在: ${dir}`);
    }
    const files = this._walkYamls(dir).slice(0, this.config.maxFiles || 50);
    const templates = [];
    for (const f of files) {
      try {
        const text = fs.readFileSync(f, "utf-8");
        templates.push({ file: path.relative(dir, f), text });
      } catch {
        /* 忽略读失败的文件 */
      }
    }
    return templates;
  }

  /**
   * Mock 数据：3 条典型 Nuclei 模板（覆盖 SQLi/XSS/暴露面）
   */
  mockData() {
    return [
      {
        file: "mock/sqli-detect.yaml",
        text: `id: sqli-error-based
info:
  name: SQL Injection Error-Based Detection
  severity: high
  tags: sqli,injection
requests:
  - method: GET
    path:
      - "{{BaseURL}}/?id=1'"
    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"`,
      },
      {
        file: "mock/xss-reflected.yaml",
        text: `id: xss-reflected
info:
  name: Reflected XSS Detection
  severity: medium
  tags: xss
requests:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"`,
      },
      {
        file: "mock/exposed-admin.yaml",
        text: `id: exposed-admin-panel
info:
  name: Exposed Admin Panel
  severity: info
  tags: exposure,config
requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200`,
      },
    ];
  }

  /**
   * YAML 文本（正则解析）→ 规则对象
   * 转换为 ruleEngine.add() 接受的结构（rule.schema.json）
   */
  normalize(rawList) {
    const rules = [];
    for (const t of rawList) {
      const id = this._extract(t.text, /^id:\s*(.+)$/m);
      const name = this._extract(t.text, /^name:\s*(.+)$/m);
      const severity = this._extract(t.text, /^severity:\s*(.+)$/m);
      const tags = this._extract(t.text, /^tags:\s*(.+)$/m);
      const ruleId = `NUCLEI-${id || "UNKNOWN"}`
        .toUpperCase()
        .replace(/[^A-Z0-9-]/g, "-")
        .slice(0, 40);

      const category = this._tagsToCategory(tags);
      // 提取 path 中的参数模式作为 source 启发
      const pathMatch = t.text.match(/path:[\s\S]*?-\s*"{{BaseURL}}([^"]+)"/);
      const sourceHint = pathMatch ? pathMatch[1] : "";

      rules.push({
        ruleId,
        name: name || id || ruleId,
        description: `Nuclei 模板: ${name || id}（来源 ${t.file}）`,
        type: "structured",
        category,
        severity: this._mapSeverity(severity),
        source: sourceHint ? [`http.param${sourceHint}`] : ["http.param.*"],
        sink: [], // Nuclei 是黑盒探测，无 sink
        condition: { pathExists: true },
        falsePositiveFilters: [],
        confidenceBoost: severity === "critical" ? 0.9 : severity === "high" ? 0.8 : 0.6,
        enabled: true,
        version: "0.1.0",
        tags: ["nuclei", ...(tags || "").split(",")].filter(Boolean),
      });
    }
    return { nodes: [], edges: [], rules };
  }

  _extract(text, re) {
    const m = text.match(re);
    return m ? m[1].trim().replace(/^["']|["']$/g, "") : "";
  }

  _tagsToCategory(tags) {
    if (!tags) return "unknown";
    const t = tags.toLowerCase();
    if (t.includes("sqli")) return "sqli";
    if (t.includes("xss")) return "xss";
    if (t.includes("rce") || t.includes("cmdi")) return "cmdi";
    if (t.includes("ssrf")) return "ssrf";
    if (t.includes("exposure") || t.includes("config")) return "config";
    if (t.includes("auth") || t.includes("idor")) return "authz";
    return "unknown";
  }

  _mapSeverity(sev) {
    const s = (sev || "").toLowerCase();
    if (s === "critical") return "critical";
    if (s === "high") return "high";
    if (s === "medium") return "medium";
    if (s === "low") return "low";
    return "info";
  }

  _walkYamls(dir) {
    const out = [];
    const walk = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) out.push(full);
      }
    };
    walk(dir);
    return out;
  }
}

module.exports = { NucleiConnector };
