// repository/pg-rule-store.js — Postgres 版 RuleEngine
//
// 与内存版 RuleEngine 接口一致（add/select/matchStructured/renderPrompt/list）。
// 注意：renderPrompt 是纯函数（无 IO），直接复用内存版的实现逻辑。

const config = require("../config");

class PgRuleEngine {
  constructor(pool) {
    this.pool = pool;
    this._seeded = false;
  }

  async _seed() {
    if (this._seeded) return;
    this._seeded = true;
    const seeds = [
      { ruleId: "INJ-SQLI-001", name: "SQL 字符串拼接注入", type: "structured", category: "sqli", severity: "critical", cwe: "CWE-89", languages: ["java", "python", "go"], source: ["http.param.*", "request.getParameter"], sink: ["execute", "executeQuery", "createStatement"], condition: { pathExists: true, hasValidation: { type: "regex", expect: false } }, falsePositiveFilters: [{ pattern: "PreparedStatement|prepareStatement|@Query", action: "drop" }], confidenceBoost: 0.9, enabled: true, version: "1.0.0" },
      { ruleId: "BL-STATE-001", name: "状态机绕过检测", type: "llm_prompt", category: "business_logic", severity: "high", languages: ["java", "python", "go"], llmPrompt: "分析以下代码，判断是否存在状态机绕过缺陷：\n1. 状态迁移未校验当前状态\n2. 缺少幂等性\n3. 跨用户污染\n代码：{code}\n上下文：{context}", evidenceRequired: ["必须给出两步攻击序列", "必须指出漏洞点行号"], confidenceBoost: 0.8, enabled: true, version: "1.0.0" },
      { ruleId: "AUTHZ-IDOR-001", name: "水平越权（IDOR）", type: "structured", category: "authz", severity: "high", cwe: "CWE-639", languages: ["java", "python", "go"], source: ["http.param.id", "@PathVariable"], sink: ["findById", "getById", "findOne"], condition: { pathExists: true, hasValidation: { type: "auth", expect: false } }, falsePositiveFilters: [{ pattern: "@PreAuthorize|isOwner|checkOwnership", action: "drop" }], confidenceBoost: 0.85, enabled: true, version: "1.0.0" },
    ];
    for (const s of seeds) {
      await this.pool.query(
        `INSERT INTO rules (rule_id, data, enabled, version) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
        [s.ruleId, JSON.stringify(s), s.enabled !== false, s.version]
      );
    }
  }

  async add(rule) {
    await this.pool.query(
      `INSERT INTO rules (rule_id, data, enabled, version) VALUES ($1,$2,$3,$4)
       ON CONFLICT (rule_id) DO UPDATE SET data=$2, enabled=$3, version=$4`,
      [rule.ruleId, JSON.stringify(rule), rule.enabled !== false, rule.version || "1.0.0"]
    );
    return rule;
  }

  async select(category, language) {
    await this._seed();
    let sql = "SELECT data FROM rules WHERE enabled=true";
    const params = [];
    if (category) { params.push(category); sql += ` AND data->>'category'=$${params.length}`; }
    const r = await this.pool.query(sql, params);
    return r.rows.map((row) => row.data).filter((rule) => {
      if (language && rule.languages && rule.languages.length > 0 && !rule.languages.includes(language)) return false;
      if (typeof rule.rolloutPercent === "number" && rule.rolloutPercent < 100) {
        return Math.random() * 100 < rule.rolloutPercent;
      }
      return true;
    });
  }

  async matchStructured(candidate) {
    const rules = (await this.select(candidate.category, candidate.language)).filter((r) => r.type === "structured");
    const results = [];
    const code = candidate.code || "";
    for (const rule of rules) {
      if (rule.falsePositiveFilters) {
        const fpHit = rule.falsePositiveFilters.some((f) => {
          try { return new RegExp(f.pattern).test(code); } catch { return code.includes(f.pattern); }
        });
        if (fpHit) { results.push({ rule, matched: false, confidence: 0, reason: "命中误报过滤器" }); continue; }
      }
      const sinkHit = (rule.sink || []).some((s) => code.includes(s));
      const sourceHit = !rule.source || rule.source.length === 0 ? true : (rule.source.some((s) => {
        if (s.includes("*")) { const stem = s.replace(/\.\*$/, "").split(".").pop(); return code.toLowerCase().includes(stem.toLowerCase()); }
        return code.includes(s);
      })) || (candidate.dataFlow?.sources?.length > 0);
      if (sinkHit && sourceHit) {
        results.push({ rule, matched: true, confidence: rule.confidenceBoost || 0.7, reason: "source→sink 路径匹配" });
      }
    }
    return results;
  }

  renderPrompt(rule, vars) {
    let prompt = rule.llmPrompt || "";
    for (const [k, v] of Object.entries(vars || {})) {
      prompt = prompt.replace(new RegExp(`\\{${k}\\}`, "g"), String(v));
    }
    if (rule.evidenceRequired && rule.evidenceRequired.length > 0) {
      prompt += "\n\n必须提供以下证据：\n" + rule.evidenceRequired.map((e) => `- ${e}`).join("\n");
    }
    prompt += '\n\n请以 JSON 格式返回：{"verdict":"confirmed|false_positive|suspect","confidence":0-1,"reasoning":"...","evidence":[...]}';
    return prompt;
  }

  async list() {
    await this._seed();
    const r = await this.pool.query("SELECT data FROM rules");
    return r.rows.map((row) => row.data);
  }
}

module.exports = { PgRuleEngine };
