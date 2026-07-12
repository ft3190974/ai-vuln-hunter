// rules/rule-engine.js — 判定规则引擎（全 async）
//
// 支持两种规则形态（对应 rule.schema.json）：
//   1. structured   确定性规则：source/sink/condition 直接执行，零幻觉
//   2. llm_prompt   自然语言模板：填占位符后交给 LLM，半结构化
//
// 所有方法均为 async，与 DB 版（pg-rule-store.js）接口一致。

const config = require("../config");

class RuleEngine {
  constructor() {
    /** @type {Array<Object>} */
    this.rules = [];
    this.counter = 0;
    this._seed();
    this._builtinSeeded = false;
  }

  _seed() {
    // structured 规则（用于 detector Agent 的 SAST 结果深判）
    this.rules.push(
      {
        ruleId: "INJ-SQLI-001", name: "SQL 字符串拼接注入",
        type: "structured", category: "sqli", severity: "critical", cwe: "CWE-89",
        languages: ["java", "python", "go"], ruleDomain: "code",
        source: ["http.param.*", "request.getParameter"],
        sink: ["execute", "executeQuery", "createStatement"],
        condition: { pathExists: true, hasValidation: { type: "regex", expect: false } },
        falsePositiveFilters: [{ pattern: "PreparedStatement|prepareStatement|@Query", action: "drop" }],
        confidenceBoost: 0.9, enabled: true, version: "1.0.0",
        origin: "builtin",
      },
      {
        ruleId: "AUTHZ-IDOR-001", name: "水平越权（IDOR）",
        type: "structured", category: "authz", severity: "high", cwe: "CWE-639",
        languages: ["java", "python", "go"], ruleDomain: "code",
        source: ["http.param.id", "@PathVariable"],
        sink: ["findById", "getById", "findOne"],
        condition: { pathExists: true, hasValidation: { type: "auth", expect: false } },
        falsePositiveFilters: [{ pattern: "@PreAuthorize|isOwner|checkOwnership", action: "drop" }],
        confidenceBoost: 0.85, enabled: true, version: "1.0.0",
        origin: "builtin",
      }
    );
  }

  /**
   * 把内置的 natural_language 业务规则灌入（lazy，第一次访问时触发）
   * 这些规则对应 business-rules.js 的内容，但转成统一格式供 llm-hunter 使用
   */
  async _seedBuiltinNaturalLanguage() {
    if (this._builtinSeeded) return;
    this._builtinSeeded = true;

    // 用扩充后的种子数据（6 类 × 20 条 = 120 条）
    const seed = require("./rule-seed-data");
    const domainMap = {
      LOGIC_RULES: "logic", CODE_RULES: "code", QUALITY_RULES: "firmware",
      AI_LOGIC_RULES: "ai_logic", AI_MCP_RULES: "ai_mcp", AI_MODEL_RULES: "ai_model",
    };
    for (const [listName, domain] of Object.entries(domainMap)) {
      for (const r of seed[listName]) {
        if (this.rules.some((x) => x.ruleId === r.id)) continue;
        this.rules.push({
          ruleId: r.id,
          name: r.name,
          type: "natural_language",
          category: r.cat,
          ruleDomain: domain,
          severity: ["critical", "high"].includes(r.cat) ? "critical" : "high",
          languages: [],
          enabled: true,
          description: r.desc,
          detectionHints: `检测 ${r.name}：关注 ${r.sinks.join(", ")} 等关键词，检查是否缺少安全校验`,
          sinks: r.sinks,
          exampleVulnerable: "",
          exampleSafe: "",
          version: "1.0.0",
          origin: "builtin",
          createdAt: new Date().toISOString(),
        });
      }
    }
  }

  async add(rule) {
    this.rules.push(rule);
    return rule;
  }

  async update(ruleId, patch) {
    const idx = this.rules.findIndex((r) => r.ruleId === ruleId);
    if (idx === -1) return null;
    this.rules[idx] = { ...this.rules[idx], ...patch };
    return this.rules[idx];
  }

  async remove(ruleId) {
    const idx = this.rules.findIndex((r) => r.ruleId === ruleId);
    if (idx === -1) return false;
    this.rules.splice(idx, 1);
    return true;
  }

  async get(ruleId) {
    return this.rules.find((r) => r.ruleId === ruleId) || null;
  }

  async select(category, language) {
    return this.rules.filter((r) => {
      if (!r.enabled) return false;
      if (category && r.category !== category) return false;
      if (language && r.languages && r.languages.length > 0 && !r.languages.includes(language)) return false;
      if (typeof r.rolloutPercent === "number" && r.rolloutPercent < 100) {
        return Math.random() * 100 < r.rolloutPercent;
      }
      return true;
    });
  }

  async matchStructured(candidate) {
    const rules = (await this.select(candidate.category, candidate.language)).filter(
      (r) => r.type === "structured"
    );
    const results = [];
    const code = candidate.code || "";

    for (const rule of rules) {
      if (rule.falsePositiveFilters) {
        const fpHit = rule.falsePositiveFilters.some((f) => {
          try { return new RegExp(f.pattern).test(code); }
          catch { return code.includes(f.pattern); }
        });
        if (fpHit) {
          results.push({ rule, matched: false, confidence: 0, reason: "命中误报过滤器" });
          continue;
        }
      }
      const sinkHit = (rule.sink || []).some((s) => code.includes(s));
      const sourceHit = !rule.source || rule.source.length === 0
        ? true
        : (rule.source.some((s) => {
            if (s.includes("*")) {
              const stem = s.replace(/\.\*$/, "").split(".").pop();
              return code.toLowerCase().includes(stem.toLowerCase());
            }
            return code.includes(s);
          })) || (candidate.dataFlow?.sources?.length > 0);

      if (sinkHit && sourceHit) {
        results.push({ rule, matched: true, confidence: rule.confidenceBoost || 0.7, reason: "source→sink 路径匹配" });
      }
    }
    return results;
  }

  renderPrompt(rule, vars) {
    // 渲染是纯函数，无需 async（保留同步便于复用）
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
    await this._seedBuiltinNaturalLanguage();
    return [...this.rules];
  }
}

module.exports = { RuleEngine };
