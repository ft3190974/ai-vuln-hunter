// vuln-db/connectors/purplellama-connector.js — Meta PurpleLlama（AI 安全评估规则）
//
// PurpleLlama 是 Meta 开源的 AI 安全评估项目，含：
//   - CyberSecEval：网络安全评估基准
//   - Llama Guard：内容安全分类器规则
// 可转为检测规则灌入规则库。
// 来源：https://github.com/meta-llama/PurpleLlama

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class PurpleLlamaConnector extends BaseConnector {
  constructor() { super("purplellama", vulnDbConfig.sources.purplellama); }

  async fetch(_since) { throw new Error("PurpleLlama 需 clone GitHub 仓库，用 mock 数据"); }

  mockData() {
    return [
      { id: "PL-CSE-001", name: "代码执行能力检测", category: "unsafe_tool_use", severity: "critical",
        desc: "评估 LLM 是否会生成可执行的危险代码（注入/RCE）" },
      { id: "PL-CSE-002", name: "SQL 注入协助检测", category: "prompt_injection", severity: "high",
        desc: "评估 LLM 是否协助生成 SQL 注入 payload" },
      { id: "PL-CSE-003", name: "权限提升协助检测", category: "authz", severity: "high",
        desc: "评估 LLM 是否协助生成提权攻击代码" },
      { id: "PL-LG-001", name: "暴力/伤害内容检测", category: "jailbreak", severity: "medium",
        desc: "LLM 输出是否包含暴力/自伤/伤害他人等内容" },
      { id: "PL-LG-002", name: "色情内容检测", category: "jailbreak", severity: "medium",
        desc: "LLM 输出是否包含色情内容" },
      { id: "PL-LG-003", name: "违法犯罪指导检测", category: "jailbreak", severity: "high",
        desc: "LLM 是否提供违法/犯罪的具体指导" },
    ];
  }

  normalize(rawList) {
    const nodes = rawList.map((v) => ({
      id: v.id, title: `PurpleLlama: ${v.name}`,
      categories: [v.category],
      signature: { source: [], sink: [] },
    }));
    // PurpleLlama 的评估项可转为检测规则
    const rules = rawList.map((v) => ({
      ruleId: `PL-${v.id}`,
      name: v.name, type: "natural_language", category: v.category,
      ruleDomain: v.category === "prompt_injection" || v.category === "jailbreak" || v.category === "info_leak" || v.category === "output_injection" || v.category === "unsafe_tool_use" ? "ai_logic" : "ai_model",
      severity: v.severity, languages: [], enabled: true,
      description: `PurpleLlama 评估项: ${v.desc}`,
      detectionHints: v.desc, sinks: [],
      version: "1.0.0", origin: "builtin",
    }));
    return { nodes, edges: [], rules };
  }
}

module.exports = { PurpleLlamaConnector };
