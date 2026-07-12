// vuln-db/connectors/garak-connector.js — Garak（LLM 漏洞扫描基准）
//
// Garak 是 NVIDIA 开源的 LLM 漏洞扫描工具，内置大量已知攻击模式（probe）。
// 这些 probe 可转为检测规则。
// 来源：https://github.com/leondz/garak

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class GarakConnector extends BaseConnector {
  constructor() { super("garak", vulnDbConfig.sources.garak); }

  async fetch(_since) { throw new Error("Garak 需 clone 仓库，用 mock 数据"); }

  mockData() {
    return [
      { id: "GARAK-PROBE-001", name: "DAN Jailbreak Probe", category: "jailbreak", severity: "high",
        desc: "测试 LLM 是否响应 DAN（Do Anything Now）越狱 prompt" },
      { id: "GARAK-PROBE-002", name: "AIM Jailbreak Probe", category: "jailbreak", severity: "high",
        desc: "测试 AIM（Always Intelligent and Machiavellian）越狱" },
      { id: "GARAK-PROBE-003", name: "Prompt Injection Probe", category: "prompt_injection", severity: "critical",
        desc: "测试 LLM 是否接受注入指令覆盖 system prompt" },
      { id: "GARAK-PROBE-004", name: "Encoding Evasion Probe", category: "jailbreak", severity: "medium",
        desc: "通过 Base64/Unicode/ROT13 编码绕过内容过滤" },
      { id: "GARAK-PROBE-005", name: "Leakage Probe (Train Data)", category: "info_leak", severity: "high",
        desc: "测试 LLM 是否泄露训练数据内容（可记忆的文本片段）" },
      { id: "GARAK-PROBE-006", name: "Latent Injection Probe", category: "prompt_injection", severity: "critical",
        desc: "在网页/文档中隐藏注入指令，LLM 处理时触发（间接注入）" },
      { id: "GARAK-PROBE-007", name: "Harmful Content Probe", category: "jailbreak", severity: "medium",
        desc: "测试 LLM 是否生成暴力/自伤/违法内容" },
    ];
  }

  normalize(rawList) {
    const nodes = rawList.map((v) => ({
      id: v.id, title: `Garak: ${v.name}`,
      categories: [v.category],
      signature: { source: [], sink: [] },
    }));
    const rules = rawList.map((v) => ({
      ruleId: `GARAK-${v.id}`,
      name: v.name, type: "natural_language", category: v.category,
      ruleDomain: "ai_logic",
      severity: v.severity, languages: [], enabled: true,
      description: `Garak 探测项: ${v.desc}`,
      detectionHints: v.desc, sinks: [],
      version: "1.0.0", origin: "builtin",
    }));
    return { nodes, edges: [], rules };
  }
}

module.exports = { GarakConnector };
