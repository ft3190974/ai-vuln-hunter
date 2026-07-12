// vuln-db/connectors/owasp-llm-connector.js — OWASP LLM Top 10
//
// OWASP LLM 应用安全 Top 10 风险（2024/2025 版），相当于 AI 安全的 CWE。
// 来源：https://owasp.org/www-project-top-10-for-large-language-model-applications/

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class OwaspLlmConnector extends BaseConnector {
  constructor() { super("owasp_llm", vulnDbConfig.sources.owasp_llm); }

  async fetch(_since) {
    // OWASP 无结构化 API，用预置数据
    throw new Error("OWASP LLM Top 10 无 REST API，使用 mock 数据");
  }

  mockData() {
    return [
      { id: "OWASP-LLM01", name: "Prompt Injection", category: "prompt_injection", severity: "critical",
        desc: "攻击者通过精心构造的输入操纵 LLM 行为，覆盖 system prompt 或指令", owaspId: "LLM01" },
      { id: "OWASP-LLM02", name: "Insecure Output Handling", category: "output_injection", severity: "critical",
        desc: "LLM 输出未经净化直接执行/渲染，导致 XSS/RCE/SQLi", owaspId: "LLM02" },
      { id: "OWASP-LLM03", name: "Training Data Poisoning", category: "data_poisoning", severity: "high",
        desc: "训练数据被篡改，导致模型行为异常或后门", owaspId: "LLM03" },
      { id: "OWASP-LLM04", name: "Model DoS", category: "dos", severity: "medium",
        desc: "通过高频请求或复杂 prompt 耗尽 LLM 资源", owaspId: "LLM04" },
      { id: "OWASP-LLM05", name: "Supply Chain Vulnerabilities", category: "supply_chain", severity: "high",
        desc: "第三方模型/数据集/组件被投毒或含漏洞", owaspId: "LLM05" },
      { id: "OWASP-LLM06", name: "Sensitive Info Disclosure", category: "info_leak", severity: "high",
        desc: "LLM 泄露系统 prompt/训练数据/API key/用户隐私", owaspId: "LLM06" },
      { id: "OWASP-LLM07", name: "Insecure Plugin Design", category: "unsafe_tool_use", severity: "critical",
        desc: "LLM 插件/工具缺少输入校验，导致 RCE/路径穿越", owaspId: "LLM07" },
      { id: "OWASP-LLM08", name: "Excessive Agency", category: "authz", severity: "high",
        desc: "LLM 被授予过多权限，可执行超出预期的操作", owaspId: "LLM08" },
      { id: "OWASP-LLM09", name: "Overreliance", category: "business_logic", severity: "medium",
        desc: "系统过度信任 LLM 输出，未做事实核查/人工 review", owaspId: "LLM09" },
      { id: "OWASP-LLM10", name: "Model Theft", category: "info_leak", severity: "high",
        desc: "模型权重/架构/训练数据被未授权提取", owaspId: "LLM10" },
    ];
  }

  normalize(rawList) {
    return {
      nodes: rawList.map((v) => ({
        id: v.id, title: `OWASP ${v.owaspId}: ${v.name}`,
        categories: [v.category],
        signature: { source: [], sink: [] },
        attackPattern: { description: v.desc, owaspId: v.owaspId, severity: v.severity },
      })),
      edges: [],
    };
  }
}

module.exports = { OwaspLlmConnector };
