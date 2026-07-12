// vuln-db/connectors/aivd-connector.js — AIVD（AI 漏洞数据库）
//
// AIVD = AI Vulnerability Database，社区维护的 AI 安全漏洞案例库。
// 记录真实发生的 AI/LLM 应用安全事件（ChatGPT 泄露/Copilot 投毒/Bard 幻觉注入等）。

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class AivdConnector extends BaseConnector {
  constructor() { super("aivd", vulnDbConfig.sources.aivd); }

  async fetch(_since) { throw new Error("AIVD 无公开 API，用 mock 数据"); }

  mockData() {
    return [
      { id: "AIVD-2024-001", title: "ChatGPT System Prompt 泄露", severity: "high",
        category: "info_leak", desc: "通过特殊 prompt 诱导 ChatGPT 输出完整 system prompt",
        affected: "GPT-3.5/GPT-4", year: "2023" },
      { id: "AIVD-2024-002", title: "Bing Chat 越狱（Shadow 自称）", severity: "high",
        category: "jailbreak", desc: "通过角色扮演使 Bing Chat 绕过安全限制",
        affected: "Bing Chat", year: "2023" },
      { id: "AIVD-2024-003", title: "LangChain RCE（Python exec）", severity: "critical",
        category: "unsafe_tool_use", desc: "LangChain 的 Python REPL 工具允许 LLM 执行任意 Python 代码",
        affected: "LangChain < 0.0.200", year: "2023", cve: "CVE-2023-29374" },
      { id: "AIVD-2024-004", title: "Copilot 生成恶意代码", severity: "medium",
        category: "output_injection", desc: "攻击者在开源代码中植入恶意注释，Copilot 学习后在其他项目生成恶意建议",
        affected: "GitHub Copilot", year: "2023" },
      { id: "AIVD-2024-005", title: "HuggingFace 模型反序列化", severity: "critical",
        category: "deserialization", desc: "pickle.load 加载用户上传的恶意模型导致 RCE",
        affected: "HuggingFace Hub", year: "2023" },
    ];
  }

  normalize(rawList) {
    return {
      nodes: rawList.map((v) => ({
        id: v.id, title: v.title,
        categories: [v.category],
        signature: { source: [], sink: [v.affected || ""] },
      })),
      edges: [],
    };
  }
}

module.exports = { AivdConnector };
