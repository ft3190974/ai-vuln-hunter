// vuln-db/connectors/ai-tvds-connector.js — AI-TVDs（中文 AI 安全漏洞库）
//
// AI-TVDs 记录中文 AI 应用的安全漏洞（国产大模型/国产 AI 框架/国产 Agent 平台）。
// 覆盖：文心一言/通义千问/智谱清言/讯飞星火/百川等国产 LLM 应用的安全事件。

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class AiTvdsConnector extends BaseConnector {
  constructor() { super("ai_tvds", vulnDbConfig.sources.ai_tvds); }

  async fetch(_since) { throw new Error("AI-TVDs 无公开 API，用 mock 数据"); }

  mockData() {
    return [
      { id: "AI-TVDs-2024-001", title: "某国产大模型 System Prompt 泄露", severity: "high",
        category: "info_leak", desc: "通过特定 prompt 可诱导模型输出完整系统提示词",
        affected: "某国产 LLM API", year: "2024" },
      { id: "AI-TVDs-2024-002", title: "某国产 AI 编程助手生成恶意代码", severity: "medium",
        category: "output_injection", desc: "AI 编程助手在特定场景下生成含后门的代码建议",
        affected: "某国产 Copilot 类产品", year: "2024" },
      { id: "AI-TVDs-2024-003", title: "某国产 Agent 平台未授权执行", severity: "critical",
        category: "unsafe_tool_use", desc: "Agent 平台的工具调用未做权限校验，可执行任意命令",
        affected: "某国产 Agent 框架", year: "2024" },
      { id: "AI-TVDs-2024-004", title: "某国产推理框架反序列化 RCE", severity: "critical",
        category: "deserialization", desc: "推理框架加载模型文件时使用不安全的 pickle 反序列化",
        affected: "某国产 ML 推理框架", year: "2024" },
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

module.exports = { AiTvdsConnector };
