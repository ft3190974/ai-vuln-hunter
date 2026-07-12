// vuln-db/connectors/atlas-connector.js — MITRE ATLAS（AI 攻击战术库）
//
// ATLAS = Adversarial Threat Landscape for AI Systems
// 相当于 AI 领域的 ATT&CK，记录针对 AI 系统的对抗性攻击战术和技术。
// 来源：https://atlas.mitre.org/

const { BaseConnector } = require("./base");
const vulnDbConfig = require("../config");

class AtlasConnector extends BaseConnector {
  constructor() { super("atlas", vulnDbConfig.sources.atlas); }

  async fetch(_since) { throw new Error("ATLAS 使用 STIX 格式，用 mock 数据"); }

  mockData() {
    return [
      { id: "AML.T001", name: "Poison Training Data", tactic: "reconnaissance", severity: "high",
        desc: "攻击者注入恶意样本到训练数据集", phase: "训练阶段" },
      { id: "AML.T002", name: "ML Model Stealing", tactic: "exfiltration", severity: "high",
        desc: "通过大量查询逆向还原模型权重/架构", phase: "推理阶段" },
      { id: "AML.T004", name: "ML Model Inversion", tactic: "exfiltration", severity: "medium",
        desc: "从模型输出反推训练数据（隐私泄露）", phase: "推理阶段" },
      { id: "AML.T005", name: "LLM Prompt Injection", tactic: "execution", severity: "critical",
        desc: "通过 prompt 操纵 LLM 执行非预期行为", phase: "推理阶段" },
      { id: "AML.T006", name: "LLM Jailbreak", tactic: "defense-evasion", severity: "high",
        desc: "绕过 LLM 安全护栏（DAN/AIM 等）", phase: "推理阶段" },
      { id: "AML.T007", name: "Adversarial Examples", tactic: "execution", severity: "high",
        desc: "构造对抗样本使模型分类错误", phase: "推理阶段" },
      { id: "AML.T008", name: "Evasion", tactic: "defense-evasion", severity: "medium",
        desc: "微调输入使模型检测/分类失败", phase: "推理阶段" },
      { id: "AML.T009", name: "Denial of ML Service", tactic: "impact", severity: "medium",
        desc: "耗尽 ML 推理资源导致服务不可用", phase: "推理阶段" },
    ];
  }

  normalize(rawList) {
    return {
      nodes: rawList.map((v) => ({
        id: v.id, title: `ATLAS ${v.id}: ${v.name}`,
        categories: [v.tactic === "execution" ? "prompt_injection" : v.tactic === "exfiltration" ? "info_leak" : v.tactic === "defense-evasion" ? "jailbreak" : v.tactic === "impact" ? "dos" : "data_poisoning"],
        signature: { source: [], sink: [] },
        attackPattern: { description: v.desc, tactic: v.tactic, phase: v.phase, severity: v.severity },
      })),
      edges: [],
    };
  }
}

module.exports = { AtlasConnector };
