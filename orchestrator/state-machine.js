// state-machine.js — 编排状态机定义
//
// 状态流转严格对应方案第五章：
//   INIT → FILTER → DISPATCH → DETECT → RAG_MATCH → VERIFY → POC_GEN → FIX → LEARN → REPORT
//
// 每个状态绑定一个 handler（在 engine.js 注册），handler 是 async (ctx) => ctx。
// 设计为声明式：状态机只定义"顺序"，不定义"做什么"——做什么由 engine 注入的 handler 决定。
// 这样状态流转与业务逻辑解耦，便于调整顺序或插入新状态。

const STATES = [
  { name: "INIT", desc: "预处理 + 工具结果归一化（若有工具输出）" },
  { name: "PROJECT_UNDERSTAND", desc: "★ 项目理解（LLM 先通读项目建立全局认知）" },
  { name: "LLM_HUNT", desc: "★ LLM 自主挖掘（带项目上下文）" },
  { name: "FILTER", desc: "误报库前置过滤（防幻觉放大）" },
  { name: "DISPATCH", desc: "调度器分类分发（直通/深判/专项）" },
  { name: "DETECT", desc: "检测 Agent：structured 规则 + LLM 深判" },
  { name: "RAG_MATCH", desc: "知识图谱相似度 + 误报二次过滤" },
  { name: "ZERO_DAY", desc: "0-day 变种挖掘（图谱遍历 + LLM 改写）" },
  { name: "VERIFY", desc: "验证 Agent：可达性判定 + POC 生成" },
  { name: "ATTACK_SCENARIO", desc: "★ 复杂攻击场景构建（多漏洞组合 DAG）" },
  { name: "FIX", desc: "修复 Agent：patch + 等价性回归 + 修复验证" },
  { name: "LEARN", desc: "学习 Agent：误报回灌 + 规则生成 + 图谱演化" },
  { name: "REPORT", desc: "汇总报告" },
];

// 终态（不在 STATES 顺序里，可从任意状态跳转）
const TERMINAL_STATES = ["REPORT", "FAILED"];

/** 取下一个状态 */
function nextOf(stateName) {
  const idx = STATES.findIndex((s) => s.name === stateName);
  if (idx === -1 || idx >= STATES.length - 1) return null;
  return STATES[idx + 1].name;
}

module.exports = { STATES, TERMINAL_STATES, nextOf };
