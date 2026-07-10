// agents/learner.js — 学习 Agent（全 async，store 调用加 await，用新增的 listNodes/setNodeField 接口）
//
// 职责：
//   1. 误报回灌：提取误报特征，更新误报库
//   2. 规则自动生成：从确认的真漏洞反推候选规则
//   3. 图谱演化：新漏洞入库，补"变种/绕过/同源"边

const config = require("../config");
const { getLlm } = require("../llm");

async function learn(ctx, deps) {
  const { fpStore, knowledgeGraph, ruleEngine, findingStore } = deps;
  const llm = getLlm();
  ctx.log_("LEARN", "学习闭环开始", "info");

  // ── 1. 误报回灌 ──
  const falsePositives = ctx.findings.filter((f) => f.status === "false_positive");
  for (const f of falsePositives) {
    const code = f.snippet?.code || "";
    if (code.length === 0) continue;
    const prompt = `从以下被判定为误报的代码中，提取一个能识别此类安全模式的正则表达式（用于后续过滤同类误报）。\n代码:\n${code}\n类别: ${f.category}\n误报原因: ${f.reviewerNote || "?"}\n请返回 JSON: {pattern:string(正则), reason:string}`;
    const result = await llm.complete(prompt, { difficulty: "low", jsonMode: true });
    const v = result.structured || {};
    if (v.pattern) {
      try {
        new RegExp(v.pattern);
        await fpStore.add({
          category: f.category, pattern: v.pattern, action: "drop",
          reason: v.reason || "从误报回灌提取", source: "auto-learn",
        });
        ctx.learnSuggestions.push({ type: "fp_pattern", findingId: f.findingId, pattern: v.pattern, reason: v.reason });
        ctx.log_("LEARN", `误报回灌: 新增过滤规则 (${v.pattern.slice(0, 40)})`, "debug");
      } catch {
        ctx.log_("LEARN", `误报回灌: 正则非法 ${v.pattern}`, "warn");
      }
    }
  }

  // ── 2. 规则自动生成 ──
  if (config.learn.ruleGenerationEnabled) {
    const confirmed = ctx.findings.filter(
      (f) => (f.status === "fixed" || f.status === "confirmed") &&
             f.confidence >= config.learn.minConfidenceForRuleGen
    );
    for (const f of confirmed) {
      const prompt = `从以下确认的真漏洞中提炼检测规则。\n类别: ${f.category}\n代码:\n${f.snippet?.code || "?"}\n数据流: ${JSON.stringify(f.dataFlow || {})}\n请返回 JSON: {candidateRule:{ruleId,type:"structured",category,source:[],sink:[],falsePositiveFilters:[],confidenceBoost:0-1}, reason:string}`;
      const result = await llm.complete(prompt, { difficulty: "high", jsonMode: true });
      const candidate = result.structured?.candidateRule;
      if (candidate) {
        candidate.ruleId = candidate.ruleId || `AUTO-${f.findingId}`;
        candidate.enabled = false;
        candidate.version = "0.1.0";
        candidate.rolloutPercent = 0;
        ctx.learnSuggestions.push({ type: "candidate_rule", findingId: f.findingId, rule: candidate, reason: result.structured?.reason });
        ctx.log_("LEARN", `规则生成: 候选规则 ${candidate.ruleId} (待人工 review)`, "debug");
      }
    }
  }

  // ── 3. 图谱演化（用新接口 hasNode/addNode/addEdge 替换 nodes.has 直接访问）──
  const newVulns = ctx.findings.filter((f) => f.status === "fixed" || f.status === "confirmed");
  for (const f of newVulns) {
    const internalId = f.linkedCves?.[0] || `INTERNAL-${f.findingId}`;
    const exists = await knowledgeGraph.hasNode(internalId);
    if (!exists) {
      await knowledgeGraph.addNode(internalId, f.title, [f.category], {
        source: (f.dataFlow?.sources || []).map((s) => s.code),
        sink: (f.dataFlow?.sinks || []).map((s) => s.code),
      });
      for (const cve of f.linkedCves || []) {
        const cveExists = await knowledgeGraph.hasNode(cve);
        if (cve !== internalId && cveExists) {
          await knowledgeGraph.addEdge(internalId, cve, "VARIANT_OF");
        }
      }
      ctx.learnSuggestions.push({ type: "graph_node", nodeId: internalId, title: f.title });
    }
  }

  const kgStats = await knowledgeGraph.stats();
  ctx.log_(
    "LEARN",
    `学习完成：误报回灌 ${falsePositives.length} 条，候选规则 ${ctx.learnSuggestions.filter((s) => s.type === "candidate_rule").length} 条，图谱节点 ${kgStats.nodes}/${kgStats.edges}边`,
    "info"
  );
  return ctx;
}

module.exports = { learn };
