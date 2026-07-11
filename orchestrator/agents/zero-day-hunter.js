// agents/zero-day-hunter.js — 0-day 变种挖掘 Agent（全 async）
//
// 三支点：变种图谱遍历 + 代码相似检索 + LLM 改写推理。
// 生成的 0-day 候选标记 isZeroDay=true，关联种子 relatedFindings。
// 覆盖状态：ZERO_DAY

const config = require("../config");
const { getLlm } = require("../llm");

async function huntZeroDay(ctx, deps) {
  const { knowledgeGraph, findingStore } = deps;
  const llm = getLlm();
  ctx.log_("ZERO_DAY", "0-day 变种挖掘开始", "info");

  const seeds = ctx.findings.filter(
    (f) => (f.status === "confirmed" || f.status === "fixed") && f.snippet
  );

  let generated = 0;
  for (const seed of seeds) {
    // 1. 沿图谱找该漏洞的变种 CVE（有 linkedCves 才查）
    const linkedCves = seed.linkedCves || [];
    let variants = [];
    for (const cve of linkedCves) {
      variants = variants.concat(await knowledgeGraph.findVariants(cve));
    }
    const variantIds = [...new Set(variants.map((v) => v.id))];
    const variantNodes = [];
    for (const id of variantIds) {
      const node = await knowledgeGraph.getNode(id);
      if (node) variantNodes.push(node);
    }

    // ★ 即使没有 linkedCves / 图谱变种，也用 LLM 推理（基于代码模式本身外推）
    const hasVariants = variantNodes.length > 0;

    // 2. LLM 推理（即使无图谱变种，也基于代码模式外推）
    const variantInfo = hasVariants
      ? variantNodes.map((v) => `- ${v.id}: ${v.title} (source: ${v.signature?.source?.join(",") || "?"}, sink: ${v.signature?.sink?.join(",") || "?"})`).join("\n")
      : "(无已知图谱变种，请基于漏洞代码模式本身推理语义变体——改变 source/sink/触发路径/绕过现有防护)";

    const prompt = `你是 0-day 漏洞挖掘专家。基于以下已确认漏洞，推理可能的"未被已知 CVE 覆盖的语义变体"。

【种子漏洞】
类别: ${seed.category}
代码:
${seed.snippet.code}
数据流 source: ${(seed.dataFlow?.sources || []).map((s) => s.code).join(", ") || "?"}
数据流 sink: ${(seed.dataFlow?.sinks || []).map((s) => s.code).join(", ") || "?"}

【图谱中的已知变种】
${variantInfo}

【任务】
请列出 1-3 个"语义变体"——即通过改变 source、改变 sink、改变触发路径、或绕过现有防护，可能产生的新攻击路径。这些变体不应被已知 CVE 完全覆盖（即 0-day 候选）。

请返回 JSON: {variants: [{description, newSource, newSink, reachable:bool, confidence:0-1, reasoning}]}`;

    const result = await llm.complete(prompt, {
      difficulty: "high", jsonMode: true,
      systemPrompt: "你是 0-day 漏洞挖掘专家，专注于发现已知漏洞的语义变种。只基于给定信息推理，不要臆测。",
    });
    const rawVariants = result.structured?.variants || [];
    const candidateVariants = rawVariants.filter(
      (v) => v.reachable !== false && (v.confidence || 0) >= 0.5
    );

    ctx.log_("ZERO_DAY", `种子 ${seed.findingId}: 图谱变种 ${variantIds.length} 个，LLM 原始 ${rawVariants.length} 个，过滤后 ${candidateVariants.length} 个 0-day 候选`, "debug");

    // 3. 为高置信度候选生成新 Finding
    for (const v of candidateVariants) {
      const zeroDayFinding = await findingStore.create({
        title: `[0-day 候选] ${seed.category} 变种: ${v.description || "(未命名)"}`,
        category: seed.category, severity: seed.severity,
        description: `基于 ${seed.findingId}（${seed.title}）外推的语义变种。\n推理: ${v.reasoning || ""}\n新 source: ${v.newSource || "?"}\n新 sink: ${v.newSink || "?"}`,
        location: seed.location, snippet: seed.snippet,
        sources: [{ toolId: "zero-day-hunter", toolType: "SAST", toolConfidence: v.confidence || 0.6, reportedAt: new Date().toISOString() }],
        confidence: Math.min((v.confidence || 0.6) + 0.1, 0.95),
        status: "candidate", isZeroDay: true, relatedFindings: [seed.findingId],
        linkedCves: variantIds.filter((id) => id.startsWith("CVE-")),
      });
      ctx.findings.push(zeroDayFinding);
      ctx.learnSuggestions.push({
        type: "zero_day_candidate", findingId: zeroDayFinding.findingId,
        seedFindingId: seed.findingId, description: v.description, confidence: v.confidence,
      });
      generated++;
      ctx.log_("ZERO_DAY", `生成 0-day 候选 ${zeroDayFinding.findingId}: ${v.description?.slice(0, 50)}`, "debug");
    }
  }

  ctx.log_("ZERO_DAY", `0-day 挖掘完成，生成 ${generated} 个候选`, "info");
  return ctx;
}

module.exports = { huntZeroDay };
