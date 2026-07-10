// agents/detector.js — 检测 Agent
//
// 职责（方案第五章 5.2 检测 Agent 分类）：
//   对深判候选用规则引擎 + LLM 做深度判定。
//   - structured 规则：确定性匹配（source/sink/condition），零幻觉
//   - llm_prompt 规则：渲染模板后调 LLM，半结构化判定
//
// 覆盖状态：DETECT

const config = require("../config");
const { getLlm } = require("../llm");

/**
 * DETECT：对 pendingCandidates 做深度判定
 */
async function detect(ctx, deps) {
  const { ruleEngine, findingStore } = deps;
  const llm = getLlm();
  ctx.log_("DETECT", `深度判定开始，候选 ${ctx.pendingCandidates.length} 个`, "info");

  let confirmed = 0;
  let falsePos = 0;

  for (const candidate of ctx.pendingCandidates) {
    const f = await findingStore.get(candidate.findingId);
    if (!f) continue;

    // 1. structured 规则匹配
    const matches = await ruleEngine.matchStructured({
      category: f.category,
      code: f.snippet?.code || "",
      language: f.snippet?.language,
      dataFlow: f.dataFlow,
    });

    let ruleConfidence = 0;
    let matchedRule = null;
    for (const m of matches) {
      if (m.matched && m.confidence > ruleConfidence) {
        ruleConfidence = m.confidence;
        matchedRule = m.rule;
      }
      if (m.reason && m.reason.includes("误报")) {
        f.status = "false_positive";
        f.reviewerNote = (f.reviewerNote || "") + ` [规则 ${m.rule.ruleId} 判定为误报]`;
        falsePos++;
        ctx.log_("DETECT", `Finding ${f.findingId} 规则判定为误报 (${m.rule.ruleId})`, "info");
        break;
      }
    }
    if (f.status === "false_positive") continue;

    // 2. 若有 llm_prompt 规则匹配该类别，调 LLM 深判
    const promptRules = (await ruleEngine.select(f.category, f.snippet?.language))
      .filter((r) => r.type === "llm_prompt");

    if (promptRules.length > 0 || f.category === "business_logic") {
      const rule = promptRules[0] || {
        llmPrompt: "判定以下代码是否为真漏洞（类别 {category}）。\n代码：{code}\n请返回 JSON：{verdict,confidence,reasoning,evidence}",
        evidenceRequired: ["必须指出漏洞点"],
        confidenceBoost: 0.7,
      };
      const prompt = rule.llmPrompt
        ? ruleEngine.renderPrompt(rule, {
            code: f.snippet?.code || "(无代码片段)",
            context: JSON.stringify(f.dataFlow || {}),
            category: f.category,
            cve: (f.linkedCves || [])[0] || "",
          })
        : ruleEngine.renderPrompt(
            { llmPrompt: rule.llmPrompt, evidenceRequired: rule.evidenceRequired },
            { code: f.snippet?.code || "", category: f.category }
          );

      const result = await llm.complete(prompt, {
        difficulty: "high",
        jsonMode: true,
        systemPrompt: "你是资深安全审计专家，专注漏洞判定。只基于给定代码判定，不要臆测未给出的代码。",
      });
      const v = result.structured || {};
      ctx.log_("DETECT", `LLM 判定 ${f.findingId}: verdict=${v.verdict} conf=${v.confidence} (model=${result.model})`, "debug");

      if (v.verdict === "false_positive") {
        f.status = "false_positive";
        f.reviewerNote = (f.reviewerNote || "") + ` [LLM 判定误报: ${v.reasoning || ""}]`;
        falsePos++;
        continue;
      }
      if (v.verdict === "confirmed" || v.verdict === "suspect") {
        // 综合 confidence = max(规则, LLM) 与置信度加成
        const llmConf = typeof v.confidence === "number" ? v.confidence : 0.6;
        f.confidence = Math.max(ruleConfidence, llmConf) + (rule.confidenceBoost || 0) * 0.1;
        f.confidence = Math.min(f.confidence, 0.99);
        if (v.reasoning) f.description += `\n[LLM 推理] ${v.reasoning}`;
        if (v.verdict === "confirmed" && f.confidence >= config.detection.confidenceThreshold) {
          f.status = "confirmed";
          confirmed++;
        } else {
          f.status = "candidate"; // suspect 保持候选
        }
      }
    } else if (ruleConfidence > 0) {
      // 仅规则命中，无 LLM 判定
      f.confidence = Math.min(ruleConfidence + 0.05, 0.95);
      f.status = f.confidence >= config.detection.confidenceThreshold ? "confirmed" : "candidate";
      if (f.status === "confirmed") confirmed++;
      f.reviewerNote = (f.reviewerNote || "") + ` [规则 ${matchedRule.ruleId} 命中]`;
    }
  }

  ctx.log_("DETECT", `检测完成：${confirmed} 个确认，${falsePos} 个误报`, "info");
  return ctx;
}

module.exports = { detect };
