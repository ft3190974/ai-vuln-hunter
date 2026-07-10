// agents/verifier.js — 验证 Agent
//
// 职责（方案第六章 + 第十三章）：
//   1. RAG_MATCH：知识图谱相似度匹配，关联 CVE/变种（0-day 种子）
//   2. VERIFY：可达性判定（L1-L4）+ POC 生成
//
// 覆盖状态：RAG_MATCH + VERIFY

const config = require("../config");
const { getLlm } = require("../llm");
const { getSandbox } = require("../sandbox");

/**
 * RAG_MATCH：知识图谱匹配，关联 CVE/变种
 */
async function ragMatch(ctx, deps) {
  const { knowledgeGraph, findingStore } = deps;
  ctx.log_("RAG_MATCH", "知识图谱关联开始", "info");

  let linked = 0;
  for (const f of ctx.findings) {
    if (f.status === "false_positive") continue;

    // 按 source/sink 签名检索相似 CVE
    const signature = {
      source: (f.dataFlow?.sources || []).map((s) => s.code),
      sink: (f.dataFlow?.sinks || []).map((s) => s.code),
    };
    const similar = await knowledgeGraph.findBySignature(signature);
    if (similar.length > 0) {
      const related = similar.map((n) => n.id);
      f.linkedCves = [...new Set([...(f.linkedCves || []), ...related])];
      // 若关联到变种，标记 0-day 候选
      if (f.isZeroDay === undefined && related.length > 0) {
        f.isZeroDay = !related.some((c) => c.startsWith("CVE-")); // 无 CVE 关联 = 可能 0-day
      }
      linked++;
      ctx.log_("RAG_MATCH", `Finding ${f.findingId} 关联 ${related.length} 个 CVE/变种: ${related.join(",")}`, "debug");
    }
  }
  ctx.log_("RAG_MATCH", `关联完成：${linked} 个 Finding 建立图谱关系`, "info");
  return ctx;
}

/**
 * VERIFY：可达性 + POC 生成
 */
async function verify(ctx, deps) {
  const { findingStore } = deps;
  const llm = getLlm();
  ctx.log_("VERIFY", "验证开始（可达性 + POC 生成）", "info");

  for (const f of ctx.findings) {
    if (f.status !== "confirmed" && f.status !== "candidate") continue;
    if (f.status === "candidate" && f.confidence < config.detection.confidenceThreshold) continue;

    // ── 可达性判定 ──
    // SCA 组件漏洞：走可达性分析
    if (f.sources[0]?.toolType === "SCA" && f.reachability) {
      const code = f.snippet?.code || "";
      const prompt = `判断以下代码是否可达（是否调用了脆弱函数）。\n漏洞: ${f.linkedCves?.[0] || "?"}\n代码片段:\n${code || "(无源码，仅组件级)"}\n请返回 JSON: {reachable:bool, level:1-4, confidence:0-1, reasoning:string}`;
      const result = await llm.complete(prompt, { difficulty: "high", jsonMode: true });
      const v = result.structured || {};
      f.reachability = {
        level: v.level || 3,
        reachable: v.reachable !== false,
        evidence: v.reasoning || "LLM 语义判定",
        verifiedBy: "llm",
        analyzedAt: new Date().toISOString(),
      };
      if (!f.reachability.reachable) {
        f.status = "false_positive";
        f.reviewerNote = (f.reviewerNote || "") + " [SCA 可达性判定为不可达]";
        ctx.log_("VERIFY", `Finding ${f.findingId} SCA 不可达，标记误报`, "info");
        continue;
      }
    }

    // ── POC 生成（仅对 confirmed）──
    if (f.status === "confirmed") {
      const pocPrompt = `为以下漏洞生成 POC（结构化描述）。\n类别: ${f.category}\n位置: ${f.location.file || "?"}:${f.location.startLine || "?"}\n代码:\n${f.snippet?.code || "?"}\n请返回 JSON: {poc:{entry,payload,precondition,expected}, confidence:0-1}`;
      const pocResult = await llm.complete(pocPrompt, { difficulty: "high", jsonMode: true });
      const pocData = pocResult.structured?.poc || pocResult.structured || {};
      const pocId = `POC-${f.findingId.split("-").slice(1).join("-")}`;
      const poc = {
        vulnType: f.category,
        entry: pocData.entry || "(待补充)",
        payload: pocData.payload || "(待补充)",
        precondition: pocData.precondition || "(待补充)",
        expected: pocData.expected || "(待补充)",
      };

      // ── 沙箱执行验证 ──
      // 在隔离环境实跑 POC，triggered=true 才算真正确认（verifiedBy 升级为 sandbox）
      const sandbox = await getSandbox();
      const execResult = await sandbox.execute({
        poc,
        targetType: f.location.targetType === "binary" ? "firmware" : "web",
        language: f.snippet?.language,
        binaryPath: f.location.binary,
      });

      ctx.verifiedPocs.push({
        pocId,
        findingId: f.findingId,
        poc,
        confidence: execResult.triggered
          ? Math.min((pocResult.structured?.confidence || 0.7) + 0.15, 0.99) // 沙箱验证通过，置信度提升
          : Math.max((pocResult.structured?.confidence || 0.7) - 0.2, 0.3), // 未触发，降低
        generatedBy: pocResult.model,
        // ★ 沙箱验证结果
        sandboxVerified: execResult.triggered,
        sandboxImpl: execResult.sandboxImpl,
        sandboxEvidence: execResult.evidence,
        sandboxResponse: execResult.response,
        durationMs: execResult.durationMs,
      });
      // 把 POC 内容直接挂到 Finding 上（供前端展示，避免额外查询）
      f.pocId = pocId;
      f.poc = {
        ...poc,
        sandboxVerified: execResult.triggered,
        sandboxEvidence: execResult.evidence,
        confidence: execResult.triggered
          ? Math.min((pocResult.structured?.confidence || 0.7) + 0.15, 0.99)
          : Math.max((pocResult.structured?.confidence || 0.7) - 0.2, 0.3),
        // ★ 完整沙箱验证过程（供前端展示"验证是怎么做的"）
        sandboxRun: {
          impl: execResult.sandboxImpl,            // mock / docker
          targetType: f.location.targetType === "binary" ? "firmware" : "web",
          input: {
            poc,                                   // 输入的 POC
            endpoint: poc.entry,
            payload: poc.payload,
          },
          steps: [
            { step: 1, action: "构造 POC 请求", detail: `${poc.entry || "(无)"} payload=${poc.payload || "(无)"}` },
            { step: 2, action: `沙箱执行（${execResult.sandboxImpl}）`, detail: `隔离环境运行，超时 30s，网络隔离` },
            { step: 3, action: "捕获响应", detail: JSON.stringify(execResult.response || {}).slice(0, 200) },
          ],
          response: execResult.response,           // 原始响应
          durationMs: execResult.durationMs,
          verdict: execResult.triggered ? "triggered" : "not_triggered",
          verdictReason: execResult.evidence,      // 判定依据
        },
      };

      // 根据沙箱结果调整 Finding 的 reachability.verifiedBy
      if (execResult.triggered) {
        // 沙箱验证通过，reachability 升级到 level 4（动态确认）
        // 没有 reachability 字段的 Finding（如 SAST 直通的）也补一个
        f.reachability = {
          level: 4,
          reachable: true,
          verifiedBy: "sandbox",
          evidence: `沙箱验证: ${execResult.evidence}`,
          analyzedAt: new Date().toISOString(),
        };
        ctx.log_("VERIFY", `Finding ${f.findingId} POC 沙箱验证通过 (${pocId}, ${execResult.sandboxImpl})`, "debug");
      } else {
        ctx.log_("VERIFY", `Finding ${f.findingId} POC 沙箱未触发 (${execResult.sandboxImpl}): ${execResult.evidence}`, "info");
      }
    }
  }

  const sandboxVerified = ctx.verifiedPocs.filter((p) => p.sandboxVerified).length;
  ctx.log_("VERIFY", `验证完成：${ctx.verifiedPocs.length} 个 POC，其中 ${sandboxVerified} 个沙箱确认`, "info");
  return ctx;
}

module.exports = { ragMatch, verify };
