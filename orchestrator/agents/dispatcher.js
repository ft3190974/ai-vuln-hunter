// agents/dispatcher.js — 调度 Agent（全 async，store 调用加 await）
//
// 职责：
//   INIT     工具结果归一化为 Finding
//   FILTER   误报库前置过滤（防幻觉放大）
//   DISPATCH 分类分发（直通/深判/专项）
//
// 注意：路由信息只记录到 pendingCandidates，不写入 Finding 对象
// （避免污染 Finding 违反 schema 的 additionalProperties:false）

const config = require("../config");
const { validate, formatErrors } = require("../../mcp-server/validator");

/**
 * INIT：把 toolOutputs 归一化为 Finding 候选
 */
async function normalize(ctx, deps) {
  const { findingStore } = deps;
  ctx.log_("INIT", "开始归一化工具输出", "info");

  let total = 0;
  const sast = ctx.toolOutputs.sast;
  if (sast && sast.findings) {
    for (const f of sast.findings) {
      const finding = await findingStore.create({
        title: f.message,
        category: f.category,
        severity: f.severity,
        description: f.message,
        location: {
          targetType: "source",
          file: f.location.file,
          function: f.location.function,
          startLine: f.location.startLine,
          endLine: f.location.endLine,
        },
        snippet: f.snippet,
        dataFlow: f.dataFlow,
        sources: [
          {
            toolId: sast.toolId, toolType: "SAST",
            rawRuleId: f.ruleId, toolConfidence: f.confidence || 0.7,
            reportedAt: sast.scannedAt,
          },
        ],
        confidence: f.confidence || 0.7,
        status: "candidate",
      });
      const { valid, errors } = validate("finding.schema.json", finding);
      if (!valid) {
        ctx.log_("INIT", `Finding ${finding.findingId} schema 校验失败: ${formatErrors(errors).slice(0, 120)}`, "warn");
      }
      ctx.findings.push(finding);
      total++;
    }
  }
  const sca = ctx.toolOutputs.sca;
  if (sca && sca.vulnerabilities) {
    for (const v of sca.vulnerabilities) {
      const finding = await findingStore.create({
        title: `组件漏洞: ${v.cve} (${v.package.name}@${v.package.version})`,
        category: "config",
        severity: v.severity,
        description: `${v.package.name}@${v.package.version} 受 ${v.cve} 影响`,
        location: { targetType: "source" },
        reachability: { level: 0, reachable: false },
        sources: [{ toolId: sca.toolId, toolType: "SCA", toolConfidence: 0.6, reportedAt: sca.scannedAt }],
        confidence: 0.6, status: "candidate", linkedCves: [v.cve],
      });
      ctx.findings.push(finding);
      total++;
    }
  }
  const bat = ctx.toolOutputs.bat;
  if (bat && bat.findings) {
    for (const f of bat.findings) {
      const finding = await findingStore.create({
        title: `固件缺陷: ${f.category} (${f.evidence})`,
        category: f.category, severity: f.severity, description: f.evidence,
        location: { targetType: "binary", binary: f.binary.path, function: f.location?.function, address: f.location?.address },
        snippet: f.snippet ? {
          code: f.snippet.code, language: "disasm",
          primaryLine: f.snippet.startLine || 1, startLine: f.snippet.startLine || 1, endLine: f.snippet.startLine || 1,
          contextType: "manual",
        } : undefined,
        sources: [{ toolId: bat.toolId, toolType: "BAT", toolConfidence: 0.7, reportedAt: bat.scannedAt }],
        confidence: 0.7, status: "candidate",
      });
      ctx.findings.push(finding);
      total++;
    }
  }

  ctx.log_("INIT", `归一化完成，共 ${total} 个 Finding 候选`, "info");
  return ctx;
}

/**
 * FILTER：误报库前置过滤
 */
async function filterFalsePositives(ctx, deps) {
  const { fpStore } = deps;
  ctx.log_("FILTER", "误报库前置过滤开始", "info");

  let dropped = 0;
  for (const f of ctx.findings) {
    if (f.status !== "candidate") continue;
    if (!f.snippet) continue;
    const result = await fpStore.match(f.snippet.code, f.category);
    if (result.hit) {
      f.status = "false_positive";
      f.reviewerNote = `误报库命中: ${result.reason} (FP-${result.fpId})`;
      f.confidence = Math.min(f.confidence, 0.2);
      dropped++;
      ctx.log_("FILTER", `Finding ${f.findingId} 命中误报库 (${result.reason})，标记为误报`, "info");
    }
  }
  ctx.log_("FILTER", `过滤完成，${dropped} 个标记为误报`, "info");
  return ctx;
}

/**
 * DISPATCH：分类分发
 */
async function dispatch(ctx, deps) {
  ctx.log_("DISPATCH", "分类分发开始", "info");
  const thresholds = { direct: 0.85 };

  for (const f of ctx.findings) {
    if (f.status !== "candidate") continue;
    // LLM_HUNT 高置信度产出（含业务逻辑）直接 confirmed（这些是 LLM 自主挖出来的，不走 SAST 通道）
    if (f.sources[0]?.toolId === "llm-hunter" && f.confidence >= 0.8) {
      f.status = "confirmed";
      f.reviewerNote = (f.reviewerNote || "") + " [LLM 自主挖掘，置信度高直通]";
      ctx.log_("DISPATCH", `Finding ${f.findingId} LLM 挖掘直通 confirmed (conf=${f.confidence})`, "debug");
      continue;
    }
    if (f.category === "business_logic") {
      ctx.pendingCandidates.push({ findingId: f.findingId, route: "deep", reason: "业务逻辑需 LLM 深判" });
      continue;
    }
    if (f.confidence >= thresholds.direct && f.sources[0]?.toolType === "SAST") {
      f.status = "confirmed";
      f.reviewerNote = (f.reviewerNote || "") + " [直通：工具置信度高]";
      ctx.log_("DISPATCH", `Finding ${f.findingId} 直通 confirmed (conf=${f.confidence})`, "debug");
      continue;
    }
    ctx.pendingCandidates.push({ findingId: f.findingId, route: "deep", reason: "需 LLM 深判" });
  }
  ctx.log_("DISPATCH", `分发完成：${ctx.pendingCandidates.length} 个进入深判，其余直通`, "info");
  return ctx;
}

module.exports = { normalize, filterFalsePositives, dispatch };
