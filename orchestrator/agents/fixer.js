// agents/fixer.js — 修复 Agent
//
// 职责（方案第十四章）：
//   为 confirmed 的 Finding 生成 patch，并做等价性回归保障。
//   修复优先级：参数校验 > 白名单 > 编码转义 > 框架防护 > 重写（风险递增）
//
// 覆盖状态：FIX

const config = require("../config");
const { getLlm } = require("../llm");

// 各类别的修复策略提示（引导 LLM 选低风险手段）
const FIX_STRATEGY_HINTS = {
  sqli: "优先使用参数化查询（PreparedStatement / ORM 绑定参数），不要拼接 SQL",
  cmdi: "优先使用白名单 + ProcessBuilder，避免直接 exec 用户输入",
  xss: "优先使用框架自带的输出编码/转义（如 escapeHtml / 模板自动转义）",
  authz: "在资源访问处增加属主校验（如 @PreAuthorize / isOwner 检查）",
  business_logic: "增加状态校验、幂等键、范围检查（业务逻辑修复需人工 review）",
  path_traversal: "规范化路径后做白名单/根目录限制校验",
  overflow: "增加长度/边界检查，使用安全函数替代（strncpy 等）",
};

/**
 * FIX：为 confirmed Finding 生成 patch
 */
async function fix(ctx, deps) {
  const { findingStore } = deps;
  const llm = getLlm();
  ctx.log_("FIX", "修复生成开始", "info");

  const confirmed = ctx.findings.filter((f) => f.status === "confirmed");
  for (const f of confirmed) {
    const hint = FIX_STRATEGY_HINTS[f.category] || "采用最小侵入式修复，保持语义等价";
    const prompt = `为以下漏洞生成修复 patch。\n类别: ${f.category}\n原始代码:\n${f.snippet?.code || "?"}\n修复策略提示: ${hint}\n请返回 JSON: {patch:string(修复后代码), strategy:string, riskLevel:"low|medium|high", rationale:string}`;

    const result = await llm.complete(prompt, { difficulty: "high", jsonMode: true });
    const fixData = result.structured || {};
    const patchId = `PATCH-${f.findingId.split("-").slice(1).join("-")}`;

    // 等价性回归（mock：只打日志，真实环境跑前后测试用例对比）
    const equivalenceOk = config.fix.equivalenceCheck ? mockEquivalenceCheck(f, fixData.patch) : true;

    ctx.patches.push({
      patchId,
      findingId: f.findingId,
      patch: fixData.patch || "(生成失败)",
      strategy: fixData.strategy || hint,
      riskLevel: fixData.riskLevel || "medium",
      rationale: fixData.rationale || "",
      equivalenceCheck: equivalenceOk,
      generatedBy: result.model,
    });
    // 把 patch 内容直接挂到 Finding（供前端展示）
    f.patchId = patchId;
    f.patch = {
      code: fixData.patch || "(生成失败)",
      strategy: fixData.strategy || hint,
      riskLevel: fixData.riskLevel || "medium",
      rationale: fixData.rationale || "",
      equivalenceCheck: equivalenceOk,
    };
    if (equivalenceOk) {
      f.status = "fixed";
      ctx.log_("FIX", `Finding ${f.findingId} 修复完成 (${patchId}, strategy=${fixData.strategy || "?"})`, "debug");
    } else {
      ctx.log_("FIX", `Finding ${f.findingId} 等价性回归失败，patch 暂存待人工 review`, "warn");
    }
  }

  ctx.log_("FIX", `修复完成：${ctx.patches.length} 个 patch 生成`, "info");
  return ctx;
}

/**
 * Mock 等价性检查（真实环境：跑前后单元测试对比）
 */
function mockEquivalenceCheck(finding, patch) {
  // mock：只要 patch 非空就认为等价通过
  return !!(patch && patch.length > 10);
}

module.exports = { fix };
