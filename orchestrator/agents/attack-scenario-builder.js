// agents/attack-scenario-builder.js — 复杂攻击场景构建器
//
// 扫描完成后，LLM 拿本次所有 Finding 构建多漏洞组合攻击路径（DAG）。
// 例：SSRF → 越权获取 token → 反序列化 RCE
//
// 覆盖状态：ATTACK_SCENARIO（VERIFY 之后、FIX 之前）

const { getLlm } = require("../llm");

async function build(ctx, deps) {
  const { findingStore } = deps;
  const llm = getLlm();
  ctx.log_("ATTACK_SCENARIO", "开始构建攻击场景", "info");

  // 取本次扫描的所有 confirmed/fixed Finding
  const confirmed = ctx.findings.filter(
    (f) => f.status === "confirmed" || f.status === "fixed" || f.status === "candidate"
  );

  if (confirmed.length === 0) {
    ctx.log_("ATTACK_SCENARIO", "无漏洞，跳过攻击场景构建", "info");
    return ctx;
  }

  if (confirmed.length === 1) {
    ctx.log_("ATTACK_SCENARIO", "仅 1 个漏洞，构建简单场景", "info");
  }

  // 准备漏洞摘要给 LLM
  const vulnSummary = confirmed.map((f) => ({
    findingId: f.findingId,
    title: f.title,
    category: f.category,
    severity: f.severity,
    location: `${f.location?.file || "?"}:${f.location?.startLine || "?"}`,
    function: f.location?.function,
    exploitability: f.exploitability,
    impact: f.impact,
  }));

  const prompt = `你是红队攻击路径分析专家。基于以下发现的多个漏洞，构建一条完整的组合攻击路径（攻击者如何从外部一步步打穿系统）。

【发现的漏洞】
${JSON.stringify(vulnSummary, null, 2)}

【任务】
1. 找出哪些漏洞可以组合利用（A 的输出是 B 的输入）
2. 构建有向无环图（DAG），标注每步的输入输出和条件
3. 如果漏洞无法组合，每条独立路径单独列出

返回 JSON:
{
  "summary": "一句话总结攻击路径",
  "difficulty": "low|medium|high",
  "impact": "最终影响（如：完全接管服务器/数据泄露）",
  "paths": [
    {
      "name": "路径名称",
      "nodes": [
        {"id": "attacker", "label": "攻击者", "type": "entry"},
        {"id": "s1", "label": "利用漏洞A", "findingId": "F-xxx", "type": "vuln", "output": "获取了XX", "detail": "怎么做的"},
        {"id": "s2", "label": "利用漏洞B", "findingId": "F-yyy", "type": "vuln", "output": "获取了YY", "detail": "需要 s1 的输出"}
      ],
      "edges": [
        {"from": "attacker", "to": "s1"},
        {"from": "s1", "to": "s2", "label": "XX"}
      ]
    }
  ]
}`;

  const result = await llm.complete(prompt, {
    difficulty: "high",
    jsonMode: true,
    systemPrompt: "你是红队攻击路径分析专家，擅长组合多个漏洞构建完整攻击链。",
  });

  const scenario = result.structured || {};
  ctx.attackScenario = {
    summary: scenario.summary || "（无法构建）",
    difficulty: scenario.difficulty || "unknown",
    impact: scenario.impact || "未知",
    paths: scenario.paths || [],
    findingsCount: confirmed.length,
    builtAt: new Date().toISOString(),
  };

  ctx.log_(
    "ATTACK_SCENARIO",
    `攻击场景构建完成：${ctx.attackScenario.paths.length} 条路径，难度 ${ctx.attackScenario.difficulty}`,
    "info"
  );
  return ctx;
}

module.exports = { build };
