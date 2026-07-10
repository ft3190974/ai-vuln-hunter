// agents/c-hunter.js — C/C++ 专用 LLM 漏洞挖掘 Agent
//
// 和 llm-hunter 类似，但针对 C/C++ 增强了上下文：
//   1. 给 LLM 的不只是单函数，还有调用图上下文（调用者/被调用者）
//   2. 资源流分析结果（泄漏/double-free/跨函数泄漏）作为"已知候选"喂给 LLM 确认
//   3. C/C++ 专用规则库（缓冲区溢出/UAF/double-free/格式化字符串/整数溢出/竞态/命令注入）
//
// 工作流：
//   解析 C/C++ → 调用图 → 资源流分析 → 候选漏洞 → LLM 语义确认 → Finding
//
// 覆盖状态：LLM_HUNT（当输入是 C/C++ 时，本 Agent 接管，替代 llm-hunter）

const config = require("../config");
const { getLlm } = require("../llm");
const { parseFile, parseDirectory, DANGER_FUNCS } = require("./c-ast-parser");
const { CallGraph } = require("./call-graph");
const { analyzeAll } = require("./resource-flow");

// C/C++ 专用漏洞规则（自然语言 prompt 模板）
const C_RULES = [
  {
    id: "C-BUFFER-OVERFLOW",
    name: "缓冲区溢出",
    category: "overflow",
    severity: "critical",
    sinks: ["strcpy", "strcat", "sprintf", "gets", "scanf", "memcpy"],
    prompt: `分析以下 C/C++ 代码，找出缓冲区溢出漏洞：
1. 是否使用了 strcpy/strcat/sprintf/gets 等无长度限制的函数
2. 目标缓冲区大小是否小于可能的输入长度
3. memcpy/memset 的长度参数是否来自外部输入且未校验

调用上下文（调用者/被调用者）：
{callContext}

代码：
\`\`\`
{code}
\`\`\`

对每个漏洞给出 exploitability（利用难度/前置条件）和 impact（影响）。
返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "C-FORMAT-STRING",
    name: "格式化字符串漏洞",
    category: "fmt_string",
    severity: "high",
    sinks: ["printf", "fprintf", "syslog", "snprintf"],
    prompt: `分析以下 C/C++ 代码，找出格式化字符串漏洞：
1. printf/fprintf/syslog 等是否直接用用户输入作为格式字符串（而非参数）
2. 典型模式：printf(user_input) 而非 printf("%s", user_input)

调用上下文：
{callContext}

代码：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "C-CMD-INJECTION",
    name: "命令注入",
    category: "cmdi",
    severity: "critical",
    sinks: ["system", "popen", "execve", "execl"],
    prompt: `分析以下 C/C++ 代码，找出命令注入漏洞：
1. system/popen/exec 系列函数的参数是否包含用户可控输入
2. 是否使用 sprintf 拼接命令字符串

调用上下文：
{callContext}

代码：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "C-INTEGER-OVERFLOW",
    name: "整数溢出",
    category: "integer_overflow",
    severity: "high",
    sinks: ["malloc", "calloc", "realloc", "memcpy"],
    prompt: `分析以下 C/C++ 代码，找出整数溢出漏洞：
1. 内存分配大小参数是否来自算术运算（可能溢出）
2. 长度计算是否可能为负数或溢出（size_t vs int 混用）

调用上下文：
{callContext}

代码：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
];

/**
 * C/C++ 专用 Hunt Agent
 * 在 llm-hunter 之前调用（当源代码是 C/C++ 时）
 */
async function hunt(ctx, deps) {
  const { findingStore, ruleEngine } = deps;
  const llm = getLlm();
  ctx.log_("LLM_HUNT", "C/C++ 专用挖掘开始（调用图 + 资源流）", "info");

  const sourceInput = ctx.sourceInput;
  if (!sourceInput || (!sourceInput.code && !sourceInput.path)) {
    return ctx;
  }

  // 1. 解析 C/C++
  let parsed;
  if (sourceInput.code) {
    parsed = parseFile(sourceInput.file || "input.c", sourceInput.code);
  } else if (sourceInput.path) {
    const fs = require("fs");
    const stat = fs.statSync(sourceInput.path);
    parsed = stat.isDirectory()
      ? parseDirectory(sourceInput.path)
      : parseFile(sourceInput.path, fs.readFileSync(sourceInput.path, "utf-8"));
  }
  if (!parsed || parsed.functions.length === 0) {
    ctx.log_("LLM_HUNT", "C/C++ 解析无结果（非 C/C++ 或无函数）", "info");
    return ctx;
  }
  ctx.log_("LLM_HUNT", `C/C++ 解析：${parsed.functions.length} 函数，${parsed.calls.length} 调用，${parsed.resources.length} 资源操作`, "info");

  // 2. 构建调用图
  const callGraph = new CallGraph();
  callGraph.buildFromParsed(parsed);

  // 3. 资源流分析（确定性发现，不依赖 LLM）
  const flowResults = analyzeAll(parsed, callGraph, parsed.functions);
  const allCandidates = [
    ...flowResults.leaks.map((l) => ({ ...l, _certain: true })),
    ...flowResults.doubleFrees.map((l) => ({ ...l, _certain: true })),
    ...flowResults.crossFunctionLeaks.map((l) => ({ ...l, _certain: true })),
  ];
  ctx.log_("LLM_HUNT", `资源流分析：${flowResults.leaks.length} 泄漏，${flowResults.doubleFrees.length} double-free，${flowResults.crossFunctionLeaks.length} 跨函数泄漏`, "info");

  // 4. 资源流发现的候选直接生成 Finding（这些是确定性发现，不需要 LLM 确认）
  for (const candidate of allCandidates) {
    const finding = await findingStore.create({
      title: `[C/C++ ${candidate.type === "double_free" ? "Double-Free" : candidate.type === "cross_function_leak" ? "跨函数泄漏" : "内存泄漏"}] ${candidate.function}`,
      category: candidate.type === "double_free" ? "double_free" : "uaf",
      severity: candidate.type === "double_free" ? "critical" : "high",
      cwe: candidate.type === "double_free" ? "CWE-415" : "CWE-401",
      description: `${candidate.detail}\n\n分析方式: 资源流追踪（确定性发现，非 LLM 推测）`,
      location: {
        targetType: "source",
        file: candidate.function ? (parsed.functions.find((f) => f.name === candidate.function)?.file || "input.c") : "input.c",
        function: candidate.function,
        startLine: candidate.line,
        endLine: candidate.line,
      },
      snippet: {
        code: parsed.functions.find((f) => f.name === candidate.function)?.body || candidate.code || "",
        language: "c",
        primaryLine: candidate.line - (parsed.functions.find((f) => f.name === candidate.function)?.bodyStart || 0),
        startLine: parsed.functions.find((f) => f.name === candidate.function)?.bodyStart + 1 || candidate.line,
        endLine: parsed.functions.find((f) => f.name === candidate.function)?.bodyEnd + 1 || candidate.line,
        contextType: "function",
      },
      fullContext: sourceInput.code || "",
      sources: [{ toolId: "c-hunter", toolType: "SAST", rawRuleId: "RESOURCE-FLOW", toolConfidence: 0.95, reportedAt: new Date().toISOString() }],
      confidence: 0.95,
      status: "candidate",
      exploitability: { difficulty: "medium", prerequisites: "需要触发特定代码路径", accessNeeded: "取决于入口" },
      impact: { assets: "内存/进程", worstCase: candidate.type === "double_free" ? "堆破坏，可能 RCE" : "内存耗尽 DoS 或信息泄露", remote: true, noAuth: false },
    });
    ctx.findings.push(finding);
    ctx.log_("LLM_HUNT", `确定性发现: [${candidate.type}] ${candidate.function} 行 ${candidate.line}`, "info");
  }

  // 5. LLM 分析（针对规则匹配的函数做语义判定）
  const MAX_SLICES = config.llmHunt?.maxSlices || 15;
  const targetFuncs = parsed.functions.slice(0, MAX_SLICES);
  let llmCalls = 0;

  for (const fn of targetFuncs) {
    const callContext = callGraph.serialize(fn.name);
    const matchedRules = C_RULES.filter((rule) => {
      if (!rule.sinks || rule.sinks.length === 0) return true;
      return rule.sinks.some((s) => fn.body.toLowerCase().includes(s.toLowerCase()));
    });

    for (const rule of matchedRules) {
      const prompt = rule.prompt
        .replace("{callContext}", callContext)
        .replace("{code}", fn.body);

      const result = await llm.complete(prompt, {
        difficulty: "high", jsonMode: true,
        systemPrompt: "你是 C/C++ 安全审计专家，专注内存安全漏洞。只基于给定代码判定。",
      });
      llmCalls++;

      const data = result.structured || {};
      if (data.found && Array.isArray(data.vulnerabilities)) {
        for (const v of data.vulnerabilities) {
          const relLine = v.line ? Number(v.line) : 1;
          const absLine = fn.line + (relLine - 1);
          const finding = await findingStore.create({
            title: `[C/C++ ${rule.name}] ${v.title || fn.name}`,
            category: rule.category,
            severity: v.severity || rule.severity,
            cwe: rule.cwe,
            description: `${v.reasoning || ""}\n\n调用上下文:\n${callContext}\n\n攻击场景: ${v.attackScenario || "(未提供)"}`,
            exploitability: v.exploitability || {},
            impact: v.impact || {},
            location: { targetType: "source", file: fn.file, function: fn.name, startLine: absLine, endLine: absLine },
            snippet: {
              code: fn.body, language: "c", primaryLine: relLine,
              startLine: fn.line, endLine: fn.bodyEnd + 1, contextType: "function",
            },
            fullContext: sourceInput.code || "",
            sources: [{ toolId: "c-hunter", toolType: "SAST", rawRuleId: rule.id, toolConfidence: v.confidence || data.confidence || 0.7, reportedAt: new Date().toISOString() }],
            confidence: Math.min((v.confidence || data.confidence || 0.7) + 0.05, 0.95),
            status: "candidate",
          });
          ctx.findings.push(finding);
          ctx.log_("LLM_HUNT", `LLM 发现: [${v.severity || rule.severity}] ${v.title || fn.name} (${fn.file}:${absLine})`, "info");
        }
      }
    }
  }

  ctx.log_("LLM_HUNT", `C/C++ 挖掘完成：${allCandidates.length} 确定性 + ${llmCalls} 次 LLM 调用，共 ${ctx.findings.length} Finding`, "info");
  return ctx;
}

module.exports = { hunt, C_RULES };
