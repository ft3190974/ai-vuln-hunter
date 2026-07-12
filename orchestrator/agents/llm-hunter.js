// agents/llm-hunter.js — LLM 自主挖掘 Agent（核心差异化能力）
//
// 不依赖 SAST/SCA/BAT 工具输出，直接读源代码切片，让 LLM 自主找漏洞。
// 重点挖掘业务逻辑漏洞（SAST 永远发现不了的领域）+ 高危漏洞补充。
//
// 工作流：
//   1. 从 ctx.sourceInput（代码/路径）切片
//   2. 对每个 slice，按"关注点过滤"选择要问的规则
//   3. 调 LLM 自主分析（每类规则一次调用）
//   4. LLM 报告的漏洞转为 Finding（candidate），进入后续 VERIFY/FIX 流程
//
// 覆盖状态：LLM_HUNT（插在 INIT 之后、FILTER 之前，独立于工具通道）

const config = require("../config");
const { getLlm } = require("../llm");
const { sliceSource } = require("./code-slicer");
const { BUSINESS_VULN_TYPES, HIGH_RISK_TYPES } = require("./business-rules");
const { scanDependencies } = require("./dependency-scanner");
const { matchKnownVulns } = require("./cve-matcher");

/**
 * 判断一个 slice 是否值得用某条规则深查
 * - 规则无 sinks（或为空）：全查（业务逻辑类通常无具体 sink）
 * - 规则有 sinks：代码含任一 sink 关键词才查（省 LLM 调用）
 */
function sliceMatchesRule(slice, rule) {
  if (!rule.sinks || rule.sinks.length === 0) return true;
  const code = (slice.code || "").toLowerCase();
  return rule.sinks.some((s) => code.includes(String(s).toLowerCase()));
}

/**
 * LLM_HUNT：自主挖掘
 */
async function hunt(ctx, deps) {
  const { findingStore, ruleEngine } = deps;
  const llm = getLlm();
  ctx.log_("LLM_HUNT", "LLM 自主挖掘开始（不依赖工具输出）", "info");

  // 输入来源：ctx.sourceInput（由 engine.run 注入）
  const sourceInput = ctx.sourceInput;
  if (!sourceInput || (!sourceInput.code && !sourceInput.path)) {
    ctx.log_("LLM_HUNT", "无源代码输入，跳过 LLM 自主挖掘（走工具通道）", "info");
    return ctx;
  }

  // ★ Web 渗透测试：URL 输入时实际发起请求测试
  const isWebUrl = (sourceInput.type === "web") || /^https?:\/\//.test(sourceInput.path || sourceInput.code || sourceInput.url || "");
  if (isWebUrl && sourceInput.type !== "git") {
    ctx.log_("LLM_HUNT", "检测到 Web URL，启用 Web 渗透测试模式", "info");
    const webHunter = require("./web-pentest-hunter");
    return webHunter.hunt(ctx, deps);
  }

  // ★ Git 仓库 clone（用户输入 Git 地址拉取源码）
  if (sourceInput.gitUrl) {
    ctx.log_("LLM_HUNT", `Git clone: ${sourceInput.gitUrl}`, "info");
    const { cloneRepo } = require("./git-clone");
    try {
      const cloned = cloneRepo(sourceInput.gitUrl);
      sourceInput.path = cloned.path;
      ctx.log_("LLM_HUNT", `Clone 完成: ${cloned.repoName} → ${cloned.path}`, "info");
    } catch (e) {
      ctx.log_("LLM_HUNT", `Clone 失败: ${e.message}`, "error");
      return ctx;
    }
  }

  // ★ AI 安全模式：检测 LLM 应用 / Skill / MCP / 模型项目漏洞
  if (sourceInput.aiSecurity) {
    ctx.log_("LLM_HUNT", "检测到 AI 安全模式，启用 AI 安全漏洞挖掘（3 维度）", "info");
    const aiSecHunter = require("./ai-security-hunter");
    return aiSecHunter.hunt(ctx, deps);
  }

  // ★ Java 二进制（.jar/.class）：反编译后走源码分析
  const isJavaBinary = isJavaJarOrClass(sourceInput);
  if (isJavaBinary) {
    ctx.log_("LLM_HUNT", "检测到 Java 二进制（.jar/.class），执行反编译", "info");
    const javaDecompiler = require("./java-decompiler");
    const targetPath = sourceInput.path || sourceInput.code;
    const result = javaDecompiler.decompile(targetPath);
    ctx.log_("LLM_HUNT", `反编译完成（${result.tool}）：${result.files.length} 个 .java 文件`, "info");
    const combinedCode = result.files.map((f) => `// === ${f.file} ===\n${f.content}`).join("\n\n");
    const newSourceInput = { code: combinedCode, file: "decompiled.java", language: "java" };
    const slices = sliceSource(newSourceInput);
    ctx.log_("LLM_HUNT", `反编译代码切片：${slices.length} 个方法`, "info");
    return huntWithSlices(ctx, deps, slices, newSourceInput);
  }

  // ★ C/C++ 二进制（.bin/.elf/.exe/.so/.dll）：走 binary-hunter
  const isBinary = isBinaryFile(sourceInput);
  if (isBinary) {
    ctx.log_("LLM_HUNT", "检测到 C/C++ 二进制，启用 binary-hunter", "info");
    const binaryHunter = require("./binary-hunter");
    return binaryHunter.hunt(ctx, deps);
  }

  // ★ C/C++ 源码：调用图 + 资源流分析
  const isC = isCOrCpp(sourceInput);
  if (isC) {
    ctx.log_("LLM_HUNT", "检测到 C/C++ 代码，启用 C/C++ 专用挖掘（调用图 + 资源流）", "info");
    const cHunter = require("./c-hunter");
    return cHunter.hunt(ctx, deps);
  }

  // 1. 切片
  const slices = sliceSource(sourceInput);
  ctx.log_("LLM_HUNT", `源代码切片完成，共 ${slices.length} 个函数/方法`, "info");
  if (slices.length === 0) {
    ctx.log_("LLM_HUNT", "切片为空（路径不存在或无源码），跳过", "warn");
    return ctx;
  }

  return huntWithSlices(ctx, deps, slices, sourceInput);
}

/**
 * 核心：用已切好的 slices + 规则做 LLM 分析（Java 反编译和源码共用）
 */
async function huntWithSlices(ctx, deps, slices, sourceInput) {
  const { findingStore, ruleEngine } = deps;
  const llm = getLlm();

  // 2. 加载规则：内置 + 用户自定义（统一从 ruleEngine 取 natural_language 类型）
  const allRulesInEngine = ruleEngine ? await ruleEngine.list() : [];
  const customRules = allRulesInEngine.filter((r) => r.type === "natural_language" && r.enabled);
  // 内置规则（business-rules.js，保留向后兼容）
  const builtinRules = [...BUSINESS_VULN_TYPES, ...HIGH_RISK_TYPES].map((r) => ({
    id: r.id, name: r.name, severity: r.severity, cwe: r.cwe,
    prompt: r.prompt, sinks: r.sinks || [], focus: r.focus, _builtin: true,
  }));
  // 合并：自定义规则优先（用户配置覆盖一切），加上内置
  const mergedRules = [
    ...customRules.map((r) => ({
      id: r.ruleId, name: r.name, severity: r.severity, cwe: r.cwe,
      prompt: buildPromptFromRule(r), sinks: r.sinks || [], focus: r.description,
      _builtin: false, _source: r.origin,
    })),
    ...builtinRules,
  ];
  ctx.log_("LLM_HUNT", `规则加载：${customRules.length} 条自定义 + ${builtinRules.length} 条内置`, "info");

  // 控制分析总量
  const MAX_SLICES = config.llmHunt?.maxSlices || 20;
  const targetSlices = slices.slice(0, MAX_SLICES);

  // 3. 对每个 slice 用匹配的规则深查（统一用 mergedRules，含用户自定义）
  let findingsGenerated = 0;
  let slicesAnalyzed = 0;
  let llmCalls = 0;
  // 去重：同一条漏洞（按 file+行+标题前缀）只生成一次，避免多规则重复报告
  const seenVulnKeys = new Set();
  const dedupKey = (slice, v) => `${slice.file}:${v.line || slice.startLine}:${(v.title || "").slice(0, 30)}`;

  for (const slice of targetSlices) {
    // 所有规则（内置 + 用户自定义）都参与，按 sinks 关键词初筛省调用
    const rulesToAsk = mergedRules.filter((rule) => sliceMatchesRule(slice, rule));

    slicesAnalyzed++;
    ctx.log_("LLM_HUNT", `分析 ${slice.file}:${slice.functionName} (行 ${slice.startLine}-${slice.endLine})，匹配 ${rulesToAsk.length} 条规则`, "debug");

    // 每条规则逐个问 LLM
    for (const rule of rulesToAsk) {
      // sink 启发过滤：无相关 sink 的规则跳过（省调用）
      if (rule.sinks && rule.sinks.length > 0 && !sliceMatchesRule(slice, rule)) {
        continue;
      }

      const prompt = rule.prompt
        .replace(/\{code\}/g, slice.code)
        .replace(/\{language\}/g, slice.language);

      const result = await llm.complete(prompt, {
        difficulty: "high",
        jsonMode: true,
        systemPrompt: "你是资深安全审计专家，专注业务逻辑漏洞。只基于给定代码判定，发现真问题，不要为凑数而报告不存在的漏洞。",
      });
      llmCalls++;

      const data = result.structured || {};
      if (data.found && Array.isArray(data.vulnerabilities)) {
        for (const v of data.vulnerabilities) {
          // 去重：已报告过的漏洞跳过
          const key = dedupKey(slice, v);
          if (seenVulnKeys.has(key)) continue;
          seenVulnKeys.add(key);

          // 置信度阈值过滤（防 LLM 凑数）
          const conf = typeof data.confidence === "number" ? data.confidence : 0.7;
          if (conf < (config.detection?.confidenceThreshold || 0.5) && (typeof v.confidence !== "number" || v.confidence < 0.5)) {
            continue;
          }

          // 行号计算：LLM 返回的 v.line 是切片内相对行号(1-based)
          // 绝对行号 = slice.startLine + (v.line - 1)；primaryLine 用相对行号供代码高亮
          const relLine = v.line ? Number(v.line) : 1;
          const absLine = slice.startLine + (relLine - 1);

          const finding = await findingStore.create({
            title: `[${rule.name}] ${v.title || slice.functionName}`,
            // 类别优先用规则的 category 字段（用户填的），否则按 id 推断
            category: rule.category || (rule.id?.startsWith("BL") ? "business_logic" : inferCategory(rule, v)),
            severity: v.severity || rule.severity,
            cwe: rule.cwe,
            description: `${v.reasoning || ""}\n\n攻击场景: ${v.attackScenario || "(未提供)"}`,
            // ★ 可利用性 + 影响说明（LLM 产出，让用户理解漏洞价值）
            exploitability: v.exploitability || {
              difficulty: "unknown", prerequisites: "(未评估)", accessNeeded: "(未评估)",
            },
            impact: v.impact || {
              assets: "(未评估)", worstCase: "(未评估)", remote: false, noAuth: false,
            },
            location: {
              targetType: "source",
              file: slice.file,
              function: slice.functionName,
              startLine: absLine,
              endLine: absLine, // 单行定位（漏洞具体那一行）
            },
            snippet: {
              // ★ 漏洞点代码（含函数级上下文，用于定位）
              code: slice.code,
              language: slice.language,
              primaryLine: relLine, // 切片内相对行（供前端高亮漏洞行）
              startLine: slice.startLine, // 切片在原文的起始行
              endLine: slice.endLine,
              contextType: "function",
              file: slice.file,
              function: slice.functionName,
            },
            // ★ 完整文件上下文（供前端"查看完整上下文"用，理解漏洞在项目中的位置）
            fullContext: ctx.sourceInput?.code || slice.code,
            sources: [
              {
                toolId: "llm-hunter",
                toolType: "SAST", // 复用 SAST 类型（实际是 LLM 发现）
                rawRuleId: rule.id,
                toolConfidence: typeof v.confidence === "number" ? v.confidence : conf,
                reportedAt: new Date().toISOString(),
              },
            ],
            confidence: Math.min((typeof v.confidence === "number" ? v.confidence : conf) + 0.05, 0.95),
            status: "candidate",
            businessContext: (rule.category === "business_logic" || rule.id?.startsWith("BL")) ? {
              asset: inferAsset(rule, slice),
              attackScenario: v.attackScenario,
              stateMachineViolation: rule.id === "BL-STATE-002" ? v.title : undefined,
            } : undefined,
          });
          ctx.findings.push(finding);
          findingsGenerated++;
          ctx.log_("LLM_HUNT", `发现: [${v.severity || rule.severity}] ${v.title || slice.functionName} (${slice.file}:${v.line || slice.startLine})`, "info");
        }
      }
    }
  }

  ctx.log_(
    "LLM_HUNT",
    `LLM 自主挖掘完成：分析 ${slicesAnalyzed}/${slices.length} 片段，LLM 调用 ${llmCalls} 次，发现 ${findingsGenerated} 个漏洞（含业务逻辑）`,
    "info"
  );
  return ctx;
}

function getAllSinks() {
  return [...new Set(BUSINESS_VULN_TYPES.flatMap((r) => r.sinks || []))];
}

/**
 * 判定输入是否 C/C++（按扩展名或内容特征）
 */
function isCOrCpp(sourceInput) {
  if (sourceInput.language === "c" || sourceInput.language === "cpp") return true;
  const file = sourceInput.file || sourceInput.path || "";
  if (/\.(c|h|cpp|cc|hpp|cxx)$/i.test(file)) return true;
  const code = sourceInput.code || "";
  if (/#include\s*[<"]stdio\.h[>"]/.test(code)) return true;
  if (/#include\s*[<"]stdlib\.h[>"]/.test(code)) return true;
  if (/#include\s*[<"]string\.h[>"]/.test(code)) return true;
  return false;
}

/**
 * 判定输入是否 Java 二进制（.jar/.class）
 */
function isJavaJarOrClass(sourceInput) {
  const file = sourceInput.file || sourceInput.path || "";
  return /\.(jar|class)$/i.test(file);
}

/**
 * 判定输入是否 C/C++ 二进制（.bin/.elf/.exe/.so/.dll/.o）
 */
function isBinaryFile(sourceInput) {
  const file = sourceInput.file || sourceInput.path || "";
  return /\.(bin|elf|exe|so|dll|o|img|fw|dat)$/i.test(file);
}

function inferCategory(rule, vuln) {
  if (rule.id.includes("INJECTION")) {
    const t = (vuln.title || "").toLowerCase();
    if (t.includes("sql")) return "sqli";
    if (t.includes("command") || t.includes("cmd") || t.includes("rce")) return "cmdi";
    if (t.includes("xss")) return "xss";
    if (t.includes("path") || t.includes("traversal")) return "path_traversal";
    if (t.includes("ssrf")) return "ssrf";
    return "sqli";
  }
  if (rule.id.includes("AUTH")) return "authz";
  return "unknown";
}

function inferAsset(rule, slice) {
  const code = (slice.code || "").toLowerCase();
  if (code.includes("order")) return "order";
  if (code.includes("payment") || code.includes("pay")) return "payment";
  if (code.includes("coupon")) return "coupon";
  if (code.includes("user")) return "user";
  return rule.name;
}

/**
 * 把用户自定义规则转成 LLM prompt
 * 用户填的 description + detectionHints + 示例代码 → 完整 prompt
 */
function buildPromptFromRule(rule) {
  let prompt = `你是漏洞挖掘专家。按以下规则分析代码，找出符合规则的漏洞。

【规则名称】${rule.name}
【规则描述】${rule.description || "(无描述)"}
【检测提示】${rule.detectionHints || "(无)"}`;

  if (rule.exampleVulnerable) {
    prompt += `\n\n【漏洞代码示例】\n\`\`\`\n${rule.exampleVulnerable}\n\`\`\``;
  }
  if (rule.exampleSafe) {
    prompt += `\n\n【安全代码示例】\n\`\`\`\n${rule.exampleSafe}\n\`\`\``;
  }

  prompt += `

【待分析代码】（${rule.languages?.length ? rule.languages.join("/") : "自动识别"}）
\`\`\`
{code}
\`\`\`

只基于给定代码判定。对每个发现的漏洞，必须给出 exploitability 和 impact。
返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`;

  return prompt;
}

module.exports = { hunt };
