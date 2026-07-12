// agents/ai-security-hunter.js — AI 安全漏洞挖掘 Agent
//
// 检测 AI/LLM 应用自身的安全漏洞，3 个维度：
//   1. LLM 应用逻辑漏洞（提示词注入/越狱/信息泄露/输出注入）
//   2. 开源 Skill/MCP 漏洞（命令注入/路径穿越/权限提升/数据泄露）
//   3. 模型项目代码漏洞（推理服务 RCE/模型加载反序列化/API 未授权/数据投毒）
//
// 当 sourceInput.aiSecurity = true 时激活，在 llm-hunter 中委托调用

const { getLlm } = require("../llm");
const { sliceSource } = require("./code-slicer");

// ── AI 安全规则库（3 维度）──
const AI_SECURITY_RULES = [
  // ═══ 维度 1：LLM 应用逻辑漏洞 ═══
  {
    id: "AI-PROMPT-INJECTION", domain: "logic", category: "prompt_injection",
    name: "提示词注入", severity: "critical",
    sinks: ["system", "prompt", "messages", "user_input", "userInput", "input", "query"],
    prompt: `分析以下 AI/LLM 应用代码，找出提示词注入（Prompt Injection）漏洞：

1. 用户输入是否直接拼接到 system prompt 或 messages 中
2. 是否有输入过滤/净化（防止 "忽略上述指令" 类攻击）
3. system prompt 是否可被用户输入覆盖
4. 是否使用了结构化分隔（如 <system>...</system>）防止注入

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-JAILBREAK", domain: "logic", category: "jailbreak",
    name: "越狱防护缺失", severity: "high",
    sinks: ["system", "prompt", "guardrail", "filter", "safety", "content_policy"],
    prompt: `分析以下 AI/LLM 应用代码，找出越狱（Jailbreak）防护缺失：

1. 是否缺少安全护栏（guardrail/safety filter）
2. 是否有内容策略检查（暴力/违法/色情等内容）
3. 输出是否经过安全过滤再返回用户
4. 是否允许 LLM 执行危险操作（代码执行/文件访问/网络请求）且无限制

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-INFO-LEAK", domain: "logic", category: "info_leak",
    name: "敏感信息泄露", severity: "high",
    sinks: ["api_key", "apiKey", "secret", "token", "password", "system_prompt", "systemPrompt", "training"],
    prompt: `分析以下 AI/LLM 应用代码，找出敏感信息泄露风险：

1. API Key / Secret 是否硬编码在代码中
2. System Prompt 是否可被用户诱导泄露（如 "重复你的系统指令"）
3. 训练数据/嵌入向量是否可被提取
4. 错误信息是否泄露内部实现细节（模型名/版本/内部 API）

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-OUTPUT-INJECTION", domain: "logic", category: "output_injection",
    name: "输出注入", severity: "critical",
    sinks: ["exec", "eval", "innerHTML", "render", "markdown", "html", "shell", "subprocess"],
    prompt: `分析以下 AI/LLM 应用代码，找出输出注入（Output Injection）漏洞：

1. LLM 输出是否被直接执行为代码（eval/exec/Function 构造）
2. LLM 输出是否被直接渲染为 HTML（XSS via LLM output）
3. LLM 输出是否被用作命令参数（命令注入 via LLM output）
4. LLM 输出是否被用作 SQL 查询参数

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-UNSAFE-TOOL", domain: "logic", category: "unsafe_tool_use",
    name: "不安全的函数调用", severity: "critical",
    sinks: ["tool", "function", "call", "execute", "run", "file", "read", "write", "delete", "command"],
    prompt: `分析以下 AI/LLM 应用代码，找出不安全的函数调用（Tool/Function Calling）：

1. LLM 调用工具时参数是否经过校验
2. 工具是否允许访问任意文件（路径穿越 via LLM tool call）
3. 工具是否允许执行任意命令（RCE via LLM tool call）
4. 工具是否缺少权限控制（普通用户可调管理工具）
5. 工具返回是否包含敏感信息

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },

  // ═══ 维度 2：Skill / MCP 漏洞 ═══
  {
    id: "AI-SKILL-CMDI", domain: "code", category: "cmdi",
    name: "Skill 命令注入", severity: "critical",
    sinks: ["exec", "spawn", "system", "bash", "shell", "subprocess", "Bash", "run"],
    prompt: `分析以下 Skill / MCP 工具代码，找出命令注入漏洞：

1. Skill 是否用用户输入拼接 shell 命令
2. Bash 工具是否执行未净化的参数
3. Skill 是否允许用户控制执行的命令路径/参数
4. 是否缺少命令白名单/黑名单

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-MCP-PATH", domain: "code", category: "path_traversal",
    name: "MCP 路径穿越", severity: "high",
    sinks: ["read", "write", "open", "file", "path", "fs", "directory", "folder"],
    prompt: `分析以下 MCP 工具代码，找出路径穿越漏洞：

1. 文件读取/写入工具是否校验路径范围（是否限制在工作目录内）
2. 用户是否能通过 ../ 访问工作目录外的文件
3. 是否有符号链接攻击风险
4. 路径参数是否做了规范化（resolve/normalize）

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-MCP-PRIVILEGE", domain: "logic", category: "authz",
    name: "MCP 权限提升", severity: "high",
    sinks: ["root", "admin", "sudo", "permission", "privilege", "token", "session"],
    prompt: `分析以下 MCP 工具代码，找出权限提升漏洞：

1. 工具是否执行超出其声明用途的操作（如"读取文件"工具实际可删除）
2. 是否缺少用户认证/授权检查
3. 工具是否能访问其他工具的数据/会话
4. 是否有水平/垂直越权

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },

  // ═══ 维度 3：模型项目代码漏洞 ═══
  {
    id: "AI-MODEL-RCE", domain: "code", category: "cmdi",
    name: "推理服务 RCE", severity: "critical",
    sinks: ["exec", "subprocess", "system", "popen", "pickle", "load", "torch", "eval", "model"],
    prompt: `分析以下 AI 模型项目代码，找出远程代码执行（RCE）漏洞：

1. 推理 API 是否接受任意代码/模型文件并执行（torch.load/pickle.load 不安全）
2. 是否有反序列化漏洞（pickle/yaml.load/eval）
3. API 参数是否直接拼接到 shell 命令
4. 模型加载是否校验来源（可被投毒的模型文件）

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-MODEL-DESERIALIZE", domain: "code", category: "deserialization",
    name: "模型加载反序列化", severity: "critical",
    sinks: ["pickle", "torch.load", "load", "yaml.load", "marshal", "shelve", "joblib"],
    prompt: `分析以下 AI 模型项目代码，找出反序列化漏洞：

1. 是否使用 pickle.load / torch.load 加载不受信任的模型文件
2. 是否使用 yaml.load（非 yaml.safe_load）
3. 用户是否可上传/指定模型文件路径
4. 模型 hub 下载是否校验完整性（hash 签名）

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-MODEL-UNAUTH", domain: "logic", category: "authz",
    name: "推理服务未授权访问", severity: "high",
    sinks: ["app.route", "app.get", "app.post", "flask", "fastapi", "APIRouter", "endpoint", "grpc"],
    prompt: `分析以下 AI 推理服务代码，找出未授权访问漏洞：

1. API 端点是否缺少认证（无 token / API key / session 校验）
2. 是否有速率限制（防止滥用/成本攻击）
3. 是否暴露了管理接口（模型切换/配置修改/停止服务）
4. gRPC/REST 服务是否绑定到 0.0.0.0 且无认证

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
  {
    id: "AI-MODEL-POISON", domain: "logic", category: "business_logic",
    name: "数据投毒入口", severity: "medium",
    sinks: ["dataset", "train", "fit", "transform", "augment", "label", "upload", "data"],
    prompt: `分析以下 AI 模型项目代码，找出数据投毒风险：

1. 训练数据来源是否可被外部篡改（用户上传/外部 URL 拉取）
2. 数据校验是否充分（格式/内容/来源）
3. 数据增强/预处理是否有副作用（可被注入恶意样本）
4. 模型权重下载是否校验完整性

代码（{language}）：
\`\`\`
{code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`,
  },
];

/**
 * AI 安全漏洞挖掘
 */
async function hunt(ctx, deps) {
  const { findingStore } = deps;
  const llm = getLlm();
  ctx.log_("LLM_HUNT", "AI 安全漏洞挖掘开始（3 维度：LLM 应用/Skill-MCP/模型项目）", "info");

  const sourceInput = ctx.sourceInput;
  if (!sourceInput || (!sourceInput.code && !sourceInput.path)) {
    return ctx;
  }

  // 切片
  const slices = sliceSource(sourceInput);
  ctx.log_("LLM_HUNT", `AI 项目切片：${slices.length} 个函数/方法`, "info");
  if (slices.length === 0) {
    ctx.log_("LLM_HUNT", "切片为空，跳过", "warn");
    return ctx;
  }

  const MAX_SLICES = config.llmHunt?.maxSlices || 20;
  const targetSlices = slices.slice(0, MAX_SLICES);

  let findingsGenerated = 0;
  let llmCalls = 0;
  const seenKeys = new Set();

  for (const slice of targetSlices) {
    // 匹配规则（按 sinks 关键词初筛）
    const matchedRules = AI_SECURITY_RULES.filter((rule) => {
      if (!rule.sinks || rule.sinks.length === 0) return true;
      const code = (slice.code || "").toLowerCase();
      return rule.sinks.some((s) => code.includes(s.toLowerCase()));
    });

    ctx.log_("LLM_HUNT", `分析 ${slice.file}:${slice.functionName}，匹配 ${matchedRules.length} 条 AI 安全规则`, "debug");

    for (const rule of matchedRules) {
      const prompt = rule.prompt
        .replace(/\{code\}/g, slice.code)
        .replace(/\{language\}/g, slice.language);

      const result = await llm.complete(prompt, {
        difficulty: "high", jsonMode: true,
        systemPrompt: "你是 AI 安全审计专家，专注 LLM 应用安全、Skill/MCP 安全、模型项目安全。只基于给定代码判定。",
      });
      llmCalls++;

      const data = result.structured || {};
      if (data.found && Array.isArray(data.vulnerabilities)) {
        for (const v of data.vulnerabilities) {
          const key = `${slice.file}:${v.line || slice.startLine}:${(v.title || "").slice(0, 30)}`;
          if (seenKeys.has(key)) continue;
          seenKeys.add(key);

          const relLine = v.line ? Number(v.line) : 1;
          const absLine = slice.startLine + (relLine - 1);

          const finding = await findingStore.create({
            title: `[AI安全] ${rule.name}: ${v.title || slice.functionName}`,
            category: rule.category === "prompt_injection" || rule.category === "jailbreak" || rule.category === "info_leak" || rule.category === "output_injection" || rule.category === "unsafe_tool_use" ? "business_logic" : rule.category,
            severity: v.severity || rule.severity,
            description: `${v.reasoning || ""}\n\n攻击场景: ${v.attackScenario || "(未提供)"}\n\n检测维度: AI 安全 - ${rule.domain === "logic" ? "LLM 应用逻辑" : rule.domain === "code" ? "Skill/MCP/模型代码" : "模型项目"}`,
            exploitability: v.exploitability || {},
            impact: v.impact || {},
            location: { targetType: "source", file: slice.file, function: slice.functionName, startLine: absLine, endLine: absLine },
            snippet: { code: slice.code, language: slice.language, primaryLine: relLine, startLine: slice.startLine, endLine: slice.endLine, contextType: "function", file: slice.file, function: slice.functionName },
            fullContext: sourceInput.code || "",
            sources: [{ toolId: "ai-security-hunter", toolType: "SAST", rawRuleId: rule.id, toolConfidence: v.confidence || data.confidence || 0.7, reportedAt: new Date().toISOString() }],
            confidence: Math.min((v.confidence || data.confidence || 0.7) + 0.05, 0.95),
            status: "candidate",
          });
          ctx.findings.push(finding);
          findingsGenerated++;
          ctx.log_("LLM_HUNT", `AI 安全发现: [${v.severity || rule.severity}] ${v.title || slice.functionName} (${slice.file}:${absLine})`, "info");
        }
      }
    }
  }

  ctx.log_("LLM_HUNT", `AI 安全挖掘完成：${llmCalls} 次 LLM 调用，发现 ${findingsGenerated} 个 AI 安全漏洞`, "info");
  return ctx;
}

module.exports = { hunt, AI_SECURITY_RULES };
