// agents/project-understand.js — 项目理解 Agent
//
// 在 LLM_HUNT 之前执行，让 LLM 先通读项目关键文件，建立全局认知。
// 产出 projectContext，后续所有 Agent 都能看到。
//
// 解决问题：LLM 不再"瞎子摸象"——它知道这是什么系统、什么业务、
// 关键流程是什么、哪些区域高风险。
//
// 覆盖状态：PROJECT_UNDERSTAND（在 INIT 之后、LLM_HUNT 之前）

const { getLlm } = require("../llm");
const fs = require("fs");
const path = require("path");

async function understand(ctx, deps) {
  const llm = getLlm();
  ctx.log_("PROJECT_UNDERSTAND", "开始理解项目...", "info");

  const sourceInput = ctx.sourceInput;
  if (!sourceInput) {
    ctx.projectContext = null;
    return ctx;
  }

  // ── 1. 提取项目关键文件（入口/控制器/配置/路由）──
  const keyFiles = extractKeyFiles(sourceInput);
  ctx.log_("PROJECT_UNDERSTAND", `提取到 ${keyFiles.length} 个关键文件`, "info");

  if (keyFiles.length === 0) {
    // 无关键文件（可能粘贴了单段代码），做简化理解
    const code = sourceInput.code || "";
    if (code) {
      ctx.projectContext = await quickUnderstand(code, llm, sourceInput.language);
      ctx.log_("PROJECT_UNDERSTAND", `快速理解完成: ${ctx.projectContext?.projectType || "未知"}（单文件模式）`, "info");
    } else {
      ctx.projectContext = null;
    }
    return ctx;
  }

  // ── 2. 合并关键文件内容（控制在 token 上限内）──
  const maxChars = 8000; // 约 2000 token
  let combined = "";
  const includedFiles = [];
  for (const f of keyFiles) {
    if (combined.length + f.content.length > maxChars) break;
    combined += `\n// === ${f.file} ===\n${f.content.slice(0, 1500)}\n`;
    includedFiles.push(f.file);
  }

  // ── 3. 调 LLM 理解项目 ──
  const prompt = `你是资深架构师 + 安全审计专家。请分析以下项目代码，理解项目的整体架构和业务逻辑。

【项目代码片段】
${combined}

请返回 JSON：
{
  "projectType": "项目类型（如：电商系统/银行核心/OA系统/API网关/CMS/IoT固件 等）",
  "framework": "技术栈（如：Spring Boot + MyBatis / Django / Express）",
  "modules": ["模块1", "模块2"],
  "entryPoints": ["/api/xxx"],
  "businessFlows": {
    "核心业务1": "流程描述（如：创建订单 → 待支付 → 支付回调 → 已发货）",
    "核心业务2": "流程描述"
  },
  "stateMachine": {
    "实体名": ["状态1", "状态2", "状态3"],
    "legal_transitions": ["状态1→状态2", "状态2→状态3"],
    "suspected_illegal_transitions": ["可能被绕过的非法跳转"]
  },
  "permissionModel": {
    "角色1": ["可访问的接口"],
    "角色2": ["可访问的接口"]
  },
  "keyDataFlows": [
    "关键数据流描述（如：用户输入 → Controller → Service → DB）"
  ],
  "riskAreas": [
    "高风险区域1（如：金额处理/状态迁移/权限校验/支付回调）",
    "高风险区域2"
  ],
  "businessRules": [
    "业务规则1（如：订单金额必须>0）",
    "业务规则2（如：优惠券不可叠加）"
  ]
}

只基于给定代码分析，不要臆测。`;

  const result = await llm.complete(prompt, {
    difficulty: "high",
    jsonMode: true,
    systemPrompt: "你是资深架构师 + 安全审计专家。你的任务是从代码中理解项目的业务逻辑和架构，为后续漏洞挖掘建立全局认知。",
  });

  ctx.projectContext = result.structured || {};
  ctx.projectContext._understoodFiles = includedFiles;
  ctx.projectContext._understoodAt = new Date().toISOString();

  ctx.log_(
    "PROJECT_UNDERSTAND",
    `项目理解完成: ${ctx.projectContext.projectType || "未知"} | ${ctx.projectContext.modules?.length || 0} 模块 | ${ctx.projectContext.riskAreas?.length || 0} 高风险区域 | ${ctx.projectContext.businessRules?.length || 0} 业务规则`,
    "info"
  );

  // 把 projectContext 存到 ctx，后续 Agent 可通过 deps 或 ctx 访问
  return ctx;
}

/**
 * 提取项目关键文件（入口/控制器/配置/路由/模型定义）
 */
function extractKeyFiles(sourceInput) {
  const keyFiles = [];

  // 从目录/路径提取
  let basePath = null;
  if (sourceInput.path) {
    try {
      const stat = fs.statSync(sourceInput.path);
      if (stat.isDirectory()) basePath = sourceInput.path;
      else if (stat.isFile()) {
        // 单文件：直接用
        keyFiles.push({
          file: path.basename(sourceInput.path),
          content: fs.readFileSync(sourceInput.path, "utf-8").slice(0, 3000),
        });
        return keyFiles;
      }
    } catch {}
  }

  // 从代码字符串提取
  if (sourceInput.code && !basePath) {
    keyFiles.push({ file: sourceInput.file || "input.code", content: sourceInput.code.slice(0, 4000) });
    return keyFiles;
  }

  if (!basePath) return keyFiles;

  // 目录：找关键文件
  const keyPatterns = [
    // 控制器/路由
    /Controller/i, /controller/i, /router/i, /route/i, /handler/i, /servlet/i,
    /controller\.(java|py|js|ts|go|php|rb|kt)$/,
    /routes?\.(js|ts|py|go)$/,
    // 入口
    /Main\.(java|py|js|ts)$/, /App\.(java|py|js|ts)$/, /index\.(js|ts)$/,
    /main\.(py|go|rs)$/, /Application\.(java|kt)$/,
    // 配置
    /application\.(yml|yaml|properties)$/, /config\.(js|ts|py|json)$/,
    /\.env$/, /package\.json$/, /pom\.xml$/, /Cargo\.toml$/,
    // 安全相关
    /Security/i, /Auth/i, /Filter/i, /Interceptor/i, /Middleware/i,
    /guard/i, /permission/i,
  ];

  walkDir(basePath, keyPatterns, keyFiles, 0, 15);
  return keyFiles;
}

function walkDir(dir, patterns, results, depth, maxFiles) {
  if (depth > 4 || results.length >= maxFiles) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  const skip = ["node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__", ".idea", ".vscode"];
  for (const entry of entries) {
    if (results.length >= maxFiles) return;
    if (skip.includes(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(full, patterns, results, depth + 1, maxFiles);
    } else {
      // 匹配关键文件模式
      const isKey = patterns.some((p) => p.test(entry.name)) ||
        /\.(java|py|js|ts|go|php|rb)$/.test(entry.name) && depth <= 2;
      if (isKey) {
        try {
          const content = fs.readFileSync(full, "utf-8");
          if (content.length > 50) {
            results.push({ file: path.relative(dir, full), content: content.slice(0, 1500) });
          }
        } catch {}
      }
    }
  }
}

/**
 * 快速理解（单文件/代码片段模式）
 */
async function quickUnderstand(code, llm, language) {
  const prompt = `分析以下代码，快速理解这是什么类型的程序、有什么业务逻辑和潜在风险。

代码（${language || "auto"}）：
\`\`\`
${code.slice(0, 3000)}
\`\`\`

返回 JSON:
{
  "projectType": "程序类型",
  "framework": "技术栈",
  "modules": ["模块"],
  "businessFlows": {"核心流程": "描述"},
  "stateMachine": {"实体": ["状态"], "legal_transitions": [], "suspected_illegal_transitions": []},
  "riskAreas": ["高风险区域"],
  "businessRules": ["业务规则"]
}`;

  const result = await llm.complete(prompt, {
    difficulty: "medium", jsonMode: true,
    systemPrompt: "你是资深安全审计专家，快速理解代码的业务逻辑和风险。",
  });
  return result.structured || {};
}

module.exports = { understand };
