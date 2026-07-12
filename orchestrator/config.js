// config.js — 编排层配置中心
//
// 集中管理：LLM 路由策略、环境变量、各类阈值。
// 所有可调参数都从这里读取，便于调参与 A/B 测试。
//
// 环境变量说明：
//   LLM_MODE       = mock | glm        LLM 实现选择，默认 mock
//   GLM_BASE_URL   GLM API 地址，默认智谱官方
//   GLM_API_KEY    GLM API Key（mode=glm 时必填，无则自动降级 mock）
//   GLM_MODEL      GLM 模型名，默认 glm-4-plus
//   SANDBOX_MODE   = mock | docker | auto  POC 验证沙箱，默认 auto（docker 不可用降级 mock）
//   SANDBOX_IMAGE  Docker 沙箱镜像，默认 node:20-alpine
//   SANDBOX_NET    Docker 网络模式，默认 none（禁止外联）
//   LOG_LEVEL      = debug | info | warn | error  日志级别，默认 info

const isGlmConfigured = () => {
  return !!(process.env.GLM_API_KEY && process.env.GLM_API_KEY.length > 0);
};

const llmMode = process.env.LLM_MODE || "mock";

const config = {
  // ── LLM 配置 ──
  llm: {
    // 当前模式。若用户指定 glm 但未配 key，自动降级到 mock（不报错，保证本地可跑）
    mode:
      llmMode === "glm" && !isGlmConfigured()
        ? "mock-fallback"
        : llmMode,
    glm: {
      baseUrl:
        process.env.GLM_BASE_URL || "https://open.bigmodel.cn/api/paas/v4",
      apiKey: process.env.GLM_API_KEY || "",
      // 分层路由：不同难度任务用不同模型（成本优化）
      // 真实接入时按 GLM 产品矩阵调整
      models: {
        low: "glm-4-flash", // 低难度：归一化、分类、字段映射
        medium: "glm-4-plus", // 中难度：漏洞判定、误报过滤
        high: "glm-4-plus", // 高难度：0-day 推理、业务逻辑、修复（生产可换 glm-4.6 或更强）
      },
      // 请求参数
      temperature: 0.2, // 漏洞判定要确定性，低温
      maxTokens: 2048,
      timeoutMs: 30000,
    },
  },

  // ── 验证配置 ──
  verify: {
    // POC 验证沙箱模式
    //   mock   纯模拟（零依赖，按 POC 特征返回结果）
    //   docker 真实 Docker 隔离执行（需本机 Docker）
    //   auto   优先 docker，不可用降级 mock（默认）
    mode: process.env.SANDBOX_MODE || "auto",
    reachabilityThreshold: 0.6, // 可达置信度阈值，高于此值才视为可达
  },

  // ── 检测配置 ──
  detection: {
    confidenceThreshold: 0.5, // Finding 综合置信度阈值，低于此降级为"疑似"
    fpFilterEnabled: true, // 是否启用误报库前置过滤
  },

  // ── LLM 自主挖掘配置 ──
  llmHunt: {
    maxSlices: Number(process.env.LLM_HUNT_MAX_SLICES) || 50, // 单次最多分析的函数切片数（控制成本）
    enabled: process.env.LLM_HUNT_ENABLED !== "0", // 默认启用
  },

  // ── 修复配置 ──
  fix: {
    equivalenceCheck: true, // 是否做等价性回归（mock 版只打日志）
  },

  // ── 学习配置 ──
  learn: {
    ruleGenerationEnabled: true, // 是否启用规则自动生成
    minConfidenceForRuleGen: 0.8, // 真漏洞置信度高于此值才生成候选规则
  },

  // ── 日志 ──
  logLevel: process.env.LOG_LEVEL || "info",
};

module.exports = config;
