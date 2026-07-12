// llm/index.js — LLM 工厂
//
// 按 config.llm.mode 返回对应实现。上层只调 getLlm()，不感知具体实现。
//
// 优先级：
//   1. 全局动态配置（settings API 设的，通过 setDynamicLlmConfig）
//   2. config.llm.mode（环境变量 LLM_MODE + GLM_API_KEY）
//   3. 默认 mock

const config = require("../config");
const { MockLlm } = require("./mock-llm");
const { GlmAdapter } = require("./glm-adapter");

let cached = null;
let dynamicConfig = null; // settings API 动态设置的配置

/**
 * 设置动态 LLM 配置（由 settings 路由调用）
 * 设置后 getLlm() 优先使用此配置
 */
function setDynamicLlmConfig(cfg) {
  dynamicConfig = cfg;
  cached = null; // 清缓存，下次 getLlm 重新创建
}

function getLlm() {
  if (cached) return cached;

  // 优先用动态配置（settings API）
  if (dynamicConfig && dynamicConfig.provider && dynamicConfig.provider !== "mock") {
    // 注入到 config 的 glm 配置
    config.llm.mode = "glm";
    if (dynamicConfig.baseUrl) config.llm.glm.baseUrl = dynamicConfig.baseUrl;
    if (dynamicConfig.apiKey) config.llm.glm.apiKey = dynamicConfig.apiKey;
    if (dynamicConfig.model) config.llm.glm.models = {
      low: dynamicConfig.model, medium: dynamicConfig.model, high: dynamicConfig.model,
    };
    cached = new GlmAdapter();
    return cached;
  }

  const mode = config.llm.mode;
  if (mode === "glm") {
    cached = new GlmAdapter();
  } else {
    cached = new MockLlm();
  }
  return cached;
}

/** 重置缓存（测试用：切换 mode 后需重新创建实例） */
function resetLlm() {
  cached = null;
}

module.exports = { getLlm, resetLlm, setDynamicLlmConfig };
