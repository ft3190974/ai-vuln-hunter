// llm/index.js — LLM 工厂
//
// 按 config.llm.mode 返回对应实现。上层只调 getLlm()，不感知具体实现。
//
// mode 取值：
//   mock          使用 MockLlm（零依赖）
//   glm           使用 GlmAdapter（需 GLM_API_KEY）
//   mock-fallback 用户想用 glm 但没配 key，自动降级到 mock

const config = require("../config");
const { MockLlm } = require("./mock-llm");
const { GlmAdapter } = require("./glm-adapter");

let cached = null;

function getLlm() {
  if (cached) return cached;
  const mode = config.llm.mode;
  if (mode === "glm") {
    cached = new GlmAdapter();
  } else {
    // mock 或 mock-fallback
    cached = new MockLlm();
  }
  return cached;
}

/** 重置缓存（测试用：切换 mode 后需重新创建实例） */
function resetLlm() {
  cached = null;
}

module.exports = { getLlm, resetLlm };
