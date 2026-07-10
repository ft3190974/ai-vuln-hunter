// llm/interface.js — LLM 抽象接口
//
// 定义所有 LLM 实现必须遵循的契约。Mock 和 GLM 适配器都实现此接口。
// 上层 Agent 只依赖此接口，不感知具体实现 → 模型可插拔。
//
// 用法：
//   const { getLlm } = require("./llm/interface");
//   const llm = getLlm();          // 按 config 返回 mock 或 glm 实例
//   const result = await llm.complete(prompt, { difficulty: "high" });

/**
 * LLM 完成请求的选项
 * @typedef {Object} CompleteOptions
 * @property {"low"|"medium"|"high"} difficulty - 任务难度，决定路由到哪个模型（成本优化）
 * @property {boolean} [jsonMode] - 是否要求 JSON 结构化输出
 * @property {string} [systemPrompt] - 系统提示词
 */

/**
 * LLM 完成请求的结果
 * @typedef {Object} CompleteResult
 * @property {string} text - 原始文本输出
 * @property {Object|null} structured - 解析后的结构化对象（jsonMode 时）
 * @property {string} model - 实际使用的模型名
 * @property {number} tokensUsed - token 用量（mock 时为 0）
 */

class ILlm {
  /**
   * @param {string} prompt
   * @param {CompleteOptions} opts
   * @returns {Promise<CompleteResult>}
   */
  async complete(_prompt, _opts = {}) {
    throw new Error("ILlm.complete 必须由子类实现");
  }

  /** 返回实现标识，便于日志追踪 */
  implName() {
    return "abstract";
  }
}

module.exports = { ILlm };
