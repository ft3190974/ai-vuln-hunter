// llm/glm-adapter.js — GLM（智谱）适配器
//
// 通过原生 fetch 调用智谱 GLM API。所有连接参数从环境变量读取，
// 默认指向智谱官方，可改为私有化部署地址（数据不出网场景）。
//
// 环境变量（见 config.js）：
//   GLM_BASE_URL  GLM_API_KEY  GLM_MODEL
//
// 智谱 GLM API 参考：POST {base_url}/chat/completions
//   { model, messages:[{role,content}], temperature, max_tokens }

const { ILlm } = require("./interface");
const config = require("../config");

class GlmAdapter extends ILlm {
  constructor() {
    super();
    this.baseUrl = config.llm.glm.baseUrl;
    this.apiKey = config.llm.glm.apiKey;
    this.models = config.llm.glm.models;
  }

  implName() {
    return `glm(${this.models.high})`;
  }

  /**
   * 根据任务难度路由到对应模型（成本优化）
   * low=便宜模型；high=强模型
   */
  pickModel(difficulty = "medium") {
    return this.models[difficulty] || this.models.medium;
  }

  async complete(prompt, opts = {}) {
    const model = this.pickModel(opts.difficulty);
    const messages = [];
    if (opts.systemPrompt) {
      messages.push({ role: "system", content: opts.systemPrompt });
    }
    messages.push({ role: "user", content: prompt });

    const body = {
      model,
      messages,
      temperature: config.llm.glm.temperature,
      max_tokens: config.llm.glm.maxTokens,
    };
    if (opts.jsonMode) {
      // 智谱 GLM 支持强制 JSON 输出
      body.response_format = { type: "json_object" };
    }

    const ctrl = new AbortController();
    const timer = setTimeout(
      () => ctrl.abort(),
      config.llm.glm.timeoutMs
    );

    try {
      const resp = await fetch(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });

      if (!resp.ok) {
        const errText = await resp.text();
        throw new Error(`GLM API ${resp.status}: ${errText.slice(0, 200)}`);
      }

      const data = await resp.json();
      const text =
        data.choices?.[0]?.message?.content || "";

      let structured = null;
      if (opts.jsonMode !== false && text) {
        try {
          structured = JSON.parse(text);
        } catch {
          // 模型偶尔返回非纯 JSON（带 markdown 围栏），尝试提取
          const match = text.match(/```(?:json)?\s*([\s\S]*?)```/);
          if (match) {
            try {
              structured = JSON.parse(match[1]);
            } catch {
              /* 忽略，structured 保持 null */
            }
          }
        }
      }

      return {
        text,
        structured,
        model,
        tokensUsed: data.usage?.total_tokens || 0,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

module.exports = { GlmAdapter };
