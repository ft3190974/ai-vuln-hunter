// llm/glm-adapter.js — GLM（智谱）适配器
//
// 通过原生 fetch 调用智谱 GLM API。支持两种协议，按 baseUrl 自动选择：
//
//   1) Anthropic 协议（GLM Coding Plan 的 glm-5.2 走这个）
//      baseUrl = https://open.bigmodel.cn/api/anthropic
//      实际端点 = {baseUrl}/v1/messages
//      Header: x-api-key + anthropic-version
//      响应: data.content[].text
//
//   2) OpenAI 协议（按量付费 API，glm-4-flash / glm-4-plus 等）
//      baseUrl = https://open.bigmodel.cn/api/paas/v4
//      实际端点 = {baseUrl}/chat/completions
//      Header: Authorization: Bearer
//      响应: data.choices[0].message.content
//
// 协议判断依据：baseUrl 是否含 "/anthropic"。

const { ILlm } = require("./interface");
const config = require("../config");

class GlmAdapter extends ILlm {
  constructor() {
    super();
    let baseUrl = config.llm.glm.baseUrl || "https://open.bigmodel.cn/api/paas/v4";
    if (baseUrl.endsWith("/")) baseUrl = baseUrl.slice(0, -1);
    this.baseUrl = baseUrl;
    this.apiKey = config.llm.glm.apiKey;
    this.models = config.llm.glm.models;
    this._lastCallTime = 0;
    // 协议判定：含 /anthropic 走 Anthropic 协议
    this.useAnthropic = /\/anthropic(\/|$)/i.test(baseUrl);
    console.log(`[GLM] 初始化: protocol=${this.useAnthropic ? "anthropic" : "openai"}, baseUrl=${this.baseUrl}, model=${this.models.high}`);
  }

  /**
   * 限流：每次调用间隔至少 1.5 秒（避免 429）
   */
  async _rateLimit() {
    const now = Date.now();
    const elapsed = now - this._lastCallTime;
    const minInterval = 1500; // 1.5 秒/次 ≈ 40 RPM
    if (elapsed < minInterval) {
      await new Promise((r) => setTimeout(r, minInterval - elapsed));
    }
    this._lastCallTime = Date.now();
  }

  async _retryWithBackoff(fn, maxRetries = 2) {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (e) {
        if (e.message?.includes("429") && attempt < maxRetries) {
          const waitMs = 5000 * (attempt + 1); // 5s, 10s 退避
          console.warn(`[GLM] 429 限流，${waitMs / 1000}s 后重试 (${attempt + 1}/${maxRetries})`);
          await new Promise((r) => setTimeout(r, waitMs));
          continue;
        }
        throw e;
      }
    }
  }

  implName() {
    return `glm(${this.models.high})`;
  }

  /**
   * 根据任务难度路由到对应模型（成本优化）
   */
  pickModel(difficulty = "medium") {
    return this.models[difficulty] || this.models.medium;
  }

  async complete(prompt, opts = {}) {
    return this._retryWithBackoff(async () => {
      await this._rateLimit();
      if (this.useAnthropic) {
        return this._completeAnthropic(prompt, opts);
      }
      return this._completeOpenAI(prompt, opts);
    });
  }

  // ── OpenAI 协议（/chat/completions）──
  async _completeOpenAI(prompt, opts = {}) {
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
      body.response_format = { type: "json_object" };
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), config.llm.glm.timeoutMs);

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
        console.error(`[GLM/OpenAI] API 错误 ${resp.status}: ${errText.slice(0, 300)}`);
        throw new Error(`GLM API ${resp.status}: ${errText.slice(0, 200)}`);
      }

      const data = await resp.json();
      const text = data.choices?.[0]?.message?.content || "";
      if (!text) console.error(`[GLM/OpenAI] 空响应:`, JSON.stringify(data).slice(0, 300));

      const structured = this._tryParseJson(text, opts);
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

  // ── Anthropic 协议（/v1/messages）── GLM Coding Plan 走这个
  async _completeAnthropic(prompt, opts = {}) {
    const model = this.pickModel(opts.difficulty);

    // Anthropic 协议要求 system 单独传，messages 里不包含 system
    const messages = [{ role: "user", content: prompt }];
    const body = {
      model,
      max_tokens: config.llm.glm.maxTokens,
      temperature: config.llm.glm.temperature,
      messages,
    };
    if (opts.systemPrompt) {
      body.system = opts.systemPrompt;
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), config.llm.glm.timeoutMs);

    try {
      const resp = await fetch(`${this.baseUrl}/v1/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // Anthropic 协议用 x-api-key，不是 Bearer
          "x-api-key": this.apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });

      if (!resp.ok) {
        const errText = await resp.text();
        console.error(`[GLM/Anthropic] API 错误 ${resp.status}: ${errText.slice(0, 300)}`);
        throw new Error(`GLM API ${resp.status}: ${errText.slice(0, 200)}`);
      }

      const data = await resp.json();
      // Anthropic 响应结构: data.content = [{type:"text", text:"..."}]
      const text = Array.isArray(data.content)
        ? data.content.filter((b) => b.type === "text").map((b) => b.text).join("")
        : "";

      if (!text) console.error(`[GLM/Anthropic] 空响应:`, JSON.stringify(data).slice(0, 300));

      const structured = this._tryParseJson(text, opts);
      return {
        text,
        structured,
        model,
        tokensUsed: data.usage?.input_tokens + data.usage?.output_tokens || 0,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * 尝试从模型返回文本中解析 JSON（支持 markdown 围栏）
   */
  _tryParseJson(text, opts) {
    if (opts.jsonMode === false || !text) return null;
    try {
      return JSON.parse(text);
    } catch {
      const match = text.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (match) {
        try {
          return JSON.parse(match[1]);
        } catch {
          return null;
        }
      }
      return null;
    }
  }
}

module.exports = { GlmAdapter };
