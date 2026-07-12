// web/server/routes/settings.js — 系统设置（LLM 配置 + 工具集成配置）
//
// POST /api/settings/llm        添加 LLM 配置
// GET  /api/settings/llm        列出所有 LLM 配置
// PUT  /api/settings/llm/:id    更新
// DELETE /api/settings/llm/:id  删除
// POST /api/settings/llm/:id/test  测试 LLM 连通性
//
// POST /api/settings/tools       添加工具集成配置（MCP SAST/SCA/BAT/MST）
// GET  /api/settings/tools       列出所有工具配置
// PUT  /api/settings/tools/:id   更新
// DELETE /api/settings/tools/:id 删除
// POST /api/settings/tools/:id/test  测试工具连通性

const express = require("express");

function settingsRoutes() {
  const router = express.Router();

  // ── LLM 配置（内存存储，生产用 DB）──
  const llmConfigs = []; // {id, name, provider, baseUrl, apiKey, model, difficulty, enabled, createdAt}
  let llmIdCounter = 0;

  // 默认配置（从环境变量读）
  llmConfigs.push({
    id: "llm-default",
    name: "默认 LLM",
    provider: process.env.LLM_MODE === "glm" ? "glm" : "mock",
    baseUrl: process.env.GLM_BASE_URL || "https://open.bigmodel.cn/api/paas/v4",
    apiKey: process.env.GLM_API_KEY ? "***（环境变量）" : "",
    model: "glm-4-plus",
    temperature: 0.2,
    maxTokens: 2048,
    difficulty: "auto", // low/medium/high/auto
    enabled: true,
    isDefault: true,
    createdAt: new Date().toISOString(),
  });

  router.get("/settings/llm", (_req, res) => res.json(llmConfigs));

  router.post("/settings/llm", (req, res) => {
    const b = req.body;
    if (!b.name || !b.provider) return res.status(400).json({ error: "name 和 provider 必填" });
    const cfg = {
      id: `llm-${++llmIdCounter}`, name: b.name, provider: b.provider,
      baseUrl: b.baseUrl || "", apiKey: b.apiKey || "",
      model: b.model || "glm-4-plus", temperature: b.temperature ?? 0.2,
      maxTokens: b.maxTokens || 2048, difficulty: b.difficulty || "auto",
      enabled: b.enabled !== false, createdAt: new Date().toISOString(),
    };
    llmConfigs.push(cfg);
    res.status(201).json(cfg);
  });

  router.put("/settings/llm/:id", (req, res) => {
    const cfg = llmConfigs.find((c) => c.id === req.params.id);
    if (!cfg) return res.status(404).json({ error: "配置不存在" });
    Object.assign(cfg, req.body, { updatedAt: new Date().toISOString() });
    res.json(cfg);
  });

  router.delete("/settings/llm/:id", (req, res) => {
    const idx = llmConfigs.findIndex((c) => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "配置不存在" });
    if (llmConfigs[idx].isDefault) return res.status(403).json({ error: "默认配置不可删除" });
    const deleted = llmConfigs.splice(idx, 1)[0];
    res.json({ deleted: deleted.id });
  });

  router.post("/settings/llm/:id/test", async (req, res) => {
    const cfg = llmConfigs.find((c) => c.id === req.params.id);
    if (!cfg) return res.status(404).json({ error: "配置不存在" });
    try {
      if (cfg.provider === "mock") {
        return res.json({ success: true, message: "Mock LLM 始终可用", latencyMs: 0 });
      }
      const start = Date.now();
      const resp = await fetch(`${cfg.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${cfg.apiKey}` },
        body: JSON.stringify({ model: cfg.model, messages: [{ role: "user", content: "ping" }], max_tokens: 5 }),
        signal: AbortSignal.timeout(10000),
      });
      const latencyMs = Date.now() - start;
      if (resp.ok) res.json({ success: true, message: `连接成功（${latencyMs}ms）`, latencyMs });
      else res.json({ success: false, message: `HTTP ${resp.status}`, latencyMs });
    } catch (e) {
      res.json({ success: false, message: e.message?.slice(0, 100) });
    }
  });

  // ── 工具集成配置（MCP SAST/SCA/BAT/MST/FUZZ/DAST）──
  const toolConfigs = []; // {id, name, toolType, mcpCommand, mcpArgs, mcpUrl, enabled, createdAt}
  let toolIdCounter = 0;

  // 预置示例（引导用户填写）
  toolConfigs.push({
    id: "tool-example-sast",
    name: "示例：软安 SAST",
    toolType: "SAST",
    mcpCommand: "node",
    mcpArgs: "/path/to/ruanan-sast-mcp/server.js",
    mcpUrl: "",
    autoRun: true,
    enabled: false,
    isExample: true,
    createdAt: new Date().toISOString(),
  });
  toolConfigs.push({
    id: "tool-example-sca",
    name: "示例：软安 SCA",
    toolType: "SCA",
    mcpCommand: "node",
    mcpArgs: "/path/to/ruanan-sca-mcp/server.js",
    mcpUrl: "",
    autoRun: true,
    enabled: false,
    isExample: true,
    createdAt: new Date().toISOString(),
  });

  router.get("/settings/tools", (_req, res) => res.json(toolConfigs));

  router.post("/settings/tools", (req, res) => {
    const b = req.body;
    if (!b.name || !b.toolType) return res.status(400).json({ error: "name 和 toolType 必填" });
    const cfg = {
      id: `tool-${++toolIdCounter}`, name: b.name, toolType: b.toolType,
      mcpCommand: b.mcpCommand || "", mcpArgs: b.mcpArgs || "",
      mcpUrl: b.mcpUrl || "", autoRun: b.autoRun !== false,
      enabled: b.enabled !== false, createdAt: new Date().toISOString(),
    };
    toolConfigs.push(cfg);
    res.status(201).json(cfg);
  });

  router.put("/settings/tools/:id", (req, res) => {
    const cfg = toolConfigs.find((c) => c.id === req.params.id);
    if (!cfg) return res.status(404).json({ error: "配置不存在" });
    Object.assign(cfg, req.body, { updatedAt: new Date().toISOString() });
    res.json(cfg);
  });

  router.delete("/settings/tools/:id", (req, res) => {
    const idx = toolConfigs.findIndex((c) => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "配置不存在" });
    if (toolConfigs[idx].isExample) return res.status(403).json({ error: "示例配置不可删除" });
    const deleted = toolConfigs.splice(idx, 1)[0];
    res.json({ deleted: deleted.id });
  });

  router.post("/settings/tools/:id/test", async (req, res) => {
    const cfg = toolConfigs.find((c) => c.id === req.params.id);
    if (!cfg) return res.status(404).json({ error: "配置不存在" });
    // 检查 MCP server 是否可达（简化：检查 URL 或 command 是否合理）
    if (cfg.mcpUrl) {
      try {
        const resp = await fetch(cfg.mcpUrl, { signal: AbortSignal.timeout(5000) });
        res.json({ success: resp.ok, message: resp.ok ? "MCP URL 可达" : `HTTP ${resp.status}` });
      } catch (e) {
        res.json({ success: false, message: e.message?.slice(0, 100) });
      }
    } else if (cfg.mcpCommand) {
      res.json({ success: true, message: "命令行模式（启动时验证）" });
    } else {
      res.json({ success: false, message: "未配置 MCP URL 或命令" });
    }
  });

  return router;
}

module.exports = settingsRoutes;
