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
const fs = require("fs");
const path = require("path");

const SETTINGS_FILE = path.resolve(__dirname, "..", "..", "..", "data", "settings.json");

// 引入编排引擎的 LLM 动态配置
let setDynamicLlmConfig = null;
try {
  setDynamicLlmConfig = require("../../../orchestrator/llm").setDynamicLlmConfig;
} catch (e) {
  console.warn("[settings] 无法加载编排引擎 LLM 模块，动态切换不可用");
}

// 持久化加载/保存
function loadSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) return JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf-8"));
  } catch {}
  return { llmConfigs: [], toolConfigs: [] };
}
function saveSettings(data) {
  try {
    const dir = path.dirname(SETTINGS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2));
  } catch (e) { console.warn("[settings] 保存失败:", e.message); }
}

function settingsRoutes() {
  const router = express.Router();

  // ── LLM 配置（持久化到 data/settings.json）──
  const saved = loadSettings();
  const llmConfigs = saved.llmConfigs?.length ? saved.llmConfigs : [
    {
      id: "llm-default", name: "默认 LLM", provider: "mock",
      baseUrl: "https://open.bigmodel.cn/api/paas/v4", apiKey: "",
      model: "glm-4-plus", temperature: 0.2, maxTokens: 2048,
      difficulty: "auto", enabled: true, isDefault: true, createdAt: new Date().toISOString(),
    },
  ];
  let llmIdCounter = llmConfigs.length;

  // 同步启用的 LLM 配置到编排引擎
  function syncLlmToEngine() {
    saveSettings({ llmConfigs, toolConfigs });
    if (!setDynamicLlmConfig) return;
    const enabled = llmConfigs.find((c) => c.enabled && c.provider !== "mock");
    if (enabled) {
      setDynamicLlmConfig(enabled);
      console.log(`[settings] LLM 同步到引擎: ${enabled.name} (${enabled.provider})`);
    } else {
      setDynamicLlmConfig(null);
      console.log("[settings] LLM 同步到引擎: mock（无启用的非 mock 配置）");
    }
  }

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
    syncLlmToEngine();
    res.status(201).json(cfg);
  });

  router.put("/settings/llm/:id", (req, res) => {
    const cfg = llmConfigs.find((c) => c.id === req.params.id);
    if (!cfg) return res.status(404).json({ error: "配置不存在" });
    Object.assign(cfg, req.body, { updatedAt: new Date().toISOString() });
    syncLlmToEngine();
    res.json(cfg);
  });

  router.delete("/settings/llm/:id", (req, res) => {
    const idx = llmConfigs.findIndex((c) => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: "配置不存在" });
    if (llmConfigs[idx].isDefault) return res.status(403).json({ error: "默认配置不可删除" });
    const deleted = llmConfigs.splice(idx, 1)[0];
    syncLlmToEngine();
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

  // ── 工具集成配置（持久化）──
  const toolConfigs = saved.toolConfigs?.length ? saved.toolConfigs : [
    { id: "tool-example-sast", name: "示例：软安 SAST", toolType: "SAST", mcpCommand: "node", mcpArgs: "/path/to/ruanan-sast-mcp/server.js", mcpUrl: "", autoRun: true, enabled: false, isExample: true, createdAt: new Date().toISOString() },
    { id: "tool-example-sca", name: "示例：软安 SCA", toolType: "SCA", mcpCommand: "node", mcpArgs: "/path/to/ruanan-sca-mcp/server.js", mcpUrl: "", autoRun: true, enabled: false, isExample: true, createdAt: new Date().toISOString() },
  ];
  let toolIdCounter = toolConfigs.length;

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

  // 启动时自动同步 LLM 配置到引擎
  syncLlmToEngine();

  return router;
}

module.exports = settingsRoutes;
