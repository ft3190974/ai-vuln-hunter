// web/server/routes/rules.js — 自定义规则 CRUD 路由
//
// 用户通过这些 API 持续"喂"漏洞挖掘方法/缺陷代码规则给系统。
// 规则存到 engine.ruleEngine，llm-hunter 扫描时自动加载使用。
//
// GET    /api/rules                列出全部（?enabled=&category= 过滤）
// POST   /api/rules                创建（natural_language 类型）
// PUT    /api/rules/:ruleId        更新
// DELETE /api/rules/:ruleId        删除（内置规则不可删）
// POST   /api/rules/:ruleId/toggle 启用/禁用

const express = require("express");

function ruleRoutes({ engine }) {
  const router = express.Router();

  // 列出规则
  router.get("/rules", async (req, res) => {
    try {
      const { enabled, category, source } = req.query;
      let rules = await engine.ruleEngine.list();
      if (enabled === "true") rules = rules.filter((r) => r.enabled);
      if (enabled === "false") rules = rules.filter((r) => !r.enabled);
      if (category) rules = rules.filter((r) => r.category === category);
      if (source) rules = rules.filter((r) => r.origin === source);
      res.json(rules);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 创建规则
  router.post("/rules", async (req, res) => {
    try {
      const b = req.body || {};
      if (!b.name || !b.description) {
        return res.status(400).json({ error: "name 和 description 必填" });
      }
      const ruleId = b.ruleId || `CUSTOM-${Date.now().toString(36).toUpperCase()}`;
      const rule = {
        ruleId,
        name: b.name,
        type: "natural_language",
        category: b.category || "unknown",
        severity: b.severity || "medium",
        languages: Array.isArray(b.languages) ? b.languages : [],
        enabled: b.enabled !== false,
        // 用户填写的核心内容
        description: b.description,
        detectionHints: b.detectionHints || "",
        sinks: Array.isArray(b.sinks) ? b.sinks : (b.sinks ? String(b.sinks).split(",").map((s) => s.trim()).filter(Boolean) : []),
        exampleVulnerable: b.exampleVulnerable || "",
        exampleSafe: b.exampleSafe || "",
        // 元数据
        version: "1.0.0",
        origin: "user",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      await engine.ruleEngine.add(rule);
      res.status(201).json(rule);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 更新规则
  router.put("/rules/:ruleId", async (req, res) => {
    try {
      const existing = (await engine.ruleEngine.list()).find((r) => r.ruleId === req.params.ruleId);
      if (!existing) return res.status(404).json({ error: "规则不存在" });
      if (existing.origin === "builtin" && req.body.category) {
        // 内置规则只允许改 enabled（通过 toggle），不允许改内容
        return res.status(403).json({ error: "内置规则不可编辑，只能启用/禁用" });
      }
      const b = req.body;
      const updated = {
        ...existing,
        name: b.name ?? existing.name,
        description: b.description ?? existing.description,
        detectionHints: b.detectionHints ?? existing.detectionHints,
        category: b.category ?? existing.category,
        severity: b.severity ?? existing.severity,
        languages: Array.isArray(b.languages) ? b.languages : existing.languages,
        sinks: Array.isArray(b.sinks) ? b.sinks : (typeof b.sinks === "string" ? b.sinks.split(",").map((s) => s.trim()).filter(Boolean) : existing.sinks),
        exampleVulnerable: b.exampleVulnerable ?? existing.exampleVulnerable,
        exampleSafe: b.exampleSafe ?? existing.exampleSafe,
        updatedAt: new Date().toISOString(),
      };
      await engine.ruleEngine.update(existing.ruleId, updated);
      res.json(updated);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 删除规则（内置不可删）
  router.delete("/rules/:ruleId", async (req, res) => {
    try {
      const existing = (await engine.ruleEngine.list()).find((r) => r.ruleId === req.params.ruleId);
      if (!existing) return res.status(404).json({ error: "规则不存在" });
      if (existing.origin === "builtin") {
        return res.status(403).json({ error: "内置规则不可删除" });
      }
      await engine.ruleEngine.remove(existing.ruleId);
      res.json({ deleted: existing.ruleId });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 启用/禁用
  router.post("/rules/:ruleId/toggle", async (req, res) => {
    try {
      const existing = (await engine.ruleEngine.list()).find((r) => r.ruleId === req.params.ruleId);
      if (!existing) return res.status(404).json({ error: "规则不存在" });
      const updated = { ...existing, enabled: !existing.enabled, updatedAt: new Date().toISOString() };
      await engine.ruleEngine.update(existing.ruleId, updated);
      res.json({ ruleId: existing.ruleId, enabled: updated.enabled });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = ruleRoutes;
