// web/server/routes/findings.js — Finding 查询路由（async，store 已 async 化）

const express = require("express");

function findingRoutes({ engine }) {
  const router = express.Router();

  router.get("/findings", async (req, res) => {
    try {
      const { status, category, minConfidence, scanId } = req.query;
      const filter = {};
      if (status) filter.status = status;
      if (category) filter.category = category;
      if (minConfidence) filter.minConfidence = Number(minConfidence);
      if (scanId) filter.scanId = scanId;
      const findings = await engine.findingStore.query(filter);
      return res.json(findings);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  router.get("/findings/:id", async (req, res) => {
    try {
      const finding = await engine.findingStore.get(req.params.id);
      if (!finding) return res.status(404).json({ error: `Finding ${req.params.id} 不存在` });
      return res.json(finding);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  router.get("/findings-stats/summary", async (_req, res) => {
    try {
      const all = await engine.findingStore.all();
      const byStatus = {}, byCategory = {}, bySeverity = {};
      for (const f of all) {
        byStatus[f.status] = (byStatus[f.status] || 0) + 1;
        byCategory[f.category] = (byCategory[f.category] || 0) + 1;
        bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      }
      return res.json({ total: all.length, byStatus, byCategory, bySeverity });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = findingRoutes;
