// web/server/routes/vuln-db.js — 漏洞库同步路由

const express = require("express");

function vulnDbRoutes({ syncManager }) {
  const router = express.Router();

  // 查询各数据源同步状态
  router.get("/vuln-db/sources", (_req, res) => {
    res.json(syncManager.status());
  });

  // 触发同步（可选 ?source=nvd 单源）
  router.post("/vuln-db/sync", async (req, res) => {
    try {
      const { source } = req.query;
      if (source) {
        const result = await syncManager.syncOne(source);
        return res.json({ results: [result] });
      }
      const result = await syncManager.syncAll();
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = vulnDbRoutes;
