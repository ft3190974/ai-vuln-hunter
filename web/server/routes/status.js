// web/server/routes/status.js — 引擎状态路由（async，inspect 已 async 化）

const express = require("express");

function statusRoutes({ engine, syncManager }) {
  const router = express.Router();

  router.get("/status", async (_req, res) => {
    try {
      res.json({
        engine: await engine.inspect(),
        vulnDb: syncManager.status(),
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = statusRoutes;
