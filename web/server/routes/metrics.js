// routes/metrics.js — Prometheus metrics 端点 + HTTP 指标中间件
const express = require("express");
const { promClient, httpRequestTotal, httpRequestDuration, updateBusinessMetrics } = require("../observability/metrics");

function metricsRoutes({ engine }) {
  const router = express.Router();

  // GET /api/metrics —— Prometheus 文本格式
  router.get("/metrics", async (_req, res) => {
    try {
      // 同步业务 Gauge（findings 计数）
      if (engine) {
        const upd = updateBusinessMetrics(engine);
        await upd();
      }
      res.set("Content-Type", promClient.register.contentType);
      res.end(await promClient.register.metrics());
    } catch (e) {
      res.status(500).end(`# metrics error: ${e.message}`);
    }
  });

  return router;
}

// HTTP 请求指标中间件（记录每个请求的计数 + 延迟）
function httpMetricsMiddleware(req, res, next) {
  const start = Date.now();
  res.on("finish", () => {
    const duration = (Date.now() - start) / 1000;
    // 标准化路径（把 /api/findings/F-2026-001 归一为 /api/findings/:id）
    const path = req.route
      ? req.route.path
      : req.path.replace(/\/[A-Z]+-\d[\w-]+/g, "/:id").replace(/\/\d+/g, "/:id");
    httpRequestTotal.inc({ method: req.method, path, status: String(res.statusCode) });
    httpRequestDuration.observe({ method: req.method, path }, duration);
  });
  next();
}

module.exports = { metricsRoutes, httpMetricsMiddleware };
