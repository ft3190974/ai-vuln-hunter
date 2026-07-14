// web/server/routes/scan.js — 扫描任务路由
//
// POST /api/scan   提交扫描（异步：立即返回 scanId，后台跑编排引擎）
// GET  /api/scan/:id  查询扫描任务状态/结果

const express = require("express");
const fs = require("fs");
const path = require("path");
const { scansTotal } = require("../observability/metrics");

const SCAN_JOBS_FILE = path.resolve(__dirname, "..", "..", "..", "data", "scan-jobs.json");
function saveScanJobs(jobs) {
  try {
    const dir = path.dirname(SCAN_JOBS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const obj = {}; for (const [id, job] of jobs.entries()) obj[id] = job;
    fs.writeFileSync(SCAN_JOBS_FILE, JSON.stringify(obj, null, 2));
  } catch {}
}

function scanRoutes({ engine, scanJobs }) {
  const router = express.Router();

  // 提交扫描任务
  router.post("/scan", async (req, res) => {
    try {
      const { scanRequest, toolOutputs, sourceInput } = req.body;
      if (!scanRequest && !sourceInput) {
        return res.status(400).json({ error: "缺少 scanRequest 或 sourceInput" });
      }
      const reqObj = scanRequest || {
        scanId: `scan-${Date.now()}`,
        target: { type: "source", path: sourceInput?.path || "(code)", language: sourceInput?.language || "java" },
        options: { depth: "deep", timeoutSec: 120 },
      };
      // 自动补 scanId
      if (!reqObj.scanId) reqObj.scanId = `scan-${Date.now()}`;
      const scanId = reqObj.scanId;

      // 记录任务初始状态
      scanJobs.set(scanId, {
        scanId,
        status: "running",
        startedAt: new Date().toISOString(),
        report: null,
        error: null,
      });

      // 后台异步跑（不阻塞 HTTP 响应）
      engine
        .run(reqObj, toolOutputs || {}, sourceInput)
        .then((report) => {
          const job = scanJobs.get(scanId);
          if (job) {
            job.status = "completed";
            job.report = report;
            job.completedAt = new Date().toISOString();
          }
          scansTotal.inc({ status: "completed" });
          saveScanJobs(scanJobs);
        })
        .catch((e) => {
          const job = scanJobs.get(scanId);
          if (job) {
            job.status = "failed";
            job.error = e.message;
          }
          scansTotal.inc({ status: "failed" });
          saveScanJobs(scanJobs);
        });

      // 记录提交指标
      scansTotal.inc({ status: "submitted" });

      return res.status(202).json({
        scanId,
        status: "running",
        message: "扫描任务已提交，用 GET /api/scan/:id 查询进度",
      });
    } catch (e) {
      scansTotal.inc({ status: "failed" });
      return res.status(500).json({ error: e.message });
    }
  });

  // 查询扫描任务
  router.get("/scan/:id", (req, res) => {
    const job = scanJobs.get(req.params.id);
    if (!job) {
      return res.status(404).json({ error: `扫描任务 ${req.params.id} 不存在` });
    }
    return res.json(job);
  });

  // 列出所有扫描任务（摘要，含漏洞数）
  router.get("/scan", async (_req, res) => {
    const list = [];
    for (const [id, job] of scanJobs.entries()) {
      // 统计该任务的漏洞数（从 findingStore 按 scanId 查）
      let findingsCount = 0;
      try {
        const findings = await engine.findingStore.query({ scanId: id });
        findingsCount = findings.length;
      } catch {}
      const input = job.scanRequest?.target || {};
      list.push({
        scanId: job.scanId,
        status: job.status,
        startedAt: job.startedAt,
        completedAt: job.completedAt,
        error: job.error,
        findingsCount,
        target: input.path || "(code)",
        language: input.language || "auto",
      });
    }
    // 按时间倒序（最新的在前）
    list.sort((a, b) => (b.startedAt || "").localeCompare(a.startedAt || ""));
    return res.json(list);
  });

  // 标记任务状态（前端轮询超时/主动取消时调用，避免任务永远卡在 running）
  router.patch("/scan/:id/status", (req, res) => {
    try {
      const job = scanJobs.get(req.params.id);
      if (!job) {
        return res.status(404).json({ error: `任务 ${req.params.id} 不存在` });
      }
      const { status, error } = req.body || {};
      if (!["running", "completed", "failed"].includes(status)) {
        return res.status(400).json({ error: "status 必须是 running/completed/failed" });
      }
      // 已完成/失败的任务不允许再改回 running（避免覆盖最终态）
      if (job.status === "completed" || job.status === "failed") {
        return res.json({ scanId: req.params.id, status: job.status, skipped: true });
      }
      job.status = status;
      if (error) job.error = error;
      if (status === "failed" || status === "completed") {
        job.completedAt = new Date().toISOString();
      }
      saveScanJobs(scanJobs);
      res.json({ scanId: req.params.id, status: job.status });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 删除任务（同时删除该任务的所有 Finding）
  router.delete("/scan/:id", async (req, res) => {
    try {
      const job = scanJobs.get(req.params.id);
      if (!job) {
        return res.status(404).json({ error: `任务 ${req.params.id} 不存在` });
      }
      // 删除关联的 Finding
      const findings = await engine.findingStore.query({ scanId: req.params.id });
      for (const f of findings) {
        await engine.findingStore.remove(f.findingId);
      }
      // 删除任务
      scanJobs.delete(req.params.id);
      saveScanJobs(scanJobs);
      res.json({ deleted: req.params.id, findingsRemoved: findings.length });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 清理孤儿 Finding：没有对应任务记录的 finding（任务已被手动删但 finding 残留，
  // 或早期无 scanId 的 finding）。返回清理数量。
  router.delete("/scan/orphans/cleanup", async (_req, res) => {
    try {
      const allFindings = await engine.findingStore.all();
      const validScanIds = new Set(scanJobs.keys());
      let removed = 0;
      for (const f of allFindings) {
        // scanId 为空，或 scanId 指向的任务已不存在 → 孤儿
        if (!f.scanId || !validScanIds.has(f.scanId)) {
          await engine.findingStore.remove(f.findingId);
          removed++;
        }
      }
      res.json({ removed, remaining: (await engine.findingStore.all()).length });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = scanRoutes;
