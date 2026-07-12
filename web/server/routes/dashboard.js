// web/server/routes/dashboard.js — 态势总览聚合数据
//
// GET /api/dashboard
// 返回：6 个核心指标 + 趋势数据（按天） + 类别分布 + 严重度分布

const express = require("express");

function dashboardRoutes({ engine }) {
  const router = express.Router();

  router.get("/dashboard", async (_req, res) => {
    try {
      const findings = await engine.findingStore.all();
      const stats = await engine.findingStore.stats();

      // ── 6 个核心指标 ──
      const totalFindings = findings.length;
      const totalScans = 0; // 由 scanJobs 统计（前端轮询补）
      const logicVulns = findings.filter((f) => f.category === "business_logic").length;
      const highSeverity = findings.filter((f) => ["critical", "high"].includes(f.severity)).length;
      const pocCount = findings.filter((f) => f.poc).length;
      const zeroDayCount = findings.filter((f) => f.isZeroDay && f.zeroDayVerified).length;
      const zeroDayCandidateCount = findings.filter((f) => f.isZeroDay && !f.zeroDayVerified).length;

      // 近 7 天新增
      const now = Date.now();
      const weekAgo = now - 7 * 24 * 3600 * 1000;
      const newThisWeek = findings.filter((f) => {
        const t = new Date(f.createdAt || f.updatedAt || now).getTime();
        return t >= weekAgo;
      }).length;

      // ── 趋势：最近 14 天每天的漏洞数 ──
      const trend = [];
      for (let i = 13; i >= 0; i--) {
        const day = new Date(now - i * 24 * 3600 * 1000);
        const dayStart = new Date(day.getFullYear(), day.getMonth(), day.getDate()).getTime();
        const dayEnd = dayStart + 24 * 3600 * 1000;
        const count = findings.filter((f) => {
          const t = new Date(f.createdAt || now).getTime();
          return t >= dayStart && t < dayEnd;
        }).length;
        trend.push({
          date: `${day.getMonth() + 1}/${day.getDate()}`,
          count,
        });
      }

      // ── 类别分布（饼图）──
      const categoryMap = {};
      for (const f of findings) {
        categoryMap[f.category] = (categoryMap[f.category] || 0) + 1;
      }
      const categoryDist = Object.entries(categoryMap)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value);

      // ── 严重度分布（直接从 findings 统计）──
      const sevMap = {};
      for (const f of findings) {
        if (f.severity) sevMap[f.severity] = (sevMap[f.severity] || 0) + 1;
      }
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const severityDist = severityOrder
        .map((s) => ({ name: s, value: sevMap[s] || 0 }))
        .filter((s) => s.value > 0);

      // ── 状态分布 ──
      const statusDist = Object.entries(stats.byStatus || {}).map(([name, value]) => ({ name, value }));

      // ── 规则数 / 图谱节点（引擎能力指标）──
      const engineStatus = await engine.inspect();

      res.json({
        metrics: {
          totalFindings,
          logicVulns,
          highSeverity,
          newThisWeek,
          pocCount,
          zeroDayCount,
          zeroDayCandidateCount,
        },
        trend,
        categoryDist,
        severityDist,
        statusDist,
        engine: {
          rules: engineStatus.rules,
          graphNodes: engineStatus.knowledgeGraph.nodes,
          fpPatterns: engineStatus.fpPatterns,
        },
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = dashboardRoutes;
