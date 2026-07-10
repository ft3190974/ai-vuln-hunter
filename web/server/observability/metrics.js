// observability/metrics.js — Prometheus 指标定义
//
// 暴露给 /metrics 端点，供 Prometheus 抓取。
// 指标分类：
//   - HTTP：请求计数（按方法/路径/状态）+ 请求延迟直方图
//   - 业务：扫描任务数、Finding 数（按状态）、LLM 调用次数/延迟
//
// 命名约定：ai_vuln_hunter_<领域>_<指标>

const promClient = require("prom-client");

// 收集默认指标（Node.js 进程：内存/CPU/GC 等）
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics({ prefix: "ai_vuln_hunter_node_" });

// ── HTTP 指标 ──
const httpRequestTotal = new promClient.Counter({
  name: "ai_vuln_hunter_http_requests_total",
  help: "HTTP 请求总数",
  labelNames: ["method", "path", "status"],
});

const httpRequestDuration = new promClient.Histogram({
  name: "ai_vuln_hunter_http_request_duration_seconds",
  help: "HTTP 请求延迟（秒）",
  labelNames: ["method", "path"],
  buckets: [0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5, 10],
});

// ── 业务指标 ──
const scansTotal = new promClient.Counter({
  name: "ai_vuln_hunter_scans_total",
  help: "扫描任务总数",
  labelNames: ["status"], // submitted/completed/failed
});

const findingsTotal = new promClient.Gauge({
  name: "ai_vuln_hunter_findings_total",
  help: "当前 Finding 总数（按状态）",
  labelNames: ["status"],
});

const llmCallsTotal = new promClient.Counter({
  name: "ai_vuln_hunter_llm_calls_total",
  help: "LLM 调用次数",
  labelNames: ["model", "difficulty"],
});

const llmCallDuration = new promClient.Histogram({
  name: "ai_vuln_hunter_llm_call_duration_seconds",
  help: "LLM 调用延迟（秒）",
  labelNames: ["model"],
  buckets: [0.5, 1, 2, 5, 10, 30, 60],
});

const vulnDbSyncTotal = new promClient.Counter({
  name: "ai_vuln_hunter_vulndb_sync_total",
  help: "漏洞库同步次数",
  labelNames: ["source", "result"], // success/error
});

// 从 engine 同步业务 Gauge（每次访问 /metrics 时调用）
function updateBusinessMetrics(engine) {
  return async () => {
    try {
      const stats = await engine.findingStore.stats();
      const byStatus = stats.byStatus || {};
      // 先重置所有标签为 0，再设新值（避免删除的状态残留）
      const allStatuses = ["candidate", "confirmed", "false_positive", "fixed", "wont_fix"];
      for (const s of allStatuses) {
        findingsTotal.set({ status: s }, byStatus[s] || 0);
      }
    } catch {
      /* engine 未就绪等 */
    }
  };
}

module.exports = {
  promClient,
  httpRequestTotal,
  httpRequestDuration,
  scansTotal,
  findingsTotal,
  llmCallsTotal,
  llmCallDuration,
  vulnDbSyncTotal,
  updateBusinessMetrics,
};
