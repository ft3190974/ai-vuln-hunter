// ruanan-sast-adapter.js — 软安 SAST（静兮）适配器 mock 实现
// 模拟真实 SAST 工具的行为：接收扫描请求 → 模拟异步分析 → 返回归一化结果。
// 真实接入时，把这里的 mock 逻辑替换为对软安 SAST 实际 API/CLI 的调用即可，
// 对外的接口（scan/getStatus/getResults）保持不变，上层无需改动。

const path = require("path");
const fs = require("fs");

// 模拟任务存储（生产环境用 Redis/DB）
const jobs = new Map();

// 工具能力声明（对应 tool-adapter.schema.json）
const ADAPTER_INFO = {
  toolId: "ruanan-sast",
  toolName: "软安 SAST 静兮",
  toolType: "SAST",
  version: "2.4.1",
  vendor: "ruanan",
  capabilities: {
    languages: ["java", "c", "cpp", "python", "go"],
    inputType: "source",
    needBuild: true,
    buildSystem: ["maven", "gradle", "make", "cmake"],
    output: ["findings", "data_flow"],
    supportsDataFlow: true,
    supportsAsync: true,
    maxConcurrency: 4,
  },
  endpoints: {
    scan: "ruanan_sast_scan",
    getStatus: "ruanan_sast_status",
    getResults: "ruanan_sast_results",
    cancel: "ruanan_sast_cancel",
  },
};

/**
 * 模拟的扫描结果（基于真实 SAST 工具常见输出结构构造）
 * 真实接入时：调用软安 SAST API 拉取报告，转换为符合 sast-output.schema.json 的结构
 */
function buildMockResults(scanRequest) {
  const targetLang = scanRequest.target.language || "java";
  return {
    toolId: "ruanan-sast",
    scanId: scanRequest.scanId,
    scannedAt: new Date().toISOString(),
    durationSec: 180,
    buildStatus: {
      success: true,
      buildSystem: scanRequest.target.buildSystem || "maven",
    },
    findings: [
      {
        ruleId: "RA-SQLI-001",
        category: "sqli",
        severity: "critical",
        message: "SQL 查询使用字符串拼接，存在 SQL 注入风险",
        location: {
          file: "src/controllers/LoginController.java",
          startLine: 42,
          endLine: 42,
          function: "login",
        },
        // ★ 关键：snippet 代码片段（用户明确要求的字段）
        snippet: {
          code:
            'String username = request.getParameter("name");\n' +
            'String pwd = request.getParameter("pwd");\n' +
            'String sql = "SELECT * FROM users WHERE name=\'" + username + "\' AND pwd=\'" + pwd + "\'";\n' +
            "Statement stmt = conn.createStatement();\n" +
            "ResultSet rs = stmt.execute(sql);",
          language: targetLang,
          primaryLine: 3,
          startLine: 40,
          endLine: 44,
          contextType: "function",
          file: "src/controllers/LoginController.java",
          function: "login",
        },
        // 污点数据流（SAST 支持时提供）
        dataFlow: {
          sources: [
            {
              file: "LoginController.java",
              line: 40,
              code: 'String username = request.getParameter("name");',
              role: "source",
            },
          ],
          sinks: [
            {
              file: "LoginController.java",
              line: 43,
              code: "stmt.execute(sql);",
              role: "sink",
            },
          ],
          path: [
            {
              file: "LoginController.java",
              line: 40,
              code: 'String username = request.getParameter("name");',
              role: "source",
            },
            {
              file: "LoginController.java",
              line: 42,
              code: 'String sql = "..." + username + "...";',
              role: "propagator",
            },
            {
              file: "LoginController.java",
              line: 43,
              code: "stmt.execute(sql);",
              role: "sink",
            },
          ],
        },
        confidence: 0.92,
      },
      {
        ruleId: "RA-AUTHZ-014",
        category: "authz",
        severity: "high",
        message: "资源访问未校验属主，存在水平越权风险",
        location: {
          file: "src/controllers/OrderController.java",
          startLine: 88,
          endLine: 90,
          function: "getOrder",
        },
        snippet: {
          code:
            "@GetMapping(\"/orders/{id}\")\n" +
            "public Order getOrder(@PathVariable Long id) {\n" +
            "    return orderRepo.findById(id);  // 未校验当前用户是否为该订单属主\n" +
            "}",
          language: targetLang,
          primaryLine: 3,
          startLine: 88,
          endLine: 90,
          contextType: "function",
          file: "src/controllers/OrderController.java",
          function: "getOrder",
        },
        confidence: 0.78,
      },
    ],
  };
}

/**
 * 提交扫描任务（异步）
 * @param {object} scanRequest  符合 scan-request.schema.json 的请求
 * @returns {object} 包含 jobId 的任务句柄
 */
function scan(scanRequest) {
  const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  jobs.set(jobId, {
    jobId,
    scanId: scanRequest.scanId,
    status: "running",
    startedAt: new Date().toISOString(),
    scanRequest,
    results: null,
    error: null,
  });

  // 模拟异步分析（真实工具可能数分钟~数小时）
  const delayMs = 1500;
  setTimeout(() => {
    const job = jobs.get(jobId);
    if (!job) return;
    if (job.status === "cancelled") return;
    try {
      job.results = buildMockResults(scanRequest);
      job.status = "completed";
      job.completedAt = new Date().toISOString();
    } catch (e) {
      job.status = "failed";
      job.error = e.message;
    }
  }, delayMs);

  return { jobId, status: "running", submittedAt: new Date().toISOString() };
}

function getStatus(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { error: `任务 ${jobId} 不存在` };
  return {
    jobId,
    scanId: job.scanId,
    status: job.status,
    startedAt: job.startedAt,
    completedAt: job.completedAt || null,
    error: job.error,
  };
}

function getResults(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { error: `任务 ${jobId} 不存在` };
  if (job.status !== "completed") {
    return { error: `任务 ${jobId} 状态为 ${job.status}，尚未完成` };
  }
  return job.results;
}

function cancel(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { error: `任务 ${jobId} 不存在` };
  job.status = "cancelled";
  return { jobId, status: "cancelled" };
}

module.exports = {
  ADAPTER_INFO,
  scan,
  getStatus,
  getResults,
  cancel,
};
