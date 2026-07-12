// web/server/app.js — Express 应用主入口
//
// 复用 OrchestratorEngine 单例（编排大脑）+ SyncManager（漏洞库），
// 暴露 RESTful API 供前端调用。
//
// 路由：
//   POST /api/scan           提交扫描任务（异步）
//   GET  /api/scan/:id       查询扫描任务状态/结果
//   GET  /api/findings       查询 Finding（支持 ?status=&category=）
//   GET  /api/findings/:id   查询单个 Finding
//   GET  /api/status         引擎状态（误报库/图谱/规则/Finding 统计）
//   GET  /api/graph          知识图谱全量数据（前端可视化）
//   GET  /api/vuln-db/sources  漏洞库各源同步状态
//   POST /api/vuln-db/sync   触发漏洞库同步
//
// 静态文件：托管 frontend/dist（Vite 构建产物）

const express = require("express");
const cors = require("cors");
const path = require("path");

const { OrchestratorEngine } = require("../../orchestrator/engine");
const { createStores } = require("../../orchestrator/repository/factory");
const { SyncManager } = require("../../vuln-db/sync-manager");

const scanRoutes = require("./routes/scan");
const findingRoutes = require("./routes/findings");
const statusRoutes = require("./routes/status");
const graphRoutes = require("./routes/graph");
const vulnDbRoutes = require("./routes/vuln-db");
const authRoutes = require("./routes/auth");
const ruleRoutes = require("./routes/rules");
const uploadRoutes = require("./routes/upload");
const dashboardRoutes = require("./routes/dashboard");
const settingsRoutes = require("./routes/settings");
const { metricsRoutes, httpMetricsMiddleware } = require("./routes/metrics");
const { UserStore } = require("./auth/users");
const { authMiddleware } = require("./auth/middleware");
const { requestLogger } = require("./observability/logger");

async function createApp(options = {}) {
  // 单例引擎（跨请求累积学习沉淀）；按 DB_MODE 自动选存储实现
  let engine = options.engine;
  if (!engine) {
    const stores = options.stores || (await createStores(process.env.DB_MODE || "memory"));
    console.log(`[app] 存储模式: ${stores.mode}`);
    engine = new OrchestratorEngine({ stores });
  }
  // SyncManager 绑定到引擎的图谱与规则库
  const syncManager =
    options.syncManager ||
    new SyncManager({
      knowledgeGraph: engine.knowledgeGraph,
      ruleEngine: engine.ruleEngine,
    });
  // 用户存储（内存版，N 之后可接 Postgres）
  const userStore = options.userStore || new UserStore();

  // 扫描任务存储（文件持久化，重启不丢）
  const SCAN_JOBS_FILE = path.resolve(__dirname, "..", "..", "data", "scan-jobs.json");
  const fs = require("fs");
  const scanJobs = new Map();
  // 启动时加载
  try {
    if (fs.existsSync(SCAN_JOBS_FILE)) {
      const saved = JSON.parse(fs.readFileSync(SCAN_JOBS_FILE, "utf-8"));
      for (const [id, job] of Object.entries(saved)) scanJobs.set(id, job);
      console.log(`[app] 恢复 ${scanJobs.size} 个历史任务`);
    }
  } catch (e) { console.warn("[app] 加载任务历史失败:", e.message); }
  // 保存函数
  function saveScanJobs() {
    try {
      const dir = path.dirname(SCAN_JOBS_FILE);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      const obj = {};
      for (const [id, job] of scanJobs.entries()) obj[id] = job;
      fs.writeFileSync(SCAN_JOBS_FILE, JSON.stringify(obj, null, 2));
    } catch (e) { console.warn("[app] 保存任务历史失败:", e.message); }
  }

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: "10mb" }));
  // 可观测性中间件：结构化请求日志 + HTTP 指标
  app.use(requestLogger);
  app.use(httpMetricsMiddleware);

  // 健康检查 + Prometheus 指标端点（都免认证）
  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, ts: new Date().toISOString(), authEnabled: process.env.AUTH_ENABLED === "1" });
  });
  app.use("/api", metricsRoutes({ engine }));

  // 认证路由（免认证，除 /me）
  app.use("/api", authRoutes({ userStore }));
  // 文件上传（免认证，扫描前上传）
  app.use("/api", uploadRoutes());

  // 其余 /api/* 需认证（AUTH_ENABLED=0 时中间件直接放行，向后兼容）
  app.use(
    "/api",
    authMiddleware,
    scanRoutes({ engine, scanJobs }),
    findingRoutes({ engine }),
    statusRoutes({ engine, syncManager }),
    graphRoutes({ engine }),
    vulnDbRoutes({ syncManager }),
    ruleRoutes({ engine }),
    dashboardRoutes({ engine }),
    settingsRoutes()
  );

  // 静态托管前端（生产环境）
  const distPath = path.resolve(__dirname, "..", "frontend", "dist");
  app.use(express.static(distPath));
  // SPA 回退：非 /api 开头的请求都返回 index.html
  app.get(/^\/(?!api).*/, (_req, res) => {
    res.sendFile(path.join(distPath, "index.html"), (err) => {
      if (err) res.status(404).json({ error: "前端未构建，请先 cd frontend && npm run build" });
    });
  });

  return { app, engine, syncManager, scanJobs, userStore };
}

module.exports = { createApp };

// 直接运行时启动服务器
if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || "0.0.0.0";
  createApp().then(({ app }) => {
    const server = app.listen(port, host, () => {
      console.log(`[ai-vuln-hunter] HTTP server 已启动`);
      console.log(`  前端:  http://localhost:${port}/`);
      console.log(`  API:   http://localhost:${port}/api/health`);
    });
    server.on("error", (e) => {
      if (e.code === "EADDRINUSE") {
        console.error(`[错误] 端口 ${port} 已被占用。改用 PORT=3001 node app.js`);
      } else {
        console.error(`[错误] 服务启动失败:`, e.message);
      }
      process.exit(1);
    });
  }).catch((e) => {
    console.error("[fatal]", e);
    process.exit(1);
  });
}
