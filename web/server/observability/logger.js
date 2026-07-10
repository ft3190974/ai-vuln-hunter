// observability/logger.js — 结构化日志（pino）
//
// JSON 格式输出，带 requestId（每请求一个，串联日志）。
// 生产环境可对接 ELK/Loki 等日志聚合系统。
//
// 日志级别由 LOG_LEVEL 环境变量控制（默认 info）。
// 用法：
//   const { logger, requestLogger } = require("./observability/logger");
//   logger.info({ scanId }, "扫描开始");
//   app.use(requestLogger);  // 自动记录每个 HTTP 请求

const pino = require("pino");
const { randomUUID } = require("crypto");

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  // 基础字段：服务名 + 版本
  base: { service: "ai-vuln-hunter", version: "1.0.0" },
  // 时间戳用 ISO 字符串（人类可读）
  timestamp: pino.stdTimeFunctions.isoTime,
  // 生产：纯 JSON；开发：着色（按 NODE_ENV）
  transport: process.env.NODE_ENV === "production"
    ? undefined
    : { target: "pino-pretty", options: { colorize: true, translateTime: "SYS:HH:MM:ss" } },
});

// 子 logger 工厂：带固定上下文（如 scanId / userId）
function child(bindings) {
  return logger.child(bindings);
}

// Express 请求日志中间件：每个请求注入 requestId，记录方法/路径/状态/延迟
function requestLogger(req, res, next) {
  const requestId = req.headers["x-request-id"] || randomUUID();
  req.requestId = requestId;
  req.log = logger.child({ requestId });
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    req.log.info({
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: duration,
      userAgent: req.headers["user-agent"],
    }, "HTTP 请求");
  });

  next();
}

module.exports = { logger, child, requestLogger };
