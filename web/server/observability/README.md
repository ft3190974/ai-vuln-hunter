# 可观测性（Observability）

P + Q + R 升级引入的可观测性能力：结构化日志 + Prometheus 指标。

## R1：结构化日志（pino）

### 文件
- `web/server/observability/logger.js` — pino 配置 + requestLogger 中间件

### 特性
- **JSON 格式**（生产）+ 着色（开发，pino-pretty）
- **requestId**：每个 HTTP 请求自动注入唯一 ID，串联该请求的所有日志
- **child logger**：`logger.child({ scanId, userId })` 创建带固定上下文的子 logger
- 日志级别由 `LOG_LEVEL` 控制（debug/info/warn/error，默认 info）

### 字段
每条日志含：`service` / `version` / `timestamp`(ISO) / 自定义字段 / `msg`

### 自动记录
`requestLogger` 中间件在每个请求完成时记录：
```json
{ "requestId": "uuid", "method": "GET", "path": "/api/findings", "status": 200, "durationMs": 12 }
```

## R2：Prometheus 指标

### 文件
- `web/server/observability/metrics.js` — 指标定义
- `web/server/routes/metrics.js` — `/api/metrics` 端点 + HTTP 指标中间件

### 指标清单
| 指标 | 类型 | 说明 |
|---|---|---|
| `ai_vuln_hunter_node_*` | 默认 | Node.js 进程（CPU/内存/GC/事件循环） |
| `ai_vuln_hunter_http_requests_total` | Counter | HTTP 请求计数（method/path/status） |
| `ai_vuln_hunter_http_request_duration_seconds` | Histogram | HTTP 请求延迟 |
| `ai_vuln_hunter_scans_total` | Counter | 扫描任务数（submitted/completed/failed） |
| `ai_vuln_hunter_findings_total` | Gauge | Finding 数（按状态） |
| `ai_vuln_hunter_llm_calls_total` | Counter | LLM 调用次数（model/difficulty） |
| `ai_vuln_hunter_llm_call_duration_seconds` | Histogram | LLM 调用延迟 |
| `ai_vuln_hunter_vulndb_sync_total` | Counter | 漏洞库同步次数（source/result） |

### 抓取
Prometheus 配置示例：
```yaml
scrape_configs:
  - job_name: "ai-vuln-hunter"
    static_configs:
      - targets: ["localhost:3000"]
    metrics_path: "/api/metrics"
```

或直接 curl：
```bash
curl http://localhost:3000/api/metrics
```

### Grafana 仪表盘建议
- HTTP：QPS（rate of http_requests_total）、P99 延迟（histogram_quantile）
- 业务：扫描成功率（completed/total）、Finding 增长曲线、LLM 调用量
- 进程：内存占用、事件循环延迟、GC 频率
