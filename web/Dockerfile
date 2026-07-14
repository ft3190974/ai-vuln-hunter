# web/Dockerfile — 多阶段构建
#
# 构建上下文必须是项目根目录（因为要 COPY orchestrator/mcp-server 等多个模块）
#   docker build -t ai-vuln-hunter -f web/Dockerfile .
# 运行：
#   docker run -p 3000:3000 -e LLM_MODE=mock ai-vuln-hunter
#   docker compose -f web/docker-compose.yml up -d

# ── Stage 1: 前端构建（Vite 产物）──
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend
COPY web/frontend/package*.json ./
RUN npm ci
COPY web/frontend/ ./
RUN npm run build

# ── Stage 2: 后端运行时 ──
FROM node:20-alpine AS runtime
WORKDIR /app

# ---- 安装各模块生产依赖（分层 COPY package.json 利用 Docker 缓存）----
# 1) Express 后端
COPY web/server/package*.json ./web/server/
RUN cd web/server && npm ci --omit=dev

# 2) 编排引擎（engine.js require @modelcontextprotocol/sdk / ajv / ajv-formats）
COPY orchestrator/package*.json ./orchestrator/
RUN cd orchestrator && npm ci --omit=dev

# 3) MCP server（工具接入层，同样依赖 sdk / ajv）
COPY mcp-server/package*.json ./mcp-server/
RUN cd mcp-server && npm ci --omit=dev

# ---- 复制各模块源码（保持原目录结构，app.js 用 __dirname 做相对路径解析）----
COPY web/server/    ./web/server/
COPY orchestrator/  ./orchestrator/
COPY mcp-server/    ./mcp-server/
COPY vuln-db/       ./vuln-db/
COPY schemas/       ./schemas/

# ---- 前端构建产物（app.js 从 __dirname/../frontend/dist 托管静态文件）----
COPY --from=frontend-builder /build/frontend/dist ./web/frontend/dist

# ---- 运行时目录（持久化数据：scan-jobs / findings / settings）----
RUN mkdir -p /app/data
VOLUME ["/app/data"]

# 环境变量默认值（运行时可覆盖）
ENV NODE_ENV=production
ENV PORT=3000
ENV LLM_MODE=mock
ENV SANDBOX_MODE=mock
ENV FINDING_STORE_FILE=/app/data/findings.json

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/health || exit 1

CMD ["node", "web/server/app.js"]
