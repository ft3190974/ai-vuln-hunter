# web/Dockerfile — 多阶段构建
#
# Stage 1: 构建前端（Vite 产物）
# Stage 2: 运行时（Express 服务 + 前端 dist + orchestrator + vuln-db）
#
# 构建：docker build -t ai-vuln-hunter ./web
# 运行：docker run -p 3000:3000 -e LLM_MODE=mock ai-vuln-hunter

# ── Stage 1: 前端构建 ──
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── Stage 2: 后端 + 整合 ──
FROM node:20-alpine AS runtime
WORKDIR /app

# 安装后端依赖
COPY server/package*.json ./server/
RUN cd server && npm ci --omit=dev

# 复制各模块代码（Express 服务 + 编排引擎 + 漏洞库 + 契约）
COPY server/ ./server/
COPY orchestrator/ ./orchestrator/
COPY vuln-db/ ./vuln-db/
COPY schemas/ ./schemas/
COPY mcp-server/ ./mcp-server/

# 复制前端构建产物（从 Stage 1）
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist

ENV NODE_ENV=production
ENV PORT=3000
ENV LLM_MODE=mock
ENV SANDBOX_MODE=mock

EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/health || exit 1

CMD ["node", "server/app.js"]
