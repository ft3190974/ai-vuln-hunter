# 🛡️ AI 漏洞挖掘应用

基于 LLM 的智能漏洞挖掘平台，聚焦 **0-day 变种挖掘**与**业务逻辑漏洞**——这是传统 SAST/SCA 工具无能为力的领域。

> **核心理念**：LLM 能理解业务语义，传统工具不能。SAST/SCA 只是辅助输入，LLM 自主挖掘才是主线。

---

## ✨ 核心能力

| 能力 | 说明 |
|---|---|
| **LLM 自主挖掘** | 直接读源代码（不需 SAST 先扫），LLM 按规则库自主发现漏洞，重点覆盖业务逻辑漏洞 |
| **C/C++ 跨函数分析** | 调用图 + 资源流追踪，发现跨函数内存泄漏 / double-free / UAF |
| **Java 二进制分析** | .jar/.class 反编译（CFR）→ 源码级 LLM 分析 |
| **C/C++ 二进制分析** | 硬编码凭据提取 + 危险函数扫描 + Ghidra 反编译（可选） |
| **0-day 变种挖掘** | 已知漏洞图谱遍历 + LLM 语义改写，推理未知变种 |
| **自定义规则** | 自然语言规则 + 表单管理，持续"喂"漏洞挖掘方法，越用越强 |
| **POC + 沙箱验证** | 自动生成 POC + 沙箱执行验证 + 攻击链路示意图 |
| **自动修复** | 生成 patch + 等价性回归保障 |

## 🏗️ 架构

```
ai-vuln-hunter/
├── schemas/          JSON Schema 契约基线（9 个 schema + 校验）
├── orchestrator/     编排大脑（核心）
│   ├── engine.js        10 状态机 + 6 Agent
│   ├── agents/          LLM 自主挖掘 / C/C++ 调用图 / Java 反编译 / 二进制分析 / 0-day / 验证 / 修复 / 学习
│   ├── llm/             LLM 抽象（Mock / GLM 可插拔 + 分层路由）
│   ├── sandbox/         POC 沙箱（Mock / Docker 强隔离）
│   ├── repository/      持久化（内存 / Postgres+Neo4j 可切换 + 降级）
│   └── mcp-server.js    统一 MCP Server（编排 + 工具接入 8 个 tool）
├── vuln-db/          多源漏洞库（NVD / OSV / CAPEC / Nuclei）
├── web/              HTTP 服务 + React 前端
│   ├── server/          Express API + JWT 认证 + Prometheus 指标
│   └── frontend/        React + Vite（暗/亮主题 + 代码高亮 + 攻击链路图）
├── migrations/       版本化数据库迁移
└── mcp-server/       工具接入层（软安 SAST/SCA/BAT 适配器）
```

## 🚀 快速开始

### 前置要求
- Node.js 18+（推荐 20+）
- Python 3.8+（仅 schema 校验用）

### 启动

```bash
# 1. 构建前端
cd web/frontend
npm install
npm run build

# 2. 启动后端
cd ../server
npm install
node app.js

# 3. 打开浏览器
# http://localhost:3000
```

### 开发模式（前后端分离热重载）

```bash
# 终端 1：后端
cd web/server && npm install && node app.js

# 终端 2：前端（自动代理 /api 到 3000）
cd web/frontend && npm install && npm run dev
# http://localhost:5173
```

## 📖 使用方式

### 1. 扫描任务页
- **上传文件**（推荐）：拖拽 `.zip`（源码包）/ `.jar` / `.bin` → 自动解压 → 开始挖掘
- **指定路径**：填本地源码目录
- **粘贴代码**：直接粘贴代码片段

### 2. 任务管理页
查看所有扫描任务，按任务查看漏洞（漏洞按任务隔离）

### 3. 漏洞清单页
每个漏洞的详情包含 5 个 tab：
- **📋 概览**：可利用性评估 + 影响评估 + 攻击场景
- **🔗 攻击链路**：SVG 攻击路径示意图（攻击者→入口→载荷→漏洞点→验证→影响）
- **📍 代码定位**：带行号的代码块，漏洞行红色高亮
- **⚔️ POC 与验证**：沙箱验证过程 + 原始响应 + POC 结构化描述
- **🔧 修复**：修复策略 + 修复后代码（可复制）

### 4. 规则配置页
- 查看内置规则（9 条，可禁用不可删）
- **创建自定义规则**：描述"什么代码有什么漏洞"，LLM 扫描时按你的规则挖掘

### 5. 引擎状态页
- 误报库 / 图谱 / 规则数 / Finding 统计
- 漏洞库 4 源同步状态 + 一键同步

## ⚙️ 配置

### LLM 切换（默认 Mock，零依赖）

```bash
# 默认 Mock（本地即跑，无需 API key）
node app.js

# 真实 GLM
set LLM_MODE=glm
set GLM_API_KEY=你的智谱API Key
node app.js

# 私有化部署
set GLM_BASE_URL=https://你的GLM地址/api/paas/v4
```

### 外部工具（可选增强）

| 工具 | 环境变量 | 作用 |
|---|---|---|
| CFR | `JAVA_BIN` + `CFR_JAR` | Java 二进制反编译 |
| Ghidra | `GHIDRA_HOME` | C/C++ 二进制反编译 |

### 数据库（默认内存，可选持久化）

```bash
set DB_MODE=postgres+neo4j
set DATABASE_URL=postgres://user:pass@host:5432/db
set NEO4J_URL=bolt://localhost:7687
```

### 认证（默认关闭）

```bash
set AUTH_ENABLED=1
set JWT_SECRET=your-secret
```

## 🐳 Docker 部署

```bash
cd web

# 单容器（默认内存存储）
docker compose up -d

# 含数据库（Postgres + Neo4j）
DB_MODE=postgres+neo4j docker compose --profile db up -d

# 访问 http://localhost:3000
```

## 🔌 MCP 接入

编排引擎可通过 MCP 协议接入 LLM 客户端（ZCode / Claude Desktop）：

```json
{
  "mcpServers": {
    "ai-vuln-hunter": {
      "command": "node",
      "args": ["C:/path/to/orchestrator/mcp-server.js"]
    }
  }
}
```

8 个 tool：`orchestrate_run` / `orchestrate_status` / `orchestrate_findings` / `ruanan_sast_*` / `validate_output`

## 📊 智能路由

系统自动识别输入类型，路由到对应挖掘通道：

```
用户输入
  ├─ .c/.h/.cpp 源码    → C/C++ 调用图 + 资源流追踪
  ├─ .jar/.class        → Java 反编译 + LLM 分析
  ├─ .bin/.elf/.exe     → 硬编码提取 + 危险函数扫描 + Ghidra（可选）
  ├─ .zip 源码包        → 解压 + 自动识别语言
  └─ 其他源码           → 通用 LLM 自主挖掘（业务逻辑）
```

## 🧪 测试

```bash
# 全量测试（10 套）
cd schemas && python validate_schemas.py        # schema 契约
cd orchestrator && node test-orchestrator.js    # 编排引擎
cd orchestrator && node test-mcp.js             # MCP 协议
cd orchestrator && node test-c-callgraph.js     # C/C++ 调用图
cd orchestrator && node test-c-hunter.js        # C/C++ 跨函数挖掘
cd orchestrator && node test-java-binary.js     # Java 二进制
cd orchestrator && node test-binary-hunter.js   # C/C++ 二进制
cd vuln-db && node test-connectors.js           # 漏洞库
cd web/server && node test-api.js               # HTTP API
cd web/server && node test-auth.js              # JWT 认证
```

## 🛠️ 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Node.js + Express |
| 前端 | React 18 + Vite + React Router |
| LLM | GLM-5.2（可插拔，默认 Mock） |
| 持久化 | 内存 / Postgres（JSONB） / Neo4j（图谱） |
| 认证 | JWT（bcrypt + access/refresh token） |
| 可观测性 | Prometheus（prom-client） + pino 结构化日志 |
| 契约 | JSON Schema Draft 2020-12（ajv 校验） |
| 二进制 | 纯 JS（ELF/PE 解析） + Ghidra（可选） |
| 部署 | Docker + docker-compose |

## 📄 License

ISC
