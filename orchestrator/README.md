# orchestrator/ — 编排大脑（M + N + O 升级版）

以状态机驱动多类 Agent 协同，把工具结果、规则、知识库、LLM、沙箱串成完整闭环。

> 本轮升级：M（编排+工具 MCP 合并）/ N（持久化层 + 全 async）/ O（JWT 认证）

---

## 1. 目录结构（升级后）

```
orchestrator/
├── engine.js                 编排核心（10 状态机 + stores 工厂接入）
├── state-machine.js          状态定义
├── context.js                任务上下文
├── config.js                 配置
├── mcp-server.js             ★ M：统一 MCP（8 个 tool：3 编排 + 5 工具接入）
├── llm/                      LLM 抽象（mock/glm 可插拔）
├── agents/                   6 类 Agent（dispatcher/detector/verifier/fixer/learner/zero-day-hunter）
├── memory/                   内存存储（全 async 化 + KnowledgeGraph 接口增强）
├── rules/rule-engine.js      规则引擎（async）
├── sandbox/                  POC 沙箱（mock/docker/auto）
├── repository/               ★ N：DB 适配器
│   ├── factory.js              存储工厂（DB_MODE + 降级）
│   ├── pg-finding-store.js     Postgres FindingStore
│   ├── pg-fp-store.js          Postgres 误报库
│   ├── pg-rule-store.js        Postgres 规则引擎
│   ├── neo4j-knowledge-graph.js Neo4j 知识图谱
│   └── schema.sql              Postgres 建表语句（含 users 表）
├── test-orchestrator.js      端到端测试（18/18）
└── test-mcp.js               统一 MCP 测试（14/14）
```

## 2. M：统一 MCP（编排 + 工具接入合并）

LLM 客户端只需接入一个 stdio MCP server，即可调全部 8 个 tool：

| 类别 | tool |
|---|---|
| 编排（3） | orchestrate_run / orchestrate_status / orchestrate_findings |
| 工具接入（5） | ruanan_sast_scan / status / results / info / validate_output |

```json
// MCP 客户端配置
{ "mcpServers": { "ai-vuln-hunter": {
    "command": "node",
    "args": ["C:\\...\\orchestrator\\mcp-server.js"]
} } }
```

## 3. N：持久化层

### 全 async 化
4 个 store（Finding/KnowledgeGraph/FalsePositive/RuleEngine）所有方法变 async，
调用点（6 agent + engine + 3 路由 + connector）全加 await。**接口与内存版一致，可无感替换。**

### KnowledgeGraph 接口增强
新增显式方法替换对 `nodes`/`edges` 的直接属性访问（DB 版可无感替换）：
`getNode(id)` / `hasNode(id)` / `listNodes()` / `listEdges()` / `setNodeField(id,field,value)`

### DB 适配器（repository/）
| Store | 内存版 | DB 版 |
|---|---|---|
| FindingStore | memory/finding-store.js | repository/pg-finding-store.js（JSONB） |
| KnowledgeGraph | memory/knowledge-graph.js | repository/neo4j-knowledge-graph.js（Cypher） |
| FalsePositiveStore | memory/false-positive-store.js | repository/pg-fp-store.js |
| RuleEngine | rules/rule-engine.js | repository/pg-rule-store.js |

### 工厂 + 优雅降级
```bash
# 默认：内存（零依赖）
DB_MODE=memory

# 生产：Postgres + Neo4j（不可用时各自独立降级到内存）
DB_MODE=postgres+neo4j
DATABASE_URL=postgres://user:pass@host:5432/db
NEO4J_URL=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=xxx
```

建表：`psql -d yourdb -f orchestrator/repository/schema.sql`

## 4. 测试

```bash
cd orchestrator
node test-orchestrator.js    # 18/18（10 状态 + 6 Agent + 沙箱 + 0-day）
node test-mcp.js             # 14/14（8 个 MCP tool）
```
