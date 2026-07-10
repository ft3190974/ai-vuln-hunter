# AI 漏洞挖掘应用 · MCP Server

基于 `schemas/` 契约实现的工具接入层 MCP Server。当前以**软安 SAST（静兮）接入**为示例，
演示完整的"工具接入 → 结果归一化 → schema 校验 → MCP 暴露"数据流，可在本地直接跑通。

> 配套契约：`../schemas/`（README 见 `../schemas/README.md`）
> 配套设计：`桌面/AI漏洞挖掘应用设计方案V2.docx` 第三章 工具接入层

---

## 1. 目录结构

```
mcp-server/
├── server.js                  # MCP Server（注册 tools，stdio 传输）
├── ruanan-sast-adapter.js     # 软安 SAST 适配器（mock，真实接入时替换）
├── validator.js               # schema 校验模块（基于 ajv，跨文件 $ref）
├── test-client.js             # 端到端测试客户端
├── package.json
└── README.md                  # 本文件
```

## 2. 快速开始

```bash
cd mcp-server
npm install            # 已装可跳过

# 方式一：跑端到端测试（自动验证全链路）
npm test
# 等价于 node test-client.js

# 方式二：仅启动 server（供 MCP 客户端连接）
npm start
# 等价于 node server.js
```

测试通过会看到：5 个 tools 注册 → 扫描任务流转 → 结果符合 schema → 校验拦截非法数据。

## 3. 已注册的 MCP Tools

| Tool 名 | 功能 | 输入 |
|---|---|---|
| `ruanan_sast_scan` | 提交软安 SAST 扫描任务，返回 jobId | scan-request 结构 |
| `ruanan_sast_status` | 查询任务状态（running/completed/failed/cancelled） | jobId |
| `ruanan_sast_results` | 获取归一化结果（**返回前做 schema 校验**） | jobId |
| `ruanan_sast_info` | 查询工具能力声明（对应 tool-adapter.schema.json） | 无 |
| `validate_output` | 通用 schema 校验（任何工具输出/finding/rule 都可校验） | schemaFile + data |

## 4. 在 MCP 客户端中接入（如 ZCode / Claude Desktop）

在客户端的 MCP 配置文件中加入：

```json
{
  "mcpServers": {
    "ai-vuln-hunter": {
      "command": "node",
      "args": [
        "C:\\Users\\常乐\\ZCodeProject\\ai-vuln-hunter\\mcp-server\\server.js"
      ]
    }
  }
}
```

接入后，LLM 即可通过这些 tools 调用软安 SAST 能力，所有结果严格符合契约。

## 5. 真实接入软安工具的方式

当前 `ruanan-sast-adapter.js` 是 mock 实现（返回构造好的示例数据）。
真实接入时**只改这一个文件**，把内部逻辑替换为对软安 SAST 实际 API/CLI 的调用：

```js
// 当前（mock）
function getResults(jobId) {
  return buildMockResults(scanRequest);   // ← 构造的示例数据
}

// 真实接入（替换为）
function getResults(jobId) {
  const rawReport = callRuananSastApi(jobId);   // 调软安 SAST 真实 API
  return normalizeToSchema(rawReport);          // 转成 sast-output.schema.json 结构
}
```

**对外接口（scan/getStatus/getResults/cancel）和 MCP tools 都不用改**，上层零改动 —— 这就是适配器模式的价值。

## 6. 关键设计：双重 schema 校验

数据合规性有两道防线：

1. **server 内部校验**（`ruanan_sast_results` 返回前）—— 工具输出先过 `validator.js`，不符合 schema 直接报错，不让脏数据流出。
2. **客户端独立校验**（`validate_output` tool）—— 任何调用方都可对任意数据做独立校验，不信任 server。

这保证了契约的**强制执行**，而非"文档约束"。

## 7. 扩展：接入更多工具

新增一个工具（如软安 SCA、BAT）只需 3 步：

1. 复制 `ruanan-sast-adapter.js` → `ruanan-sca-adapter.js`，改实现 + ADAPTER_INFO
2. 在 `server.js` 的 `TOOLS` 数组加对应的 tool 定义
3. 在 `CallTool` 分发里加 case

无需改 `validator.js`（已自动加载所有 schema），无需改客户端。

## 8. 测试结果（参考）

```
[✓] 5 个 MCP tools 全部注册并可调用
[✓] 扫描任务异步流转正常（submit → poll → completed）
[✓] 结果严格符合 sast-output.schema.json 契约
[✓] snippet 代码片段与 dataFlow 污点流正确返回
[✓] validate_output 能正确识别合法/非法数据
```
