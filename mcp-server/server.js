// server.js — AI 漏洞挖掘应用 · MCP Server
//
// 把工具接入层的接口注册为 MCP tools，供 MCP 客户端（如 ZCode / Claude Desktop）
// 通过标准 MCP 协议调用。
//
// 当前注册的 tools（基于 schemas/ 契约）：
//   1. ruanan_sast_scan      提交软安 SAST 扫描任务
//   2. ruanan_sast_status    查询任务状态
//   3. ruanan_sast_results   获取归一化结果（schema 校验后返回）
//   4. ruanan_sast_info      查询工具能力声明（对应 tool-adapter.schema.json）
//   5. validate_output       通用 schema 校验工具（任何工具的输出都可校验）
//
// 传输方式：stdio（标准 MCP 启动方式）

const { Server } = require("@modelcontextprotocol/sdk/server");
const {
  StdioServerTransport,
} = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");

const adapter = require("./ruanan-sast-adapter");
const { validate, formatErrors } = require("./validator");

// ── Tool 定义（输入 schema 来自 schemas/*.schema.json 的精简版）──
const TOOLS = [
  {
    name: "ruanan_sast_scan",
    description:
      "提交软安 SAST 静兮扫描任务。传入符合 scan-request 契约的请求，返回 jobId。任务异步执行，稍后用 ruanan_sast_status 轮询。",
    inputSchema: {
      type: "object",
      properties: {
        scanId: { type: "string", description: "UUID 任务 ID" },
        target: {
          type: "object",
          properties: {
            type: { type: "string", enum: ["source", "binary"] },
            path: { type: "string", description: "目标本地路径" },
            language: { type: "string", description: "源码语言，如 java" },
            buildSystem: { type: "string", description: "构建系统，如 maven" },
            buildCmd: { type: "string", description: "构建命令" },
          },
          required: ["type", "path"],
        },
        options: {
          type: "object",
          properties: {
            depth: { type: "string", enum: ["fast", "normal", "deep"] },
            timeoutSec: { type: "integer" },
          },
        },
      },
      required: ["scanId", "target"],
    },
  },
  {
    name: "ruanan_sast_status",
    description: "查询软安 SAST 任务状态（running/completed/failed/cancelled）。",
    inputSchema: {
      type: "object",
      properties: { jobId: { type: "string" } },
      required: ["jobId"],
    },
  },
  {
    name: "ruanan_sast_results",
    description:
      "获取软安 SAST 归一化扫描结果。返回结构严格符合 sast-output.schema.json，含 findings + snippet(代码片段) + dataFlow(污点流)。",
    inputSchema: {
      type: "object",
      properties: { jobId: { type: "string" } },
      required: ["jobId"],
    },
  },
  {
    name: "ruanan_sast_info",
    description: "查询软安 SAST 工具能力声明（对应 tool-adapter.schema.json）。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "validate_output",
    description:
      "通用 schema 校验工具。任何工具输出（sca/sast/bat-output 等）或 finding/rule 对象，都可指定 schema 文件名校验是否合规。",
    inputSchema: {
      type: "object",
      properties: {
        schemaFile: {
          type: "string",
          description: "schema 文件名，如 sast-output.schema.json / finding.schema.json",
          enum: [
            "finding.schema.json",
            "sca-output.schema.json",
            "sast-output.schema.json",
            "bat-output.schema.json",
            "scan-request.schema.json",
            "rule.schema.json",
            "code-snippet.schema.json",
            "tool-adapter.schema.json",
          ],
        },
        data: { type: "object", description: "待校验的数据对象" },
      },
      required: ["schemaFile", "data"],
    },
  },
];

// ── MCP Server 实例 ──
const server = new Server(
  { name: "ai-vuln-hunter-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

// ListTools：返回工具清单
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

// CallTool：分发到对应处理函数
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let result;
    switch (name) {
      case "ruanan_sast_scan": {
        result = adapter.scan(args);
        break;
      }
      case "ruanan_sast_status": {
        result = adapter.getStatus(args.jobId);
        break;
      }
      case "ruanan_sast_results": {
        const raw = adapter.getResults(args.jobId);
        if (raw.error) {
          result = raw;
          break;
        }
        // ★ 关键：返回前做 schema 校验，确保契约一致性
        const { valid, errors } = validate("sast-output.schema.json", raw);
        result = valid
          ? { ok: true, schemaValidated: true, results: raw }
          : {
              ok: false,
              error: "工具输出不符合 sast-output.schema.json 契约",
              details: formatErrors(errors),
              raw,
            };
        break;
      }
      case "ruanan_sast_info": {
        result = adapter.ADAPTER_INFO;
        break;
      }
      case "validate_output": {
        const { valid, errors } = validate(args.schemaFile, args.data);
        result = {
          schemaFile: args.schemaFile,
          valid,
          errors: valid ? null : formatErrors(errors),
        };
        break;
      }
      default:
        throw new Error(`未知工具: ${name}`);
    }
    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  } catch (e) {
    return {
      content: [{ type: "text", text: `工具执行错误: ${e.message}` }],
      isError: true,
    };
  }
});

// ── 启动 ──
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[ai-vuln-hunter-mcp] server 已启动，监听 stdio");
}

main().catch((e) => {
  console.error("[fatal]", e);
  process.exit(1);
});
