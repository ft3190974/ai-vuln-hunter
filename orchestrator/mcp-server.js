// orchestrator/mcp-server.js — 统一 MCP Server（编排 + 工具接入）
//
// 把编排引擎（大脑）和工具接入层（扫描器）合并到同一个 stdio MCP server，
// LLM 客户端只需接入这一个 server，即可：
//   - 调工具（ruanan_sast_*）拿原始扫描结果
//   - 调编排（orchestrate_*）做深度判定/验证/修复/学习
//   - 用 validate_output 校验任何数据是否符合 schema 契约
//
// 合并后 mcp-server/server.js 仍保留作独立工具接入层（adapter/validator 是共享代码）。

const { Server } = require("@modelcontextprotocol/sdk/server");
const {
  StdioServerTransport,
} = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");

const { OrchestratorEngine } = require("./engine");
const { resetLlm } = require("./llm");
const { createStores } = require("./repository/factory");

// 工具接入层共享代码（跨目录 require，dispatcher.js 已验证可行）
const adapter = require("../mcp-server/ruanan-sast-adapter");
const { validate, formatErrors } = require("../mcp-server/validator");

// 单例引擎（按 DB_MODE 自动选存储实现；DB 不可用降级内存）
let engine;
async function getEngine() {
  if (!engine) {
    const stores = await createStores(process.env.DB_MODE || "memory");
    engine = new OrchestratorEngine({ stores });
    console.error(`[ai-vuln-hunter-mcp] 存储模式: ${stores.mode}`);
  }
  return engine;
}

// ── 统一 Tool 清单（8 个：3 编排 + 5 工具接入）──
const TOOLS = [
  // ── 编排类（大脑）──
  {
    name: "orchestrate_run",
    description:
      "触发一次完整的漏洞挖掘编排。输入 ScanRequest + 各工具的归一化输出（SAST/SCA/BAT），" +
      "引擎自动跑完 INIT→FILTER→DISPATCH→DETECT→RAG_MATCH→ZERO_DAY→VERIFY→FIX→LEARN→REPORT 十个状态，" +
      "返回完整报告（Findings + POCs + Patches + 学习建议）。",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["scanRequest", "toolOutputs"],
      properties: {
        scanRequest: {
          type: "object",
          description: "符合 scan-request.schema.json 的扫描请求",
          properties: {
            scanId: { type: "string" },
            target: {
              type: "object",
              properties: {
                type: { type: "string", enum: ["source", "binary"] },
                path: { type: "string" },
                language: { type: "string" },
                buildSystem: { type: "string" },
              },
            },
            options: {
              type: "object",
              properties: {
                depth: { type: "string", enum: ["fast", "normal", "deep"] },
                timeoutSec: { type: "integer" },
              },
            },
          },
        },
        toolOutputs: {
          type: "object",
          description: "各工具的归一化输出，key 为工具类型（sast/sca/bat）",
          properties: {
            sast: { type: "object", description: "符合 sast-output.schema.json" },
            sca: { type: "object", description: "符合 sca-output.schema.json" },
            bat: { type: "object", description: "符合 bat-output.schema.json" },
          },
        },
      },
    },
  },
  {
    name: "orchestrate_status",
    description:
      "查询编排引擎内部状态：误报库模式数、知识图谱节点/边数、规则数、Finding 存储统计。",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "orchestrate_findings",
    description: "查询已编排出的 Finding 列表，支持按状态/类别过滤。",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        status: {
          type: "string",
          enum: ["candidate", "confirmed", "false_positive", "fixed", "wont_fix"],
          description: "按状态过滤（空则返回全部）",
        },
        category: { type: "string", description: "按漏洞类别过滤" },
      },
    },
  },

  // ── 工具接入类（扫描器）──
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
            path: { type: "string" },
            language: { type: "string" },
            buildSystem: { type: "string" },
            buildCmd: { type: "string" },
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
      "获取软安 SAST 归一化扫描结果。返回结构严格符合 sast-output.schema.json，含 findings + snippet + dataFlow。返回前自动做 schema 校验。",
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
      "通用 schema 校验工具。任何工具输出或 finding/rule 对象，指定 schema 文件名校验是否合规。",
    inputSchema: {
      type: "object",
      properties: {
        schemaFile: {
          type: "string",
          description: "schema 文件名",
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

const server = new Server(
  { name: "ai-vuln-hunter-mcp", version: "0.3.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const engine = await getEngine();
    let result;
    switch (name) {
      // ── 编排类 ──
      case "orchestrate_run": {
        resetLlm();
        result = await engine.run(args.scanRequest, args.toolOutputs);
        break;
      }
      case "orchestrate_status": {
        result = await engine.inspect();
        break;
      }
      case "orchestrate_findings": {
        result = await engine.findingStore.query({
          status: args.status,
          category: args.category,
        });
        break;
      }

      // ── 工具接入类 ──
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

async function main() {
  // 预热引擎（触发 factory 探测存储模式，启动时就打印模式日志）
  await getEngine();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[ai-vuln-hunter-mcp] 统一 MCP server 已启动（编排 + 工具），监听 stdio");
}

module.exports = { getEngine, TOOLS };

if (require.main === module) {
  main().catch((e) => {
    console.error("[fatal]", e);
    process.exit(1);
  });
}
