// orchestrator/test-mcp.js — 统一 MCP server 端到端测试
//
// 验证合并后的 8 个 tool（3 编排 + 5 工具接入）：
//   1. listTools 返回 8 个
//   2. 工具接入链路：ruanan_sast_scan → status → results（含 schema 校验）
//   3. 编排链路：orchestrate_run → status → findings
//   4. validate_output 拦截非法数据
//
// 用法：node test-mcp.js

const { Client } = require("@modelcontextprotocol/sdk/client");
const {
  StdioClientTransport,
} = require("@modelcontextprotocol/sdk/client/stdio.js");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const INFO = "\x1b[36mℹ\x1b[0m";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const scanRequest = {
  scanId: "mcp-test-001",
  target: { type: "source", path: "/demo", language: "java" },
  options: { depth: "deep", timeoutSec: 60 },
};
const toolOutputs = {
  sast: {
    toolId: "ruanan-sast",
    scanId: "mcp-test-001",
    scannedAt: "2026-07-07T10:00:00Z",
    findings: [
      {
        ruleId: "RA-SQLI-001",
        category: "sqli",
        severity: "critical",
        message: "SQL 拼接注入",
        location: { file: "Login.java", startLine: 10, endLine: 10, function: "login" },
        snippet: {
          code: 'String sql = "SELECT * FROM u WHERE n=\'" + name + "\'";\nstmt.execute(sql);',
          language: "java",
          primaryLine: 1, startLine: 9, endLine: 10, contextType: "function",
        },
        confidence: 0.9,
      },
    ],
  },
};

async function main() {
  console.log("=".repeat(60));
  console.log("统一 MCP server（编排 + 工具接入）· 端到端测试");
  console.log("=".repeat(60));

  const transport = new StdioClientTransport({ command: "node", args: ["mcp-server.js"] });
  const client = new Client({ name: "test", version: "0.1.0" }, { capabilities: {} });
  await client.connect(transport);
  console.log(`${PASS} 已连接统一 MCP server\n`);

  let pass = 0, fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  // 1. listTools 返回 8 个
  console.log(`${INFO} [1] 列出工具`);
  const { tools } = await client.listTools();
  const toolNames = tools.map((t) => t.name);
  console.log(`  工具: ${toolNames.join(", ")}`);
  check("注册 8 个 tool", tools.length === 8, `(${tools.length} 个)`);
  check("含 3 个编排 tool", ["orchestrate_run", "orchestrate_status", "orchestrate_findings"].every((n) => toolNames.includes(n)));
  check("含 5 个工具接入 tool", ["ruanan_sast_scan", "ruanan_sast_status", "ruanan_sast_results", "ruanan_sast_info", "validate_output"].every((n) => toolNames.includes(n)));

  // 2. 工具接入链路
  console.log(`\n${INFO} [2] 工具接入链路（ruanan_sast_*）`);
  const infoResp = await client.callTool({ name: "ruanan_sast_info", arguments: {} });
  const info = JSON.parse(infoResp.content[0].text);
  check("ruanan_sast_info 返回能力声明", info.toolId === "ruanan-sast");

  const scanResp = await client.callTool({
    name: "ruanan_sast_scan",
    arguments: {
      scanId: "tool-test-001",
      target: { type: "source", path: "/demo", language: "java" },
    },
  });
  const job = JSON.parse(scanResp.content[0].text);
  check("ruanan_sast_scan 返回 jobId", !!job.jobId);

  // 轮询状态
  let status = "running";
  for (let i = 0; i < 20; i++) {
    await sleep(200);
    const stResp = await client.callTool({ name: "ruanan_sast_status", arguments: { jobId: job.jobId } });
    status = JSON.parse(stResp.content[0].text).status;
    if (status !== "running") break;
  }
  check("ruanan_sast_status 完成", status === "completed", `(status=${status})`);

  const resResp = await client.callTool({ name: "ruanan_sast_results", arguments: { jobId: job.jobId } });
  const resWrapper = JSON.parse(resResp.content[0].text);
  check("ruanan_sast_results schema 校验通过", resWrapper.ok === true && resWrapper.schemaValidated === true);
  check("结果含 snippet", !!resWrapper.results.findings[0].snippet);

  // 3. 编排链路
  console.log(`\n${INFO} [3] 编排链路（orchestrate_*）`);
  const runResp = await client.callTool({
    name: "orchestrate_run",
    arguments: { scanRequest, toolOutputs },
  });
  const report = JSON.parse(runResp.content[0].text);
  check("orchestrate_run 完成", report.current === "REPORT");
  check("报告含 findings", report.findings.length > 0, `(${report.findings.length} 个)`);

  const stResp = await client.callTool({ name: "orchestrate_status", arguments: {} });
  const statusData = JSON.parse(stResp.content[0].text);
  check("orchestrate_status 返回引擎状态", typeof statusData.fpPatterns === "number");

  const fResp = await client.callTool({
    name: "orchestrate_findings",
    arguments: { status: "fixed" },
  });
  const findings = JSON.parse(fResp.content[0].text);
  check("orchestrate_findings 按状态过滤", Array.isArray(findings));

  // 4. validate_output
  console.log(`\n${INFO} [4] validate_output`);
  const validResp = await client.callTool({
    name: "validate_output",
    arguments: { schemaFile: "sast-output.schema.json", data: resWrapper.results },
  });
  const valid = JSON.parse(validResp.content[0].text);
  check("合法数据校验通过", valid.valid === true);

  const badResp = await client.callTool({
    name: "validate_output",
    arguments: { schemaFile: "finding.schema.json", data: { title: "缺字段" } },
  });
  const bad = JSON.parse(badResp.content[0].text);
  check("非法数据被拦截", bad.valid === false);

  await client.close();
  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} 统一 MCP 测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 8 个 tool 全部注册（3 编排 + 5 工具接入）");
    console.log("  ✓ 工具接入完整链路（scan → status → results + schema 校验）");
    console.log("  ✓ 编排完整链路（run → status → findings）");
    console.log("  ✓ validate_output 拦截非法数据");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试有 ${fail} 项未通过 (${pass} 通过 / ${fail} 失败)`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(FAIL + " 测试失败:", e);
  process.exit(1);
});
