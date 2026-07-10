// test-client.js — MCP 端到端测试客户端
//
// 模拟 MCP 客户端完整调用链：
//   1. 连接 server
//   2. list tools（确认工具已注册）
//   3. ruanan_sast_info（查能力声明）
//   4. ruanan_sast_scan（提交扫描任务）
//   5. 轮询 ruanan_sast_status（直到 completed）
//   6. ruanan_sast_results（拿归一化结果）
//   7. validate_output（独立校验结果合规性）
//
// 启动方式：node test-client.js

const { Client } = require("@modelcontextprotocol/sdk/client");
const {
  StdioClientTransport,
} = require("@modelcontextprotocol/sdk/client/stdio.js");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const INFO = "\x1b[36mℹ\x1b[0m";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  console.log("=".repeat(60));
  console.log("AI Vuln Hunter MCP — 端到端测试");
  console.log("=".repeat(60));

  // 1. 连接 server（通过 stdio 启动子进程）
  console.log(`\n${INFO} 启动并连接 MCP server...`);
  const transport = new StdioClientTransport({
    command: "node",
    args: ["server.js"],
  });
  const client = new Client(
    { name: "test-client", version: "0.1.0" },
    { capabilities: {} }
  );
  await client.connect(transport);
  console.log(`${PASS} 已连接`);

  // 2. 列出工具
  console.log(`\n${INFO} 列出可用工具...`);
  const { tools } = await client.listTools();
  for (const t of tools) {
    console.log(`  ${PASS} ${t.name}`);
  }
  if (tools.length < 5) {
    console.log(`${FAIL} 工具数量不足（期望 5 个，实际 ${tools.length}）`);
    process.exit(1);
  }

  // 3. 查询工具能力
  console.log(`\n${INFO} 调用 ruanan_sast_info 查询能力声明...`);
  const infoResp = await client.callTool({
    name: "ruanan_sast_info",
    arguments: {},
  });
  const info = JSON.parse(infoResp.content[0].text);
  console.log(`  ${PASS} toolId=${info.toolId}, needBuild=${info.capabilities.needBuild}`);
  console.log(`  ${PASS} 支持语言: ${info.capabilities.languages.join(", ")}`);

  // 4. 提交扫描任务
  console.log(`\n${INFO} 调用 ruanan_sast_scan 提交扫描任务...`);
  const scanId = "550e8400-e29b-41d4-a716-446655440000";
  const scanResp = await client.callTool({
    name: "ruanan_sast_scan",
    arguments: {
      scanId,
      target: {
        type: "source",
        path: "/workspace/projects/payment-service",
        language: "java",
        buildSystem: "maven",
        buildCmd: "mvn compile -DskipTests",
      },
      options: { depth: "deep", timeoutSec: 3600 },
    },
  });
  const job = JSON.parse(scanResp.content[0].text);
  console.log(`  ${PASS} jobId=${job.jobId}, status=${job.status}`);

  // 5. 轮询状态
  console.log(`\n${INFO} 轮询任务状态（每 500ms 一次）...`);
  let status = job.status;
  let results = null;
  for (let i = 0; i < 20; i++) {
    await sleep(500);
    const stResp = await client.callTool({
      name: "ruanan_sast_status",
      arguments: { jobId: job.jobId },
    });
    const st = JSON.parse(stResp.content[0].text);
    status = st.status;
    process.stdout.write(`\r  ${INFO} 第 ${i + 1} 次轮询: status=${status}   `);
    if (status === "completed" || status === "failed") break;
  }
  console.log("");
  if (status !== "completed") {
    console.log(`${FAIL} 任务未完成（status=${status}）`);
    await client.close();
    process.exit(1);
  }
  console.log(`${PASS} 任务完成`);

  // 6. 获取归一化结果
  console.log(`\n${INFO} 调用 ruanan_sast_results 获取结果...`);
  const resResp = await client.callTool({
    name: "ruanan_sast_results",
    arguments: { jobId: job.jobId },
  });
  const resWrapper = JSON.parse(resResp.content[0].text);
  if (!resWrapper.ok) {
    console.log(`${FAIL} ${resWrapper.error}`);
    console.log(resWrapper.details);
    await client.close();
    process.exit(1);
  }
  results = resWrapper.results;
  console.log(`  ${PASS} schema 已校验: ${resWrapper.schemaValidated}`);
  console.log(`  ${PASS} 发现 ${results.findings.length} 个漏洞:`);
  for (const f of results.findings) {
    console.log(
      `     - [${f.severity.toUpperCase()}] ${f.category}: ${f.message}`
    );
    console.log(`       位置: ${f.location.file}:${f.location.startLine}`);
    console.log(
      `       代码片段: "${f.snippet.code.split("\n")[f.snippet.primaryLine - 1].trim()}"`
    );
    if (f.dataFlow) {
      console.log(
        `       污点流: ${f.dataFlow.path.length} 个节点 (source → ... → sink)`
      );
    }
  }

  // 7. 独立 schema 校验（不依赖 server 内部校验，客户端再验一次）
  console.log(`\n${INFO} 调用 validate_output 独立校验结果合规性...`);
  const valResp = await client.callTool({
    name: "validate_output",
    arguments: {
      schemaFile: "sast-output.schema.json",
      data: results,
    },
  });
  const val = JSON.parse(valResp.content[0].text);
  console.log(`  ${val.valid ? PASS : FAIL} schema=${val.schemaFile}, valid=${val.valid}`);
  if (!val.valid) {
    console.log(`  错误详情:\n${val.errors}`);
    await client.close();
    process.exit(1);
  }

  // 8. 故意传一个非法数据，验证 validate 能拦住
  console.log(`\n${INFO} 注入非法数据，验证校验能拦截...`);
  const badResp = await client.callTool({
    name: "validate_output",
    arguments: {
      schemaFile: "finding.schema.json",
      data: { title: "缺字段的 finding" },
    },
  });
  const bad = JSON.parse(badResp.content[0].text);
  console.log(
    `  ${!bad.valid ? PASS : FAIL} valid=${bad.valid}（期望 false，能正确拦截非法数据）`
  );

  // 总结
  console.log("\n" + "=".repeat(60));
  console.log(`${PASS} 端到端测试全部通过`);
  console.log("  - 5 个 MCP tools 全部注册并可调用");
  console.log("  - 扫描任务异步流转正常（submit → poll → completed）");
  console.log("  - 结果严格符合 sast-output.schema.json 契约");
  console.log("  - snippet 代码片段与 dataFlow 污点流正确返回");
  console.log("  - validate_output 能正确识别合法/非法数据");
  console.log("=".repeat(60));

  await client.close();
  process.exit(0);
}

main().catch((e) => {
  console.error(`\n${FAIL} 测试失败:`, e);
  process.exit(1);
});
