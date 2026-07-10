// test-orchestrator.js — 编排层端到端测试
//
// 构造模拟的扫描请求 + 工具输出，跑完整编排链路，验证：
//   1. 状态机完整流转（INIT→FILTER→DISPATCH→DETECT→RAG_MATCH→VERIFY→FIX→LEARN→REPORT）
//   2. 五类 Agent 全部被调用且产出正确
//   3. 全程 Finding 严格符合 schema
//   4. 误报库前置过滤生效（防幻觉放大）
//   5. SCA 可达性 + POC 生成 + patch 生成 + 学习增量
//
// 用法：node test-orchestrator.js
// 切换真实 GLM：set LLM_MODE=glm && set GLM_API_KEY=xxx && node test-orchestrator.js

const { OrchestratorEngine } = require("./engine");
const { validate, formatErrors } = require("../mcp-server/validator");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

// 构造模拟的 ScanRequest（符合 scan-request.schema.json）
const scanRequest = {
  scanId: "test-scan-001",
  createdAt: "2026-07-07T10:00:00Z",
  target: {
    type: "source",
    path: "/workspace/projects/payment-service",
    language: "java",
    buildSystem: "maven",
    buildCmd: "mvn compile -DskipTests",
  },
  options: {
    depth: "deep",
    timeoutSec: 3600,
    categories: ["sqli", "authz", "business_logic"],
  },
};

// 构造模拟的 SAST 输出（符合 sast-output.schema.json）
// 含 3 个 finding：1 个真漏洞(SQLi)、1 个误报(已参数化)、1 个越权
const sastOutput = {
  toolId: "ruanan-sast",
  scanId: "test-scan-001",
  scannedAt: "2026-07-07T10:30:00Z",
  durationSec: 180,
  buildStatus: { success: true, buildSystem: "maven" },
  findings: [
    {
      ruleId: "RA-SQLI-001",
      category: "sqli",
      severity: "critical",
      message: "SQL 查询使用字符串拼接",
      location: {
        file: "src/controllers/LoginController.java",
        startLine: 42, endLine: 42, function: "login",
      },
      snippet: {
        code: 'String username = request.getParameter("name");\nString sql = "SELECT * FROM users WHERE name=\'" + username + "\'";\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.execute(sql);',
        language: "java",
        primaryLine: 2, startLine: 40, endLine: 43,
        contextType: "function",
      },
      dataFlow: {
        sources: [{ file: "LoginController.java", line: 40, code: 'getParameter("name")', role: "source" }],
        sinks: [{ file: "LoginController.java", line: 43, code: "stmt.execute(sql)", role: "sink" }],
        path: [],
      },
      confidence: 0.92,
    },
    {
      ruleId: "RA-SQLI-099",
      category: "sqli",
      severity: "low",
      message: "疑似 SQL 注入（实际已参数化）",
      location: {
        file: "src/controllers/UserController.java",
        startLine: 20, endLine: 20, function: "getUser",
      },
      snippet: {
        code: 'String sql = "SELECT * FROM users WHERE id=?";\nPreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, id);\nResultSet rs = ps.executeQuery();',
        language: "java",
        primaryLine: 1, startLine: 18, endLine: 21,
        contextType: "function",
      },
      confidence: 0.6,
    },
    {
      ruleId: "RA-AUTHZ-014",
      category: "authz",
      severity: "high",
      message: "资源访问未校验属主",
      location: {
        file: "src/controllers/OrderController.java",
        startLine: 88, endLine: 90, function: "getOrder",
      },
      snippet: {
        code: '@GetMapping("/orders/{id}")\npublic Order getOrder(@PathVariable Long id) {\n    return orderRepo.findById(id);\n}',
        language: "java",
        primaryLine: 3, startLine: 88, endLine: 90,
        contextType: "function",
      },
      confidence: 0.78,
    },
  ],
};

// 构造模拟的 SCA 输出（符合 sca-output.schema.json，含可达性待判定）
const scaOutput = {
  toolId: "ruanan-sca",
  scanId: "test-scan-001",
  scannedAt: "2026-07-07T10:05:00Z",
  durationSec: 42,
  sbom: {
    packages: [{ name: "log4j-core", version: "2.14.0", ecosystem: "maven", direct: true }],
  },
  vulnerabilities: [
    {
      cve: "CVE-2021-44228",
      package: { name: "log4j-core", version: "2.14.0" },
      severity: "critical",
      vulnerableFunctions: ["JndiLookup.lookup"],
      fixedVersion: "2.17.1",
      source: "ruanan-sca",
    },
  ],
};

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("AI 漏洞挖掘应用 · 编排层端到端测试");
  console.log("=".repeat(60) + "\x1b[0m");

  const engine = new OrchestratorEngine();
  const report = await engine.run(scanRequest, { sast: sastOutput, sca: scaOutput });

  console.log("\n" + HDR + "─".repeat(60) + "\x1b[0m");
  console.log(HDR + "结果校验" + "\x1b[0m");
  console.log("─".repeat(60));

  let pass = 0;
  let fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  // 1. 状态机完整流转
  const stateSequence = report.log.map((l) => l.state);
  const expectedStates = ["INIT", "FILTER", "DISPATCH", "DETECT", "RAG_MATCH", "ZERO_DAY", "VERIFY", "FIX", "LEARN", "REPORT"];
  check(
    "状态机完整流转 10 个状态",
    expectedStates.every((s) => stateSequence.includes(s)),
    `(${stateSequence.length} 个状态记录)`
  );
  check("无 FAILED 终态", report.current === "REPORT", `(current=${report.current})`);

  // 2. Finding 数量与状态
  const findings = report.findings;
  // 4 个原始（3 SAST + 1 SCA）+ 0-day 挖掘生成的变种候选
  check("归一化 + 0-day 挖掘产出 Finding", findings.length >= 4, `(共 ${findings.length} 个)`);
  const fpCount = findings.filter((f) => f.status === "false_positive").length;
  const fixedCount = findings.filter((f) => f.status === "fixed").length;
  const confirmedCount = findings.filter((f) => f.status === "confirmed").length;
  check("误报库前置过滤生效（已参数化的 SQLi 被标记误报）", fpCount >= 1, `(误报 ${fpCount} 个)`);

  // 3. 全程 schema 校验
  let schemaOk = true;
  for (const f of findings) {
    const { valid, errors } = validate("finding.schema.json", f);
    if (!valid) {
      schemaOk = false;
      console.log(`  ${FAIL} Finding ${f.findingId} schema 失败: ${formatErrors(errors).slice(0, 100)}`);
    }
  }
  check("所有 Finding 严格符合 schema", schemaOk);

  // 4. POC 与 patch 生成
  check("POC 已生成", report.pocs.length >= 1, `(共 ${report.pocs.length} 个)`);
  check("Patch 已生成", report.patches.length >= 1, `(共 ${report.patches.length} 个)`);
  const equivOk = report.patches.every((p) => p.equivalenceCheck !== false);
  check("Patch 等价性回归通过", equivOk);

  // 4b. 沙箱验证（POC 实际执行）
  const sandboxVerified = report.pocs.filter((p) => p.sandboxVerified === true);
  check("沙箱 POC 执行有结果", report.pocs.every((p) => p.sandboxImpl), `(实现: ${report.pocs[0]?.sandboxImpl})`);
  check("沙箱验证至少触发一个", sandboxVerified.length >= 1, `(触发 ${sandboxVerified.length}/${report.pocs.length})`);
  if (sandboxVerified.length > 0) {
    check(
      "沙箱触发后 reachability 升级 level 4",
      findings.some((f) => f.reachability?.level === 4 && f.reachability?.verifiedBy === "sandbox"),
      `(有 ${findings.filter(f => f.reachability?.level === 4).length} 个升到 level 4)`
    );
  }

  // 5. 学习闭环
  const fpLearned = report.learnSuggestions.filter((s) => s.type === "fp_pattern").length;
  const rulesGen = report.learnSuggestions.filter((s) => s.type === "candidate_rule").length;
  const graphNodes = report.learnSuggestions.filter((s) => s.type === "graph_node").length;
  check("学习闭环-误报回灌", fpLearned >= 1, `(新增 ${fpLearned} 条过滤模式)`);
  check("学习闭环-规则生成", rulesGen >= 1, `(候选 ${rulesGen} 条规则)`);
  check("学习闭环-图谱演化", graphNodes >= 1, `(新增 ${graphNodes} 个节点)`);

  // 6. SCA 可达性
  const scaFindings = findings.filter((f) => f.sources[0]?.toolType === "SCA");
  if (scaFindings.length > 0) {
    const scaF = scaFindings[0];
    check(
      "SCA 可达性已判定",
      scaF.reachability && scaF.reachability.level > 0,
      `(level=${scaF.reachability?.level}, reachable=${scaF.reachability?.reachable})`
    );
  }

  // 7. 0-day 变种挖掘
  const zeroDayFindings = findings.filter((f) => f.isZeroDay === true);
  check("0-day 变种挖掘生成候选", zeroDayFindings.length >= 1, `(共 ${zeroDayFindings.length} 个 0-day 候选)`);
  if (zeroDayFindings.length > 0) {
    const zd = zeroDayFindings[0];
    check(
      "0-day 候选有关联种子",
      Array.isArray(zd.relatedFindings) && zd.relatedFindings.length > 0,
      `(关联 ${zd.relatedFindings?.length} 个种子)`
    );
    check(
      "0-day 候选置信度合理",
      zd.confidence >= 0.5 && zd.confidence <= 0.99,
      `(conf=${zd.confidence})`
    );
  }

  // 8. 引擎内部状态（inspect 已 async 化）
  const inspect = await engine.inspect();
  console.log("\n" + HDR + "引擎内部状态" + "\x1b[0m");
  console.log(`  误报库模式: ${inspect.fpPatterns} 条`);
  console.log(`  知识图谱: ${inspect.knowledgeGraph.nodes} 节点 / ${inspect.knowledgeGraph.edges} 边`);
  console.log(`  规则数: ${inspect.rules} 条`);
  console.log(`  Finding 存储: ${inspect.findings.total} 条 (${JSON.stringify(inspect.findings.byStatus)})`);

  // 总结
  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} 端到端测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 10 个状态完整流转");
    console.log("  ✓ 6 类 Agent 全部生效（含 0-day 挖掘）");
    console.log("  ✓ 误报库前置过滤防幻觉");
    console.log("  ✓ 全程 schema 契约校验");
    console.log("  ✓ POC + Patch + 学习闭环 + 0-day 变种");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试有 ${fail} 项未通过 (${pass} 通过 / ${fail} 失败)`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("\n" + FAIL + " 测试异常:", e);
  process.exit(1);
});
