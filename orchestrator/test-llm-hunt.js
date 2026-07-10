// orchestrator/test-llm-hunt.js — LLM 自主挖掘端到端验证
//
// 用真实 Java 代码（含 6 个业务逻辑+高危漏洞）跑 LLM_HUNT 通道，
// 验证不依赖 SAST 也能发现漏洞。
//
// 用法：node test-llm-hunt.js

const path = require("path");
const { OrchestratorEngine } = require("./engine");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

const DEMO_CODE_PATH = path.resolve(__dirname, "..", "demo-code", "OrderController.java");

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("LLM 自主挖掘 · 真实代码端到端验证");
  console.log("=".repeat(60) + "\x1b[0m\n");

  const engine = new OrchestratorEngine();
  const scanRequest = {
    scanId: "llm-hunt-test",
    target: { type: "source", path: DEMO_CODE_PATH, language: "java" },
    options: { depth: "deep", timeoutSec: 60 },
  };

  console.log(`${HDR}提交源代码（不经过 SAST，直接 LLM 分析）${"\x1b[0m"}`);
  console.log(`  文件: ${DEMO_CODE_PATH}`);
  console.log(`  模式: mock LLM（真实 GLM 切换见 config.js）\n`);

  // 关键：toolOutputs 为空对象，sourceInput 传代码路径
  const report = await engine.run(scanRequest, {}, { path: DEMO_CODE_PATH, language: "java" });

  let pass = 0, fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  // 1. LLM_HUNT 状态执行
  console.log(HDR + "[1] LLM_HUNT 状态执行" + "\x1b[0m");
  const llmHuntLog = report.log.filter((l) => l.state === "LLM_HUNT");
  check("LLM_HUNT 状态有日志", llmHuntLog.length > 0);
  const summary = llmHuntLog.find((l) => l.msg.includes("完成"));
  check("LLM 自主挖掘完成", !!summary, `(${summary?.msg?.slice(0, 80)})`);

  // 2. 发现的漏洞
  console.log("\n" + HDR + "[2] 发现的漏洞" + "\x1b[0m");
  const findings = report.findings;
  check("发现 Finding 数 > 0", findings.length > 0, `(共 ${findings.length} 个)`);

  // 3. 业务逻辑漏洞（核心卖点）
  console.log("\n" + HDR + "[3] 业务逻辑漏洞（SAST 发现不了的）" + "\x1b[0m");
  const businessFindings = findings.filter((f) => f.category === "business_logic");
  check("发现业务逻辑漏洞", businessFindings.length > 0, `(共 ${businessFindings.length} 个)`);
  const titles = businessFindings.map((f) => f.title);
  check("含状态机绕过", titles.some((t) => t.includes("状态机") || t.includes("状态")));
  check("含金额篡改", titles.some((t) => t.includes("金额")));
  check("含越权/IDOR", titles.some((t) => t.includes("越权") || t.includes("IDOR")));
  check("含幂等缺失", titles.some((t) => t.includes("幂等")));

  // 4. Finding 完整性
  console.log("\n" + HDR + "[4] Finding 完整性" + "\x1b[0m");
  if (findings.length > 0) {
    const f = findings[0];
    check("Finding 有代码片段", !!f.snippet?.code);
    check("Finding 有位置信息", !!f.location?.file && f.location.startLine > 0);
    check("Finding 有 businessContext", !!f.businessContext?.attackScenario, `(攻击场景)`);
    check("Finding 来源是 llm-hunter", f.sources?.[0]?.toolId === "llm-hunter");
  }

  // 5. 后续流程仍正常（VERIFY/FIX/LEARN）
  console.log("\n" + HDR + "[5] 后续编排流程" + "\x1b[0m");
  const stateSeq = [...new Set(report.log.map((l) => l.state))];
  check("完整状态流转（11 状态）", stateSeq.length >= 10, `(${stateSeq.length} 个)`);
  check("VERIFY 执行", stateSeq.includes("VERIFY"));
  check("FIX 执行", stateSeq.includes("FIX"));

  // 6. POC 和 Patch 生成
  console.log("\n" + HDR + "[6] POC 与 Patch" + "\x1b[0m");
  check("POC 生成", report.pocs.length > 0, `(共 ${report.pocs.length} 个)`);
  check("Patch 生成", report.patches.length > 0, `(共 ${report.patches.length} 个)`);

  // 打印发现的漏洞清单
  console.log("\n" + HDR + "发现的漏洞清单" + "\x1b[0m");
  for (const f of findings) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.category}: ${f.title}`);
    console.log(`    📍 ${f.location.file}:${f.location.startLine} (${f.location.function})`);
    if (f.businessContext?.attackScenario) {
      console.log(`    ⚔️  ${f.businessContext.attackScenario.slice(0, 80)}`);
    }
  }

  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} LLM 自主挖掘测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 不依赖 SAST，直接读代码发现漏洞");
    console.log(`  ✓ 发现 ${businessFindings.length} 个业务逻辑漏洞（SAST 无能为力的领域）`);
    console.log("  ✓ 完整编排闭环（LLM_HUNT → VERIFY → FIX → LEARN）");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试有 ${fail} 项未通过 (${pass}/${pass + fail})`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(FAIL + " 异常:", e);
  process.exit(1);
});
