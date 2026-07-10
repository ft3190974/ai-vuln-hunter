// orchestrator/test-c-hunter.js — C/C++ 端到端漏洞挖掘验证
//
// 用 leak_example.c 验证 c-hunter 能发现：
//   1. 确定性发现：内存泄漏 / double-free / 跨函数泄漏
//   2. LLM 发现：缓冲区溢出 / 格式化字符串 / 命令注入
//   3. 完整编排闭环（VERIFY/FIX/LEARN）

const path = require("path");
const { OrchestratorEngine } = require("./engine");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

const C_FILE = path.resolve(__dirname, "..", "demo-code", "leak_example.c");
const fs = require("fs");
const code = fs.readFileSync(C_FILE, "utf-8");

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("C/C++ 跨函数漏洞挖掘 · 端到端验证");
  console.log("=".repeat(60) + "\x1b[0m\n");

  const engine = new OrchestratorEngine();
  const scanRequest = {
    scanId: "c-hunt-test",
    target: { type: "source", path: C_FILE, language: "auto" },
    options: { depth: "deep", timeoutSec: 60 },
  };

  console.log(`${HDR}提交 C 代码（含跨函数泄漏 + double-free + 栈溢出）${"\x1b[0m"}`);
  console.log(`  文件: leak_example.c\n`);

  const report = await engine.run(scanRequest, {}, { code, file: "leak_example.c", language: "c" });

  let pass = 0, fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  console.log(HDR + "[1] 确定性发现（资源流分析，不需 LLM）" + "\x1b[0m");
  const findings = report.findings;
  const certainFindings = findings.filter((f) => f.sources[0]?.rawRuleId === "RESOURCE-FLOW");
  console.log(`  确定性 Finding 数: ${certainFindings.length}`);
  for (const f of certainFindings) {
    console.log(`    - [${f.severity}] ${f.title} (${f.location.startLine})`);
  }
  check("发现内存泄漏", certainFindings.some((f) => f.title.includes("泄漏") && !f.title.includes("跨函数")));
  check("发现 double-free", certainFindings.some((f) => f.title.includes("Double-Free")));
  check("发现跨函数泄漏", certainFindings.some((f) => f.title.includes("跨函数")));

  console.log("\n" + HDR + "[2] LLM 发现（语义判定）" + "\x1b[0m");
  const llmFindings = findings.filter((f) => f.sources[0]?.rawRuleId?.startsWith("C-"));
  console.log(`  LLM Finding 数: ${llmFindings.length}`);
  for (const f of llmFindings.slice(0, 5)) {
    console.log(`    - [${f.severity}] ${f.title} (${f.location.startLine})`);
  }
  check("LLM 发现漏洞", llmFindings.length > 0, `(${llmFindings.length} 个)`);

  const titles = findings.map((f) => f.title + " " + f.description);
  check("含缓冲区溢出", titles.some((t) => t.includes("strcpy") || t.includes("栈溢出") || t.includes("gets")));
  check("含命令注入", titles.some((t) => t.includes("命令") || t.includes("system")));

  console.log("\n" + HDR + "[3] Finding 完整性" + "\x1b[0m");
  if (findings.length > 0) {
    const f = findings[0];
    check("有可利用性", !!f.exploitability?.difficulty);
    check("有影响", !!f.impact?.worstCase);
    check("有定位", !!f.location?.startLine);
    check("有完整上下文", !!f.fullContext);
  }

  console.log("\n" + HDR + "[4] 完整编排" + "\x1b[0m");
  const states = [...new Set(report.log.map((l) => l.state))];
  check("完整状态流转", states.length >= 10, `(${states.length} 个状态)`);
  check("VERIFY 执行", states.includes("VERIFY"));
  check("FIX 执行", states.includes("FIX"));
  check("POC 生成", report.pocs.length > 0, `(${report.pocs.length} 个)`);
  check("Patch 生成", report.patches.length > 0, `(${report.patches.length} 个)`);

  console.log("\n" + HDR + "发现的漏洞清单" + "\x1b[0m");
  for (const f of findings) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.category}: ${f.title}`);
    console.log(`    📍 ${f.location.function || "?"} 行 ${f.location.startLine}`);
    if (f.sources[0]?.rawRuleId === "RESOURCE-FLOW") {
      console.log(`    🔒 确定性发现（资源流追踪）`);
    }
  }

  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} C/C++ 跨函数挖掘测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 资源流分析（泄漏/double-free/跨函数，确定性发现）");
    console.log("  ✓ LLM 语义判定（栈溢出/命令注入）");
    console.log("  ✓ 完整编排闭环 + POC + Patch");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试失败 (${pass}/${pass + fail})`);
    process.exit(1);
  }
}

main().catch((e) => { console.error(FAIL + " 异常:", e); process.exit(1); });
