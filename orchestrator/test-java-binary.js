// orchestrator/test-java-binary.js — Java 二进制反编译分析验证
//
// 验证 .jar 输入能反编译（mock）+ 走 LLM 分析 + 发现漏洞

const { OrchestratorEngine } = require("./engine");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("Java 二进制反编译分析 · 端到端验证");
  console.log("=".repeat(60) + "\x1b[0m\n");

  const engine = new OrchestratorEngine();
  const scanRequest = {
    scanId: "java-bin-test",
    target: { type: "source", path: "(binary)", language: "java" },
    options: { depth: "deep", timeoutSec: 60 },
  };

  console.log(`${HDR}提交 .jar 文件（mock 反编译 + LLM 分析）${"\x1b[0m"}\n`);

  // 模拟 .jar 输入（实际路径不存在，但 mock 会返回构造的反编译代码）
  const report = await engine.run(scanRequest, {}, {
    path: "demo.jar",
    file: "demo.jar",
    language: "java",
  });

  let pass = 0, fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  console.log(HDR + "[1] 反编译执行" + "\x1b[0m");
  const decompileLog = report.log.find((l) => l.state === "LLM_HUNT" && l.msg.includes("反编译"));
  check("反编译触发", !!decompileLog, `(${decompileLog?.msg?.slice(0, 60) || "无日志"})`);

  console.log("\n" + HDR + "[2] 漏洞发现" + "\x1b[0m");
  const findings = report.findings;
  check("发现 Finding", findings.length > 0, `(${findings.length} 个)`);
  const titles = findings.map((f) => f.title + " " + f.description);
  check("发现 SQL 注入", titles.some((t) => t.includes("SQL") || t.includes("sql")));
  check("完整编排", [...new Set(report.log.map((l) => l.state))].length >= 10);
  check("POC 生成", report.pocs.length > 0, `(${report.pocs.length} 个)`);

  console.log("\n" + HDR + "发现的漏洞" + "\x1b[0m");
  for (const f of findings.slice(0, 5)) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.title}`);
    console.log(`    📍 ${f.location.file}:${f.location.startLine} (${f.location.function})`);
  }

  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} Java 二进制测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ .jar 反编译（mock）→ 切片 → LLM 分析");
    console.log("  ✓ 发现反编译代码中的漏洞");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试失败 (${pass}/${pass + fail})`);
    process.exit(1);
  }
}

main().catch((e) => { console.error(FAIL + " 异常:", e); process.exit(1); });
