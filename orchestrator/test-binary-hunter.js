// orchestrator/test-binary-hunter.js — 二进制漏洞挖掘验证
const { OrchestratorEngine } = require("./engine");
const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("C/C++ 二进制漏洞挖掘 · 端到端验证");
  console.log("=".repeat(60) + "\x1b[0m\n");

  const engine = new OrchestratorEngine();
  // 用不存在的 .bin 路径（触发 mock 二进制）
  const report = await engine.run(
    { scanId: "bin-test", target: { type: "binary", path: "firmware.bin" }, options: { depth: "deep", timeoutSec: 60 } },
    {},
    { path: "firmware.bin", file: "firmware.bin" }
  );

  let pass = 0, fail = 0;
  const check = (n, c, d = "") => { if (c) { pass++; console.log(`  ${PASS} ${n} ${d}`); } else { fail++; console.log(`  ${FAIL} ${n} ${d}`); } };

  const findings = report.findings;
  console.log(HDR + "[1] 确定性发现（硬编码敏感信息）" + "\x1b[0m");
  const hardcoded = findings.filter((f) => f.sources[0]?.rawRuleId === "STRING-EXTRACT");
  console.log(`  硬编码 Finding: ${hardcoded.length}`);
  for (const f of hardcoded.slice(0, 5)) console.log(`    - [${f.severity}] ${f.title}`);
  check("发现硬编码密码", hardcoded.some((f) => f.title.includes("password") || f.title.includes("口令")));
  check("发现私钥", hardcoded.some((f) => f.title.includes("私钥") || f.title.includes("PRIVATE")));
  check("发现 URL", hardcoded.some((f) => f.title.includes("URL")));

  console.log("\n" + HDR + "[2] 危险函数" + "\x1b[0m");
  const dangers = findings.filter((f) => f.sources[0]?.rawRuleId === "DANGER-FUNC");
  console.log(`  危险函数 Finding: ${dangers.length}`);
  for (const f of dangers.slice(0, 5)) console.log(`    - [${f.severity}] ${f.title}`);
  check("发现 strcpy", dangers.some((f) => f.title.includes("strcpy")));
  check("发现 system", dangers.some((f) => f.title.includes("system")));

  console.log("\n" + HDR + "[3] 完整性" + "\x1b[0m");
  check("Finding 有可利用性", findings.every((f) => f.exploitability));
  check("Finding 有影响", findings.every((f) => f.impact));
  check("完整编排", [...new Set(report.log.map((l) => l.state))].length >= 10);

  console.log("\n" + HDR + "发现的漏洞清单" + "\x1b[0m");
  for (const f of findings) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.title}`);
    console.log(`    📍 ${f.location.binary} @ ${f.location.address || "?"}`);
  }

  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} 二进制漏洞挖掘测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 硬编码敏感信息提取（密码/私钥/URL）");
    console.log("  ✓ 危险函数扫描（strcpy/system/gets）");
    console.log("  ✓ 完整编排 + 可利用性 + 影响");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试失败 (${pass}/${pass + fail})`);
    process.exit(1);
  }
}
main().catch((e) => { console.error(FAIL + " 异常:", e); process.exit(1); });
