// orchestrator/test-c-callgraph.js — C/C++ AST 解析 + 调用图测试
//
// 用 leak_example.c 验证：
//   1. 正确提取函数定义（8 个函数）
//   2. 正确提取函数调用（main 调 process_leak 等）
//   3. 正确提取资源操作（malloc/free/fopen/fclose）
//   4. 调用图能查到调用关系

const path = require("path");
const fs = require("fs");
const { parseFile } = require("./agents/c-ast-parser");
const { CallGraph } = require("./agents/call-graph");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

const C_FILE = path.resolve(__dirname, "..", "demo-code", "leak_example.c");

let pass = 0, fail = 0;
const check = (name, cond, detail = "") => {
  if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
  else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
};

function main() {
  console.log(HDR + "=".repeat(60));
  console.log("C/C++ AST 解析 + 调用图测试");
  console.log("=".repeat(60) + "\x1b[0m\n");

  const content = fs.readFileSync(C_FILE, "utf-8");
  const parsed = parseFile(C_FILE, content);

  console.log(HDR + "[1] 函数定义提取" + "\x1b[0m");
  console.log(`  共 ${parsed.functions.length} 个函数:`);
  for (const f of parsed.functions) {
    console.log(`    - ${f.name} (行 ${f.line}-${f.bodyEnd})`);
  }
  const funcNames = parsed.functions.map((f) => f.name);
  check("提取函数数 ≥ 8", parsed.functions.length >= 8, `(${parsed.functions.length} 个)`);
  check("含 read_input", funcNames.includes("read_input"));
  check("含 process_leak", funcNames.includes("process_leak"));
  check("含 main", funcNames.includes("main"));
  check("含 double_free_bug", funcNames.includes("double_free_bug"));

  console.log("\n" + HDR + "[2] 函数调用提取" + "\x1b[0m");
  console.log(`  共 ${parsed.calls.length} 个调用关系`);
  // main 应该调用了 process_leak 和 process_ok
  const mainCallees = parsed.calls.filter((c) => c.caller === "main").map((c) => c.callee);
  console.log(`  main 调用了: ${mainCallees.join(", ")}`);
  check("main 调用 process_leak", mainCallees.includes("process_leak"));
  check("main 调用 process_ok", mainCallees.includes("process_ok"));
  // process_leak 应该调用了 read_input
  const leakCallees = parsed.calls.filter((c) => c.caller === "process_leak").map((c) => c.callee);
  check("process_leak 调用 read_input", leakCallees.includes("read_input"));

  console.log("\n" + HDR + "[3] 资源操作提取" + "\x1b[0m");
  const acquires = parsed.resources.filter((r) => r.type === "acquire");
  const releases = parsed.resources.filter((r) => r.type === "release");
  console.log(`  acquire: ${acquires.length} 处, release: ${releases.length} 处`);
  for (const a of acquires.slice(0, 5)) {
    console.log(`    [acquire] ${a.resource}/${a.func} in ${a.function}:${a.line} — ${a.code.slice(0, 50)}`);
  }
  for (const r of releases.slice(0, 5)) {
    console.log(`    [release] ${r.resource}/${r.func} in ${r.function}:${r.line} — ${r.code.slice(0, 50)}`);
  }
  check("提取到 malloc acquire", acquires.some((a) => a.func === "malloc"));
  check("提取到 free release", releases.some((r) => r.func === "free"));
  check("提取到 fopen acquire", acquires.some((a) => a.func === "fopen"));
  check("提取到 fclose release", releases.some((r) => r.func === "fclose"));

  console.log("\n" + HDR + "[4] 调用图构建与查询" + "\x1b[0m");
  const cg = new CallGraph();
  cg.buildFromParsed(parsed);
  console.log(`  图节点: ${cg.stats().functions}, 边: ${cg.stats().calls}`);

  // read_input 的调用者应该包含 process_leak 和 process_ok
  const readInputCallers = cg.getCallers("read_input").map((c) => c.caller);
  console.log(`  read_input 的调用者: ${readInputCallers.join(", ")}`);
  check("read_input 被 process_leak 调用", readInputCallers.includes("process_leak"));
  check("read_input 被 process_ok 调用", readInputCallers.includes("process_ok"));

  // main 到 read_input 的调用链
  const chain = cg.getCallChain("main", "read_input");
  console.log(`  main → read_input 调用链: ${chain ? chain.join(" → ") : "不可达"}`);
  check("main 到 read_input 可达", chain !== null && chain.length >= 2);

  // serialize 输出
  console.log("\n" + HDR + "[5] serialize（给 LLM 的调用上下文）" + "\x1b[0m");
  const serialized = cg.serialize("read_input");
  console.log(serialized);
  check("serialize 含上游信息", serialized.includes("上游") || serialized.includes("调用"));
  check("serialize 含下游信息", serialized.includes("下游") || serialized.includes("调用"));

  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} C/C++ 调用图测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 函数定义提取（8+ 函数）");
    console.log("  ✓ 跨函数调用关系");
    console.log("  ✓ 资源操作（malloc/free/fopen/fclose）");
    console.log("  ✓ 调用图查询（getCallers/getCallChain/serialize）");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试失败 (${pass}/${pass + fail})`);
    process.exit(1);
  }
}

main();
