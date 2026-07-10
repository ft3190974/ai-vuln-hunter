// agents/resource-flow.js — 资源生命周期追踪（零依赖）
//
// 基于 c-ast-parser 的输出，追踪资源的 acquire → release 生命周期，
// 发现"acquire 了但某些路径没 release"的泄漏/UAF/double-free 候选。
//
// 这是 C/C++ 跨函数漏洞挖掘的核心——LLM 看不懂跨函数资源流，
// 但本模块能预先算出来"哪里泄漏了"，把结论喂给 LLM 做语义确认。
//
// 三类发现：
//   1. 泄漏：函数内有 acquire 但无 release（或某分支无 release）
//   2. Double-free：同一资源在同一函数内被 release 两次
//   3. 跨函数泄漏：函数 A acquire，通过返回值/参数传给 B，B 没 release

/**
 * 分析单个函数内的资源生命周期
 * @param {Array} resources  该函数的资源操作（来自 c-ast-parser）
 * @param {object} funcMeta  函数元信息 {name, body, returnLine, ...}
 * @returns {{leaks, doubleFrees, missingOnPath}}
 */
function analyzeFunction(resources, funcMeta) {
  const leaks = [];
  const doubleFrees = [];
  const missingOnPath = [];

  // 按资源类型分组
  const byType = {};
  for (const r of resources) {
    if (!byType[r.resource]) byType[r.resource] = [];
    byType[r.resource].push(r);
  }

  for (const [resType, ops] of Object.entries(byType)) {
    const acquires = ops.filter((o) => o.type === "acquire");
    const releases = ops.filter((o) => o.type === "release");

    // Double-free：同一函数内 release 次数 > acquire 次数
    if (releases.length > acquires.length && acquires.length > 0) {
      doubleFrees.push({
        type: "double_free",
        resource: resType,
        function: funcMeta.name,
        line: releases[releases.length - 1].line,
        detail: `${funcMeta.name} 内 ${resType} acquire ${acquires.length} 次但 release ${releases.length} 次，疑似 double-free`,
        code: releases[releases.length - 1].code,
      });
    }

    // 泄漏：有 acquire 但无 release
    if (acquires.length > 0 && releases.length === 0) {
      // 检查是否通过 return 把资源传出（调用者负责释放——这是正常模式，不是泄漏）
      const returnsResource = checkReturnsResource(funcMeta, acquires);
      if (!returnsResource) {
        leaks.push({
          type: "leak",
          resource: resType,
          function: funcMeta.name,
          line: acquires[0].line,
          detail: `${funcMeta.name} 内 acquire ${resType}（${acquires[0].func}）但无 release，疑似内存泄漏`,
          code: acquires[0].code,
        });
      }
    }
  }

  return { leaks, doubleFrees, missingOnPath };
}

/**
 * 检查函数是否通过 return 把资源传出（合法的所有权转移）
 * 简化：看 return 语句是否返回了 acquire 的变量
 */
function checkReturnsResource(funcMeta, acquires) {
  if (!funcMeta || !funcMeta.body) return false;
  // 从 acquire 操作提取变量名
  const acquiredVars = new Set();
  for (const a of acquires) {
    // 从 code 提取左值：`char* buf = (char*)malloc(...)` → buf
    const m = a.code.match(/=\s*\(?[^=]*\b(?:malloc|calloc|realloc|fopen|new)\b/);
    if (m) {
      const lhs = a.code.split("=")[0].trim().replace(/.*\s+/, "").replace(/[\*]/g, "");
      if (lhs) acquiredVars.add(lhs);
    }
  }
  // 检查 body 里是否有 return 这些变量
  const returnLines = funcMeta.body.split("\n").filter((l) => /^\s*return\b/.test(l));
  for (const rl of returnLines) {
    for (const v of acquiredVars) {
      if (rl.includes(v)) return true;
    }
  }
  return false;
}

/**
 * 跨函数泄漏分析
 * 场景：函数 A acquire 后 return 给调用者 B，但 B 没 release
 *
 * @param {Array} allResources  所有函数的资源操作
 * @param {object} callGraph    调用图（查调用关系）
 * @param {Array} allFuncs      所有函数元信息
 */
function analyzeCrossFunction(allResources, callGraph, allFuncs) {
  const crossLeaks = [];

  // 找"acquire 后 return 出去"的函数（资源所有权转移点）
  const transferPoints = [];
  for (const fn of allFuncs) {
    const fnResources = allResources.filter((r) => r.function === fn.name);
    const acquires = fnResources.filter((r) => r.type === "acquire");
    for (const a of acquires) {
      if (checkReturnsResource(fn, [a])) {
        transferPoints.push({ from: fn.name, resource: a.resource, line: a.line });
      }
    }
  }

  // 对每个转移点，检查调用者是否 release 了
  for (const tp of transferPoints) {
    const callers = callGraph.getCallers(tp.from);
    if (callers.length === 0) continue;

    for (const caller of callers) {
      const callerResources = allResources.filter((r) => r.function === caller.caller);
      const releases = callerResources.filter((r) => r.type === "release" && r.resource === tp.resource);
      if (releases.length === 0) {
        crossLeaks.push({
          type: "cross_function_leak",
          resource: tp.resource,
          function: caller.caller,
          callee: tp.from,
          line: caller.line,
          detail: `${caller.caller} 调用 ${tp.from}（acquire ${tp.resource} 于行 ${tp.line}）但未 release，跨函数内存泄漏`,
        });
      }
    }
  }

  return crossLeaks;
}

/**
 * 综合分析入口
 */
function analyzeAll(parsed, callGraph, allFuncs) {
  const allResults = { leaks: [], doubleFrees: [], crossFunctionLeaks: [] };

  // 单函数分析
  const funcNames = new Set(parsed.resources.map((r) => r.function));
  for (const fn of funcNames) {
    const fnResources = parsed.resources.filter((r) => r.function === fn);
    const funcMeta = allFuncs.find((f) => f.name === fn);
    const r = analyzeFunction(fnResources, funcMeta);
    allResults.leaks.push(...r.leaks);
    allResults.doubleFrees.push(...r.doubleFrees);
  }

  // 跨函数分析
  allResults.crossFunctionLeaks = analyzeCrossFunction(parsed.resources, callGraph, allFuncs);

  return allResults;
}

module.exports = { analyzeFunction, analyzeCrossFunction, analyzeAll, checkReturnsResource };
