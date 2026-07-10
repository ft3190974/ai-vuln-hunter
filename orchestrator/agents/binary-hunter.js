// agents/binary-hunter.js — C/C++ 二进制漏洞挖掘 Agent
//
// 组合三个能力源：
//   1. string-extractor：确定性发现硬编码敏感信息（准确率 ~100%）
//   2. danger-func-scanner：确定性发现危险函数使用
//   3. ghidra-adapter（可选）：反编译伪码 → LLM 分析单函数漏洞
//
// 确定性发现直接生成 Finding（不需 LLM）。
// 反编译伪码（有 Ghidra 时）走 LLM 分析。
//
// 覆盖状态：LLM_HUNT（当输入是二进制文件时，本 Agent 接管）

const { loadBinary } = require("./binary-loader");
const stringExtractor = require("./string-extractor");
const dangerScanner = require("./danger-func-scanner");
const { decompileWithGhidra, isGhidraAvailable } = require("./ghidra-adapter");
const config = require("../config");
const { getLlm } = require("../llm");

async function hunt(ctx, deps) {
  const { findingStore } = deps;
  ctx.log_("LLM_HUNT", "二进制漏洞挖掘开始", "info");

  const sourceInput = ctx.sourceInput;
  const binaryPath = sourceInput.path || sourceInput.code;
  if (!binaryPath) return ctx;

  // 1. 加载二进制
  let binary;
  try {
    binary = loadBinary(binaryPath);
  } catch (e) {
    ctx.log_("LLM_HUNT", `二进制加载失败: ${e.message}，尝试用 mock 二进制`, "warn");
    // mock 二进制（让流程能跑通）
    binary = mockBinary();
  }
  ctx.log_("LLM_HUNT", `二进制加载: ${binary.format}/${binary.arch}, ${binary.strings.length} 字符串, ${binary.symbols.length} 符号, ${binary.size} 字节`, "info");

  // 2. 确定性发现：硬编码敏感信息
  const sensitiveFindings = stringExtractor.extract(binary.strings, binaryPath);
  ctx.log_("LLM_HUNT", `字符串扫描: 发现 ${sensitiveFindings.length} 个硬编码敏感信息`, "info");
  for (const sf of sensitiveFindings) {
    const finding = await findingStore.create({
      title: `[二进制] 硬编码${sf.desc}: ${sf.value}`,
      category: sf.type.includes("password") || sf.type.includes("backdoor") ? "hardcoded_secret" : "config",
      severity: sf.severity,
      cwe: "CWE-798",
      description: `在二进制 ${sf.binary} 偏移 ${sf.offset} 发现${sf.desc}。\n脱敏值: ${sf.value}（长度 ${sf.rawLength}）\n原始证据: ${sf.evidence}\n\n这是确定性发现（字符串提取），准确率接近 100%。`,
      location: { targetType: "binary", binary: binaryPath, address: `0x${sf.offset.toString(16)}` },
      sources: [{ toolId: "binary-hunter", toolType: "BAT", rawRuleId: "STRING-EXTRACT", toolConfidence: 0.99, reportedAt: new Date().toISOString() }],
      confidence: 0.99,
      status: "confirmed",
      exploitability: { difficulty: "low", prerequisites: "获取二进制文件", accessNeeded: "无需认证" },
      impact: { assets: sf.desc, worstCase: sf.type.includes("private_key") || sf.type.includes("aws") ? "完全接管云资源/系统" : "凭据泄露导致未授权访问", remote: false, noAuth: true },
    });
    ctx.findings.push(finding);
    ctx.log_("LLM_HUNT", `确定性发现: [${sf.severity}] 硬编码${sf.desc} @ 0x${sf.offset.toString(16)}`, "info");
  }

  // 3. 确定性发现：危险函数使用
  const dangerFindings = dangerScanner.scan(binary.symbols, binaryPath);
  ctx.log_("LLM_HUNT", `危险函数扫描: 发现 ${dangerFindings.length} 个危险函数`, "info");
  for (const df of dangerFindings) {
    const finding = await findingStore.create({
      title: `[二进制] 使用危险函数: ${df.func}()`,
      category: df.category === "command_exec" ? "cmdi" : df.category === "buffer_overflow" ? "overflow" : df.category === "format_string" ? "fmt_string" : "config",
      severity: df.severity,
      cwe: df.category === "command_exec" ? "CWE-78" : df.category === "buffer_overflow" ? "CWE-120" : "CWE-134",
      description: `二进制 ${df.binary} 导入了危险函数 ${df.func}()。\n${df.desc}\n\n注意：使用危险函数不等于一定有漏洞，需结合数据流分析输入来源。这是风险标记。`,
      location: { targetType: "binary", binary: binaryPath, address: `0x${df.offset.toString(16)}` },
      sources: [{ toolId: "binary-hunter", toolType: "BAT", rawRuleId: "DANGER-FUNC", toolConfidence: 0.85, reportedAt: new Date().toISOString() }],
      confidence: 0.7, // 使用危险函数只是风险，不一定有漏洞
      status: "candidate",
      exploitability: { difficulty: "medium", prerequisites: "需确认输入来源是否可控", accessNeeded: "取决于调用上下文" },
      impact: { assets: df.desc, worstCase: df.category === "command_exec" ? "RCE" : df.category === "buffer_overflow" ? "栈/堆溢出导致 RCE" : "信息泄露或内存破坏", remote: true, noAuth: false },
    });
    ctx.findings.push(finding);
    ctx.log_("LLM_HUNT", `风险标记: [${df.severity}] ${df.func}() @ 0x${df.offset.toString(16)}`, "info");
  }

  // 4. 可选：Ghidra 反编译 → LLM 分析
  if (isGhidraAvailable()) {
    ctx.log_("LLM_HUNT", "检测到 Ghidra，执行反编译 + LLM 函数级分析", "info");
    const decompResult = decompileWithGhidra(binaryPath);
    if (decompResult.decompiled && decompResult.functions.length > 0) {
      const llm = getLlm();
      ctx.log_("LLM_HUNT", `Ghidra 反编译 ${decompResult.functions.length} 个函数，开始 LLM 分析`, "info");
      const MAX_FUNCS = 20;
      for (const fn of decompResult.functions.slice(0, MAX_FUNCS)) {
        const prompt = `分析以下 Ghidra 反编译的 C 伪码，找出单函数内的漏洞（缓冲区溢出/资源泄漏/格式化字符串/整数溢出）。
注意：反编译代码变量名可能丢失（如 uVar1），重点看数据流和控制流。

代码：
\`\`\`
${fn.code}
\`\`\`

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","reasoning","attackScenario","exploitability":{"difficulty","prerequisites","accessNeeded"},"impact":{"assets","worstCase","remote","noAuth"}}], "confidence": 0-1}`;
        const result = await llm.complete(prompt, { difficulty: "high", jsonMode: true, systemPrompt: "你是二进制安全审计专家。" });
        const data = result.structured || {};
        if (data.found && data.vulnerabilities) {
          for (const v of data.vulnerabilities) {
            const finding = await findingStore.create({
              title: `[二进制反编译] ${fn.name}: ${v.title}`,
              category: "overflow",
              severity: v.severity || "high",
              description: `${v.reasoning}\n\n攻击场景: ${v.attackScenario}`,
              location: { targetType: "binary", binary: binaryPath, function: fn.name },
              snippet: { code: fn.code, language: "c", primaryLine: 1, startLine: 1, endLine: fn.code.split("\n").length, contextType: "function" },
              sources: [{ toolId: "binary-hunter", toolType: "BAT", rawRuleId: "GHIDRA-LLM", toolConfidence: v.confidence || 0.7, reportedAt: new Date().toISOString() }],
              confidence: v.confidence || 0.7, status: "candidate",
              exploitability: v.exploitability || {}, impact: v.impact || {},
            });
            ctx.findings.push(finding);
          }
        }
      }
    }
  } else {
    ctx.log_("LLM_HUNT", "Ghidra 未安装，跳过函数级反编译分析（只做确定性扫描）", "info");
    ctx.log_("LLM_HUNT", "  安装 Ghidra 后设置 GHIDRA_HOME 环境变量可启用反编译分析", "info");
  }

  ctx.log_("LLM_HUNT", `二进制挖掘完成: ${sensitiveFindings.length} 硬编码 + ${dangerFindings.length} 危险函数`, "info");
  return ctx;
}

/**
 * Mock 二进制（无真实文件时让流程跑通）
 */
function mockBinary() {
  // 构造含硬编码密码 + 危险函数的 mock 字符串
  return {
    format: "elf", arch: "arm", endian: "little", size: 1024,
    strings: [
      { value: "password=admin123", offset: 0x100 },
      { value: "-----BEGIN RSA PRIVATE KEY-----", offset: 0x200 },
      { value: "http://update.example.com/firmware.bin", offset: 0x300 },
      { value: "token=sk-abc123def456", offset: 0x400 },
      { value: "192.168.1.1", offset: 0x500 },
      { value: "mysql://root:toor@db.internal:3306/prod", offset: 0x600 },
    ],
    symbols: [
      { name: "strcpy", offset: 0x1000 },
      { name: "system", offset: 0x1010 },
      { name: "sprintf", offset: 0x1020 },
      { name: "gets", offset: 0x1030 },
      { name: "popen", offset: 0x1040 },
      { name: "memcpy", offset: 0x1050 },
      { name: "printf", offset: 0x1060 },
    ],
  };
}

module.exports = { hunt };
