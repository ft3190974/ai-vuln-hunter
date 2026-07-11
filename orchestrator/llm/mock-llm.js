// llm/mock-llm.js — LLM Mock 实现
//
// 零依赖，本地即跑。按 prompt 关键词返回构造好的结果，
// 让编排状态机和数据流能端到端验证，无需 API key。
//
// 设计：mock 不是"随机返回"，而是"按规则返回合理结果"——
// 让上层 Agent 的逻辑能被真实地走通。例如检测到 SQL 注入类 prompt，
// 返回一个 confirmed 的判定；检测到误报类 prompt，返回 false_positive。

const { ILlm } = require("./interface");

class MockLlm extends ILlm {
  implName() {
    return "mock";
  }

  async complete(prompt, opts = {}) {
    // 模拟一点延迟，让异步流程真实
    await new Promise((r) => setTimeout(r, 50));

    const lower = (prompt || "").toLowerCase();
    let text = "";
    let structured = null;

    // ── 按关键词识别任务类型，返回合理 mock 结果 ──
    // 注意：分支顺序很重要——越具体的任务越靠前，避免被泛化分支抢先匹配。

    // [最高优先级] 学习 Agent 的误报回灌
    if (lower.includes("正则") || (lower.includes("提取") && lower.includes("安全模式"))) {
      let pattern = "PreparedStatement|prepareStatement";
      let reason = "已使用参数化查询";
      if (lower.includes("escapehtml") || lower.includes("sanitize")) { pattern = "escapeHtml|sanitize\\("; reason = "已做输出编码"; }
      else if (lower.includes("whitelist") || lower.includes("allowlist")) { pattern = "whitelist\\(|allowList"; reason = "已使用白名单"; }
      structured = { pattern, reason };
      text = JSON.stringify(structured);
    } else if (lower.includes("缓冲区溢出") || lower.includes("格式化字符串") || lower.includes("命令注入") || lower.includes("整数溢出") || lower.includes("c/c++")) {
      // ★ C/C++ 专用漏洞挖掘（c-hunter）—— 必须在通用"分析代码"分支之前
      structured = analyzeCCodeForMock(prompt);
      text = JSON.stringify(structured);
    } else if ((lower.includes("单元测试") || lower.includes("测试用例") || lower.includes("修复后")) && !lower.includes("红队")) {
      // ★ 修复后验证（单元测试生成）—— 必须在攻击场景之前（prompt 可能同时含两者）
      structured = generateUnitTests(prompt);
      text = JSON.stringify(structured);
    } else if (lower.includes("红队") || lower.includes("攻击路径") || lower.includes("组合攻击") || (lower.includes("攻击场景") && !lower.includes("单元测试"))) {
      // ★ 复杂攻击场景构建（attack-scenario-builder）
      structured = buildAttackScenario(prompt);
      text = JSON.stringify(structured);
    } else if (lower.includes("分析以下代码") || lower.includes("找出") && (lower.includes("漏洞") || lower.includes("逻辑"))) {
      // LLM 自主挖掘（llm-hunter）：按代码内容识别漏洞类型返回
      structured = analyzeCodeForMock(prompt);
      text = JSON.stringify(structured);
    } else if (lower.includes("判定") || lower.includes("是否为漏洞") || lower.includes("判定为真漏洞")) {
      // 检测 Agent 的深度判定任务
      const isSql = lower.includes("sqli") || lower.includes("sql") || lower.includes("拼接");
      structured = {
        verdict: "confirmed", // confirmed / false_positive / suspect
        confidence: isSql ? 0.92 : 0.78,
        reasoning: isSql
          ? "用户输入直接拼接到 SQL 语句，未参数化，存在明确 SQL 注入。"
          : "资源访问未校验属主，存在水平越权风险。",
        evidence: ["污点 source → sink 路径完整", "缺少输入校验"],
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("误报") || lower.includes("是否为安全模式")) {
      // 误报判定（检测 Agent 用）
      structured = {
        isFalsePositive: lower.includes("@min") || lower.includes("参数化") || lower.includes("prepared"),
        confidence: 0.85,
        reasoning: "代码已使用参数化查询/校验注解，属已知安全模式。",
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("相似") || lower.includes("变种") || lower.includes("变体") || lower.includes("0-day") || lower.includes("0day")) {
      // 0-day 变种推理 —— 提前到"可达"分支之前，避免被 prompt 里 JSON 示例的 "reachable" 误触发
      structured = {
        variants: [
          {
            description: "变种1：source 改为 JSON body 字段",
            newSource: "http.body.data",
            newSink: "JSON.parse → 动态字段访问",
            reachable: true,
            confidence: 0.7,
          },
        ],
        confidence: 0.7,
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("可达") || lower.includes("是否调用")) {
      // 可达性判定（SCA 专用）
      // 注意：不匹配英文 "reachable"，避免被 prompt 里的 JSON 示例字段误触发
      structured = {
        reachable: true,
        level: 3,
        confidence: 0.82,
        reasoning: "调用链可从 HTTP 入口到达脆弱函数，参数来自外部输入。",
        evidence: ["Controller → Service → 库函数"],
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("状态机") || lower.includes("业务逻辑")) {
      // 业务逻辑漏洞判定
      structured = {
        verdict: "confirmed",
        confidence: 0.8,
        reasoning: "状态迁移未校验当前状态，可绕过业务流程。",
        attackSequence: ["步骤1: 创建订单", "步骤2: 取消订单", "步骤3: 对已取消订单发起发货"],
        vulnerableLine: "状态迁移函数缺少 currentState 校验",
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("修复") || lower.includes("patch")) {
      // 修复生成
      structured = {
        patch: "// 使用参数化查询替代字符串拼接\nString sql = \"SELECT * FROM users WHERE name=? AND pwd=?\";\nPreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, username);\nps.setString(2, pwd);\nResultSet rs = ps.executeQuery();",
        strategy: "框架内置防护（参数化查询）",
        riskLevel: "low",
        rationale: "改用 PreparedStatement 彻底消除 SQL 注入，语义等价。",
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("poc") || lower.includes("触发")) {
      // POC 生成
      structured = {
        poc: {
          vulnType: "SQL Injection",
          entry: "POST /api/login",
          payload: "admin' OR '1'='1' --",
          precondition: "目标使用拼接 SQL，无参数化",
          expected: "登录成功，返回 200 与 admin token",
        },
        confidence: 0.88,
      };
      text = JSON.stringify(structured);
    } else if (lower.includes("提取规则") || lower.includes("生成规则") || lower.includes("提炼")) {
      // 学习 Agent 的规则生成
      structured = {
        candidateRule: {
          ruleId: "AUTO-GEN-001",
          type: "structured",
          category: "sqli",
          source: ["http.param.*"],
          sink: ["*.execute(*)"],
          condition: { pathExists: true, hasValidation: { type: "regex", expect: false } },
          confidenceBoost: 0.85,
        },
        reason: "从确认的真漏洞提炼：source→拼接→execute 的模式。",
      };
      text = JSON.stringify(structured);
    } else {
      // 兜底：返回通用确认
      structured = { note: "mock 兜底响应", promptSnippet: (prompt || "").slice(0, 80) };
      text = JSON.stringify(structured);
    }

    return {
      text,
      structured: opts.jsonMode !== false ? structured : null,
      model: "mock-llm",
      tokensUsed: 0,
    };
  }
}

module.exports = { MockLlm };

/**
 * Mock 代码分析：针对当前代码块，返回最相关的 1 条漏洞（模拟真实 LLM 的"只报相关漏洞"行为）
 * 真实环境用 GLM 时，由 LLM 真实推理。
 *
 * 设计原则：每个代码块只返回 0 或 1 条最匹配的漏洞（避免一个函数报 N 类漏洞的不真实重复）
 */
function analyzeCodeForMock(prompt) {
  const codeMatch = prompt.match(/```\n([\s\S]*?)\n```/) || prompt.match(/代码（\w+）：\n([\s\S]+?)\n\n/);
  const code = codeMatch ? codeMatch[1] : "";
  const lines = code.split("\n");

  // 按 prompt 主题 + 代码内容匹配，每类规则只在该代码确实相关时返回 1 条
  // 优先级：业务逻辑 > 注入

  if (prompt.includes("金额") && /amount|price|setAmount/i.test(code) && !/@Min|>=\s*0/i.test(code)) {
    return singleVuln("金额未校验非负/上限", "critical",
      "amount 参数直接使用，未校验负数或上限。",
      "POST /create?amount=-100 套利", findLineNum(lines, "amount|setAmount"),
      { difficulty: "low", prerequisites: "构造负数 amount 参数", accessNeeded: "普通用户" },
      { assets: "支付/订单系统", worstCase: "余额无限增加，资金直接损失", remote: true, noAuth: false });
  }
  if (prompt.includes("状态机") && /setStatus|ship/i.test(code) && !/getStatus\(\).*==|if.*status/i.test(code)) {
    return singleVuln("状态迁移未校验当前状态", "high",
      "状态迁移未校验当前状态，已取消订单也能发货。",
      "对未支付订单调用 /ship 绕过支付", findLineNum(lines, "setStatus|ship"),
      { difficulty: "low", prerequisites: "知道订单 ID + 发货接口", accessNeeded: "普通用户" },
      { assets: "订单履约系统", worstCase: "未支付商品被发货，造成实物损失", remote: true, noAuth: false });
  }
  if (prompt.includes("幂等") && /charge|pay/i.test(code) && !/idempot|already/i.test(code)) {
    return singleVuln("支付无幂等保护", "high",
      "支付接口无幂等键，重复请求重复扣款。",
      "重放 /pay 请求 N 次扣款 N 倍", findLineNum(lines, "charge|pay"),
      { difficulty: "low", prerequisites: "抓包一次正常支付请求", accessNeeded: "普通用户" },
      { assets: "支付系统", worstCase: "用户余额被多倍扣减，或攻击者多倍套现", remote: true, noAuth: false });
  }
  if (prompt.includes("越权") && /findById|getOrder|getById/i.test(code) && !/isOwner|@PreAuthorize|currentUser/i.test(code)) {
    return singleVuln("水平越权（IDOR）", "high",
      "按 ID 查询未校验属主。",
      "遍历 /api/orders/1,2,3 看他人订单", findLineNum(lines, "findById|getById|getOrder"),
      { difficulty: "low", prerequisites: "无", accessNeeded: "任意登录用户" },
      { assets: "用户订单数据", worstCase: "全站订单信息泄露，含金额/地址/商品", remote: true, noAuth: false });
  }
  if (prompt.includes("优惠券") && /coupon|discount/i.test(code) && !/used|limit|once/i.test(code)) {
    return singleVuln("优惠券可叠加", "medium",
      "优惠券使用次数未限制。",
      "多次 /applyCoupon 使金额变负", findLineNum(lines, "coupon|discount|applyCoupon"),
      { difficulty: "low", prerequisites: "有一个有效优惠券", accessNeeded: "普通用户" },
      { assets: "优惠/支付系统", worstCase: "免费下单甚至反向套利", remote: true, noAuth: false });
  }
  if (prompt.includes("SQL") && /\+\s*keyword|LIKE.*\+|".*\+.*\+/i.test(code) && !/PreparedStatement|\?/i.test(code)) {
    return singleVuln("SQL 注入（拼接）", "critical",
      "SQL 字符串拼接用户输入。",
      "search?keyword=' OR '1'='1", findLineNum(lines, "SELECT|sql|keyword"),
      { difficulty: "low", prerequisites: "无", accessNeeded: "匿名" },
      { assets: "数据库", worstCase: "全库数据泄露/篡改/删除，可导致 RCE", remote: true, noAuth: true });
  }

  return { found: false, vulnerabilities: [], confidence: 0.3 };
}

function singleVuln(title, severity, reasoning, scenario, line, exploitability, impact) {
  return {
    found: true,
    vulnerabilities: [{
      title, severity, line, reasoning,
      attackScenario: scenario,
      confidence: 0.85,
      exploitability: exploitability || { difficulty: "low", prerequisites: "可构造恶意请求", accessNeeded: "普通用户/匿名" },
      impact: impact || { assets: "订单/支付系统", worstCase: "资金损失或数据泄露", remote: true, noAuth: false },
    }],
    confidence: 0.85,
  };
}

function findLineNum(lines, pattern) {
  const re = new RegExp(pattern, "i");
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) return i + 1;
  }
  return 1;
}

/**
 * C/C++ 代码分析（mock 版）：识别缓冲区溢出/格式化字符串/命令注入/整数溢出
 */
function analyzeCCodeForMock(prompt) {
  const codeMatch = prompt.match(/```\n([\s\S]*?)\n```/) || prompt.match(/代码：\n([\s\S]+?)\n\n/);
  const code = codeMatch ? codeMatch[1] : "";
  const lines = code.split("\n");
  const vulns = [];

  if (prompt.includes("缓冲区溢出")) {
    if (/\bstrcpy\s*\(/i.test(code)) {
      vulns.push(mkCVuln("strcpy 无长度限制导致栈溢出", "critical",
        "strcpy 拷贝到固定大小栈缓冲区，输入超长会溢出。",
        "发送超长输入覆盖返回地址", findLineNum(lines, "strcpy"),
        { difficulty: "low", prerequisites: "无", accessNeeded: "匿名" },
        { assets: "进程内存", worstCase: "RCE，远程代码执行", remote: true, noAuth: true }));
    }
    if (/\bgets\s*\(/i.test(code)) {
      vulns.push(mkCVuln("gets 无边界检查", "critical",
        "gets 不检查输入长度，必定溢出。",
        "发送超长输入", findLineNum(lines, "gets"),
        { difficulty: "low", prerequisites: "无", accessNeeded: "匿名" },
        { assets: "进程", worstCase: "RCE", remote: true, noAuth: true }));
    }
  }
  if (prompt.includes("格式化字符串")) {
    if (/printf\s*\([^,"%]/.test(code) && !/printf\s*\(\s*"/.test(code)) {
      vulns.push(mkCVuln("格式化字符串漏洞", "high",
        "printf 直接用用户输入作为格式字符串。",
        "发送 %x%x%x 泄露栈，%n 写内存", findLineNum(lines, "printf"),
        { difficulty: "medium", prerequisites: "无", accessNeeded: "匿名" },
        { assets: "进程内存", worstCase: "内存泄露或任意写", remote: true, noAuth: true }));
    }
  }
  if (prompt.includes("命令注入")) {
    if (/\bsystem\s*\(/i.test(code) && /sprintf.*system|"\+.*system/i.test(code)) {
      vulns.push(mkCVuln("命令注入", "critical",
        "system 参数包含用户输入。",
        "注入 ; rm -rf / 等命令", findLineNum(lines, "system"),
        { difficulty: "low", prerequisites: "无", accessNeeded: "匿名" },
        { assets: "操作系统", worstCase: "RCE", remote: true, noAuth: true }));
    }
  }
  if (prompt.includes("整数溢出")) {
    if (/malloc\s*\([^)]*[*+]/i.test(code)) {
      vulns.push(mkCVuln("整数溢出导致小分配", "high",
        "malloc 参数是算术运算结果，可能溢出为小值。",
        "构造溢出导致小缓冲区 + 后续大写入", findLineNum(lines, "malloc"),
        { difficulty: "medium", prerequisites: "无", accessNeeded: "匿名" },
        { assets: "堆", worstCase: "堆溢出 RCE", remote: true, noAuth: true }));
    }
  }
  return { found: vulns.length > 0, vulnerabilities: vulns, confidence: vulns.length > 0 ? 0.85 : 0.3 };
}

function mkCVuln(title, severity, reasoning, scenario, line, exploitability, impact) {
  return { title, severity, line, reasoning, attackScenario: scenario, confidence: 0.85, exploitability, impact };
}

/**
 * Mock：构建复杂攻击场景（多漏洞组合 DAG）
 */
function buildAttackScenario(prompt) {
  // 从 prompt 提取漏洞列表（找 findingId / category）
  const findingMatches = [...prompt.matchAll(/"findingId"\s*:\s*"(F-[^"]+)"/g)];
  const categoryMatches = [...prompt.matchAll(/"category"\s*:\s*"([^"]+)"/g)];
  const titleMatches = [...prompt.matchAll(/"title"\s*:\s*"([^"]+)"/g)];

  const findings = findingMatches.map((m, i) => ({
    id: m[1],
    category: categoryMatches[i]?.[1] || "unknown",
    title: titleMatches[i]?.[1] || "未知漏洞",
  }));

  if (findings.length === 0) {
    return { summary: "无法构建攻击场景（无足够漏洞）", difficulty: "unknown", impact: "未知", paths: [] };
  }

  // 构建 DAG 路径：攻击者 → 漏洞1 → 漏洞2 → ... → 影响
  const nodes = [{ id: "attacker", label: "攻击者", type: "entry" }];
  const edges = [];
  const severityMap = { business_logic: "逻辑利用", sqli: "SQL注入", authz: "越权", cmdi: "命令注入", overflow: "溢出", deserialization: "反序列化" };

  let prevId = "attacker";
  findings.forEach((f, i) => {
    const stepId = `s${i + 1}`;
    const label = severityMap[f.category] || f.category;
    nodes.push({
      id: stepId,
      label: `${label}: ${f.title.slice(0, 30)}`,
      findingId: f.id,
      type: "vuln",
      output: i < findings.length - 1 ? `获取${label}能力` : "最终目标达成",
      detail: `利用 ${f.id}（${f.category}）`,
    });
    edges.push({ from: prevId, to: stepId, label: i === 0 ? "初始入口" : `上一步输出` });
    prevId = stepId;
  });

  // 影响节点
  nodes.push({ id: "impact", label: "💥 最终影响", type: "impact" });
  edges.push({ from: prevId, to: "impact", label: "完全控制" });

  const difficulty = findings.length >= 3 ? "medium" : "low";
  const impact = findings.some((f) => ["cmdi", "deserialization", "overflow"].includes(f.category))
    ? "远程代码执行，完全接管服务器" : "数据泄露/权限提升";

  return {
    summary: `攻击者通过组合 ${findings.length} 个漏洞，实现${impact}`,
    difficulty,
    impact,
    paths: [{ name: "主攻击路径", nodes, edges }],
  };
}

/**
 * Mock：生成单元测试用例（修复后验证）
 */
function generateUnitTests(prompt) {
  // 从 prompt 提取漏洞类别
  const catMatch = prompt.match(/漏洞类别:\s*(\w+)/);
  const category = catMatch?.[1] || "unknown";

  const tests = [
    { name: `testNormalInput_${category}`, input: "正常用户输入", expectedBehavior: "功能正常返回预期结果", passed: true, detail: "修复后功能保持正常" },
    { name: `testMaliciousInput_${category}`, input: "恶意攻击载荷", expectedBehavior: "恶意输入被拦截/中和", passed: true, detail: "原漏洞 payload 已无法利用" },
    { name: `testEdgeCase_${category}`, input: "边界值/空值/超长", expectedBehavior: "优雅处理不崩溃", passed: true, detail: "边界情况处理正确" },
  ];

  return { tests };
}
