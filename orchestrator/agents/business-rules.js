// agents/business-rules.js — 业务逻辑漏洞挖掘规则库
//
// 驱动 LLM 自主挖掘业务逻辑漏洞。每条规则是一个 prompt 模板 + 关注点。
// 这些漏洞 SAST 永远发现不了——这是本产品的核心差异化价值。

const BUSINESS_VULN_TYPES = [
  {
    id: "BL-PRICE-001",
    name: "价格/金额篡改",
    severity: "critical",
    cwe: "CWE-20",
    focus: "金额、价格、数量相关参数是否做了校验",
    checks: [
      "金额是否允许负数或零",
      "整数溢出（大额绕过）",
      "小数精度问题（浮点比较）",
      "币种/单位混淆",
      "折扣比例是否限制在 0-1 / 0-100",
    ],
    sinks: ["setPrice", "setAmount", "setQuantity", "charge", "payment", "order.total"],
    prompt: `分析以下代码，找出价格/金额相关的业务逻辑漏洞：
1. 金额参数是否允许负数、零、或超大值（整数溢出）
2. 是否使用浮点数比较金额（精度问题）
3. 折扣/优惠比例是否限制范围
4. 币种或单位是否可能混淆

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定，不要臆测未给出的代码。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
  {
    id: "BL-STATE-002",
    name: "状态机绕过",
    severity: "high",
    cwe: "CWE-664",
    focus: "业务状态迁移是否校验当前状态",
    checks: [
      "状态迁移函数是否校验当前状态（如已取消订单仍能发货）",
      "是否存在非法状态跳转（跳过支付直接发货）",
      "终态是否能回退（已完成订单能否重新打开）",
    ],
    sinks: ["setStatus", "updateStatus", "ship", "cancel", "complete", "transition"],
    prompt: `分析以下代码，找出状态机绕过相关的业务逻辑漏洞：
1. 状态迁移函数是否校验当前状态（例：已取消订单仍能发货）
2. 是否存在非法状态跳转（跳过中间步骤）
3. 终态是否能回退到非终态
4. 状态字段是否可被外部输入直接控制

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
  {
    id: "BL-IDEMPOTENCY-003",
    name: "幂等性缺失（重复操作）",
    severity: "high",
    cwe: "CWE-367",
    focus: "关键操作是否能被重复触发",
    checks: [
      "支付/下单接口是否有幂等键",
      "重复请求是否会导致重复扣款/重复下单",
      "并发请求是否会产生竞态（TOCTOU）",
    ],
    sinks: ["pay", "charge", "create", "submit", "transfer", "withdraw"],
    prompt: `分析以下代码，找出幂等性/并发相关的业务逻辑漏洞：
1. 关键操作（支付/下单/转账）是否有幂等键保护
2. 重复请求是否会导致重复副作用（重复扣款、重复下单）
3. 是否存在 TOCTOU 竞态（check-then-act 之间状态可变）
4. 库存/余额扣减是否原子

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
  {
    id: "BL-AUTHZ-004",
    name: "水平/垂直越权",
    severity: "high",
    cwe: "CWE-639",
    focus: "资源访问是否校验属主",
    checks: [
      "按 ID 查询/修改资源时是否校验当前用户是该资源属主",
      "是否存在 IDOR（直接对象引用）",
      "普通用户能否访问管理接口",
    ],
    sinks: ["findById", "getById", "getOrder", "getUser", "update", "delete"],
    prompt: `分析以下代码，找出越权（IDOR/水平越权）相关的业务逻辑漏洞：
1. 按 ID 查询/修改资源时是否校验当前用户是该资源属主
2. ID 参数是否来自外部输入且未校验属主
3. 是否存在垂直越权（普通用户能访问管理接口）
4. 列表接口是否过滤了他人数据

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
  {
    id: "BL-COUPON-005",
    name: "优惠券/积分套利",
    severity: "medium",
    cwe: "CWE-841",
    focus: "优惠/积分逻辑边界",
    checks: [
      "优惠券是否可叠加（导致负金额）",
      "过期优惠券能否复用",
      "积分是否允许负值或溢出套利",
      "优惠金额是否超过订单总额",
    ],
    sinks: ["coupon", "discount", "points", "reward", "apply", "redeem"],
    prompt: `分析以下代码，找出优惠券/积分相关的业务逻辑漏洞：
1. 优惠券是否可叠加使用（导致零金额或负金额）
2. 过期优惠券能否复用
3. 积分是否允许负值或整数溢出套利
4. 优惠金额是否超过订单总额（未做上限校验）

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
];

// 高危类（非业务逻辑，LLM 也能挖，作为补充）
const HIGH_RISK_TYPES = [
  {
    id: "HR-INJECTION-001",
    name: "注入类（SQL/命令/模板）",
    severity: "critical",
    focus: "用户输入是否流入危险 sink",
    prompt: `分析以下代码，找出注入类漏洞（SQL/命令/模板/路径穿越/SSRF）：
1. 用户输入是否直接拼接到 SQL/命令/模板字符串
2. 是否使用参数化查询或安全的 API
3. 路径参数是否做了规范化与根目录限制
4. URL 参数是否限制了内网访问（SSRF）

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
  {
    id: "HR-AUTH-002",
    name: "认证/会话缺陷",
    severity: "high",
    focus: "认证与会话管理",
    prompt: `分析以下代码，找出认证/会话相关漏洞：
1. 密码是否明文存储或弱哈希
2. JWT/Token 是否校验签名与过期
3. 会话固定/会话未在登出后失效
4. 密码重置/修改接口是否校验身份

代码（{language}）：
\`\`\`
{code}
\`\`\`

只基于给定代码判定。
对每个发现的漏洞，必须给出：
- exploitability: 可利用性说明（利用难度 low/medium/high + 需要的前置条件 + 攻击者所需权限）
- impact: 影响说明（受影响的资产/数据/业务 + 最坏后果 + 是否可远程/无需认证）

返回 JSON: {"found": bool, "vulnerabilities":[{"title","severity","line","reasoning","attackScenario","exploitability":{"difficulty":"low|medium|high","prerequisites":"","accessNeeded":""},"impact":{"assets":"","worstCase":"","remote":bool,"noAuth":bool}}], "confidence": 0-1}`,
  },
];

module.exports = { BUSINESS_VULN_TYPES, HIGH_RISK_TYPES };
