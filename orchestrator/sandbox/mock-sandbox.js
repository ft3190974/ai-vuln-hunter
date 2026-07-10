// sandbox/mock-sandbox.js — 沙箱 Mock 实现
//
// 零依赖，本地即跑。按 POC 内容返回构造的执行结果，
// 让验证层数据流能端到端跑通，无需真实 Docker。
//
// 设计：mock 不是"总是返回成功"，而是按 POC 特征返回合理结果——
// 例如 payload 含 SQL 注入特征 → triggered=true + 返回 admin token。

const { ISandbox } = require("./interface");

class MockSandbox extends ISandbox {
  implName() {
    return "mock";
  }

  async execute(req) {
    // 模拟执行延迟
    await new Promise((r) => setTimeout(r, 80));

    const poc = req.poc || {};
    const payload = String(poc.payload || "").toLowerCase();
    const entry = String(poc.entry || "").toLowerCase();
    const expected = String(poc.expected || "").toLowerCase();

    let triggered = false;
    let evidence = "";
    let response = {};

    // ── 按漏洞类型特征判定是否触发 ──
    if (payload.includes("' or '1'='1") || payload.includes("or 1=1") || payload.includes("union select")) {
      // SQL 注入特征
      triggered = true;
      evidence = "数据库返回了非预期数据（绕过认证），疑似 SQL 注入成功";
      response = { status: 200, body: '{"token":"admin-fake-token","role":"admin"}', leakedData: true };
    } else if (payload.includes("<script>") || payload.includes("onerror=") || payload.includes("javascript:")) {
      // XSS 特征
      triggered = true;
      evidence = "响应中 payload 未被编码，原样反射到页面";
      response = { status: 200, bodyContains: payload.slice(0, 50), reflected: true };
    } else if (payload.includes("../") || payload.includes("..\\") || payload.includes("/etc/passwd")) {
      // 路径穿越特征
      triggered = true;
      evidence = "读取到非授权文件内容";
      response = { status: 200, bodyContains: "root:x:0:0", fileLeaked: true };
    } else if (payload.includes("id=1") && (entry.includes("orders") || entry.includes("/api/"))) {
      // IDOR/越权特征
      triggered = true;
      evidence = "未授权访问到他人资源（水平越权）";
      response = { status: 200, body: '{"id":1,"owner":"other_user"}', unauthorizedAccess: true };
    } else if (expected.includes("crash") || expected.includes("崩溃") || payload.length > 1000) {
      // 固件崩溃特征
      triggered = true;
      evidence = "目标进程崩溃（SIGSEGV），疑似缓冲区溢出";
      response = { exitCode: -11, signal: "SIGSEGV", crashed: true };
    } else if (Object.keys(poc).length > 0) {
      // 通用：POC 有内容但未匹配具体特征，给"疑似触发"
      triggered = true;
      evidence = "POC 执行后响应异常（状态码或内容偏离预期）";
      response = { status: 200, anomalyDetected: true };
    } else {
      evidence = "POC 内容为空或无效，未触发";
      response = { status: 0 };
    }

    return {
      triggered,
      evidence,
      response,
      sandboxImpl: "mock",
      durationMs: 80 + Math.floor(Math.random() * 40),
    };
  }
}

module.exports = { MockSandbox };
