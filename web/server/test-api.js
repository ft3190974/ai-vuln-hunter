// web/server/test-api.js — HTTP API 端到端测试
//
// 用 supertest 风格手写 fetch 调用（避免额外依赖），
// 启动 app → 调各 API → 校验响应。
// 用法：node test-api.js

const http = require("http");
const { createApp } = require("./app");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

// 把 Express app 包成可 fetch 的 server
function startServer(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      resolve({ server, baseUrl: `http://localhost:${port}` });
    });
  });
}

async function fetchJson(baseUrl, path, options = {}) {
  const url = baseUrl + path;
  const resp = await fetch(url, {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const status = resp.status;
  let body;
  try {
    body = await resp.json();
  } catch {
    body = await resp.text();
  }
  return { status, body };
}

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("L HTTP API · 端到端测试");
  console.log("=".repeat(60) + "\x1b[0m\n");

  const { app, engine, syncManager, userStore } = await createApp();
  const { server, baseUrl } = await startServer(app);

  let pass = 0;
  let fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  try {
    // 0. 先同步漏洞库（让图谱有数据）
    console.log(HDR + "[0] 预同步漏洞库" + "\x1b[0m");
    await syncManager.syncAll();
    check("漏洞库同步完成", true);

    // 1. 健康检查
    console.log("\n" + HDR + "[1] 健康检查" + "\x1b[0m");
    const health = await fetchJson(baseUrl, "/api/health");
    check("GET /api/health", health.status === 200 && health.body.ok === true);

    // 2. 引擎状态
    console.log("\n" + HDR + "[2] 引擎状态" + "\x1b[0m");
    const status = await fetchJson(baseUrl, "/api/status");
    check("GET /api/status 返回 engine", !!status.body.engine);
    check("状态含图谱统计", typeof status.body.engine.knowledgeGraph?.nodes === "number");
    check("状态含漏洞库状态", Array.isArray(status.body.vulnDb?.sources));

    // 3. 知识图谱数据
    console.log("\n" + HDR + "[3] 知识图谱数据" + "\x1b[0m");
    const graph = await fetchJson(baseUrl, "/api/graph");
    check("GET /api/graph 返回 cytoscape 格式", Array.isArray(graph.body.nodes) && Array.isArray(graph.body.edges));
    check("图谱有节点", graph.body.nodes.length > 0, `(${graph.body.nodes.length} 节点)`);
    check("节点含 data.id", graph.body.nodes[0]?.data?.id !== undefined);

    // 4. 提交扫描任务
    console.log("\n" + HDR + "[4] 提交扫描任务" + "\x1b[0m");
    const scanReq = {
      scanRequest: {
        scanId: "api-test-001",
        target: { type: "source", path: "/demo", language: "java" },
        options: { depth: "deep", timeoutSec: 60 },
      },
      toolOutputs: {
        sast: {
          toolId: "ruanan-sast",
          scanId: "api-test-001",
          scannedAt: new Date().toISOString(),
          findings: [
            {
              ruleId: "RA-SQLI-001",
              category: "sqli",
              severity: "critical",
              message: "SQL 拼接注入",
              location: { file: "Login.java", startLine: 10, endLine: 10, function: "login" },
              snippet: {
                code: 'String sql = "SELECT * FROM u WHERE n=\'" + name + "\'";stmt.execute(sql);',
                language: "java",
                primaryLine: 1, startLine: 9, endLine: 10, contextType: "function",
              },
              confidence: 0.92,
            },
          ],
        },
      },
    };
    const submit = await fetchJson(baseUrl, "/api/scan", { method: "POST", body: scanReq });
    check("POST /api/scan 返回 202", submit.status === 202, `(status=${submit.status})`);
    check("返回 scanId", submit.body.scanId === "api-test-001");

    // 5. 轮询扫描状态
    console.log("\n" + HDR + "[5] 轮询扫描状态" + "\x1b[0m");
    let job = null;
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 200));
      const r = await fetchJson(baseUrl, "/api/scan/api-test-001");
      job = r.body;
      if (job.status === "completed" || job.status === "failed") break;
    }
    check("扫描完成", job?.status === "completed", `(status=${job?.status})`);
    check("报告含 findings", (job?.report?.findings?.length || 0) > 0);

    // 6. 查询 Finding 列表
    console.log("\n" + HDR + "[6] 查询 Finding" + "\x1b[0m");
    const findingsAll = await fetchJson(baseUrl, "/api/findings");
    check("GET /api/findings 返回数组", Array.isArray(findingsAll.body));
    check("Finding 数 > 0", findingsAll.body.length > 0, `(${findingsAll.body.length} 个)`);

    // 按状态过滤
    const fixed = await fetchJson(baseUrl, "/api/findings?status=fixed");
    check("GET /api/findings?status=fixed 过滤生效",
      Array.isArray(fixed.body) && fixed.body.every((f) => f.status === "fixed"),
      `(${fixed.body.length} 个 fixed)`);

    // 单个 Finding
    if (findingsAll.body.length > 0) {
      const fid = findingsAll.body[0].findingId;
      const one = await fetchJson(baseUrl, `/api/findings/${fid}`);
      check("GET /api/findings/:id", one.status === 200 && one.body.findingId === fid);
    }

    // 7. Finding 统计
    console.log("\n" + HDR + "[7] Finding 统计" + "\x1b[0m");
    const stats = await fetchJson(baseUrl, "/api/findings-stats/summary");
    check("GET /api/findings-stats/summary", typeof stats.body.total === "number");
    check("统计含 byStatus", typeof stats.body.byStatus === "object");

    // 8. 漏洞库同步 API
    console.log("\n" + HDR + "[8] 漏洞库同步 API" + "\x1b[0m");
    const sources = await fetchJson(baseUrl, "/api/vuln-db/sources");
    check("GET /api/vuln-db/sources", Array.isArray(sources.body.sources));
    check("4 个数据源", sources.body.sources.length === 4);

    const syncResp = await fetchJson(baseUrl, "/api/vuln-db/sync?source=nvd", { method: "POST" });
    check("POST /api/vuln-db/sync?source=nvd", !syncResp.body.error);

    // 9. 404 处理
    console.log("\n" + HDR + "[9] 错误处理" + "\x1b[0m");
    const notFound = await fetchJson(baseUrl, "/api/findings/NON-EXISTENT");
    check("不存在的 Finding 返回 404", notFound.status === 404);

    // 10. 认证（默认模式：AUTH_ENABLED 未设，中间件放行）
    console.log("\n" + HDR + "[10] 认证 - 默认免认证模式" + "\x1b[0m");
    const healthAuth = await fetchJson(baseUrl, "/api/health");
    check("health 显示 authEnabled 状态", typeof healthAuth.body.authEnabled === "boolean");
    // 默认模式访问 findings 应成功（中间件放行）
    const findingsNoAuth = await fetchJson(baseUrl, "/api/findings");
    check("默认模式免认证可访问", findingsNoAuth.status === 200);

    // 注册 + 登录（即使默认免认证，auth 路由仍可用）
    const reg = await fetchJson(baseUrl, "/api/auth/register", {
      method: "POST", body: { username: "tester", password: "pass123456" },
    });
    check("注册成功（首个用户 admin）", reg.status === 201 && reg.body.user?.role === "admin", `(role=${reg.body.user?.role})`);
    check("注册返回 token 对", !!reg.body.accessToken && !!reg.body.refreshToken);

    const login = await fetchJson(baseUrl, "/api/auth/login", {
      method: "POST", body: { username: "tester", password: "pass123456" },
    });
    check("登录成功", login.status === 200 && !!login.body.accessToken);

    // 重复注册应失败
    const dup = await fetchJson(baseUrl, "/api/auth/register", {
      method: "POST", body: { username: "tester", password: "pass123456" },
    });
    check("重复用户名注册被拒", dup.status === 400);

    // 错误密码
    const wrongPw = await fetchJson(baseUrl, "/api/auth/login", {
      method: "POST", body: { username: "tester", password: "wrong" },
    });
    check("错误密码登录被拒", wrongPw.status === 401);

    // refresh token 换新 access token
    const refresh = await fetchJson(baseUrl, "/api/auth/refresh", {
      method: "POST", body: { refreshToken: login.body.refreshToken },
    });
    check("refresh token 换新 access token", refresh.status === 200 && !!refresh.body.accessToken);

    // 带 token 访问 /me
    const me = await fetchJson(baseUrl, "/api/auth/me", {
      headers: { Authorization: `Bearer ${login.body.accessToken}` },
    });
    check("GET /api/auth/me 返回当前用户", me.status === 200 && me.body.user?.username === "tester");

    // 无 token 访问 /me（默认模式放行，返回 anonymous；但 /me 有局部中间件）
    // 默认 AUTH_ENABLED!=1，中间件注入 anonymous，/me 仍返回 200
    const meNoToken = await fetchJson(baseUrl, "/api/auth/me");
    check("/me 默认模式放行", meNoToken.status === 200);

  } finally {
    server.close();
  }

  // 总结
  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} L HTTP API 测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 12 个 API 端点全部工作正常");
    console.log("  ✓ 扫描任务异步流转（POST → 轮询 → 完成）");
    console.log("  ✓ Finding 查询/过滤/统计");
    console.log("  ✓ 知识图谱 cytoscape 格式");
    console.log("  ✓ 漏洞库同步与状态查询");
    console.log("  ✓ JWT 认证（注册/登录/刷新/me，默认免认证向后兼容）");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试有 ${fail} 项未通过 (${pass} 通过 / ${fail} 失败)`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(FAIL + " 测试异常:", e);
  process.exit(1);
});
