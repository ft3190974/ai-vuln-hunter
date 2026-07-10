// web/server/test-auth.js — AUTH_ENABLED=1 强制认证模式测试
//
// 验证启用认证后：
//   1. 无 token 访问 /api/findings → 401
//   2. 登录拿 token → 带 token 访问 → 200
//   3. 错误 token → 401
//
// 用法：node test-auth.js（脚本内部设置 AUTH_ENABLED=1 并启动独立 app 实例）

process.env.AUTH_ENABLED = "1"; // 强制启用认证

const { createApp } = require("./app");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";

async function fetchJson(baseUrl, path, options = {}) {
  const resp = await fetch(baseUrl + path, {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  let body;
  try { body = await resp.json(); } catch { body = null; }
  return { status: resp.status, body };
}

async function main() {
  console.log("=".repeat(60));
  console.log("O 认证 · AUTH_ENABLED=1 强制认证测试");
  console.log("=".repeat(60) + "\n");

  const { app } = await createApp();
  const server = app.listen(0);
  const baseUrl = `http://localhost:${server.address().port}`;

  let pass = 0, fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  try {
    // 1. 无 token 访问受保护资源 → 401
    console.log("[1] 无 token 访问受保护资源");
    const noToken = await fetchJson(baseUrl, "/api/findings");
    check("GET /api/findings 无 token → 401", noToken.status === 401, `(status=${noToken.status})`);

    const noTokenStatus = await fetchJson(baseUrl, "/api/status");
    check("GET /api/status 无 token → 401", noTokenStatus.status === 401);

    // 2. health 仍可访问（免认证）
    const health = await fetchJson(baseUrl, "/api/health");
    check("GET /api/health 免认证仍可访问", health.status === 200);

    // 3. 注册 + 登录
    console.log("\n[2] 注册并登录");
    await fetchJson(baseUrl, "/api/auth/register", {
      method: "POST", body: { username: "admin1", password: "secret123" },
    });
    const login = await fetchJson(baseUrl, "/api/auth/login", {
      method: "POST", body: { username: "admin1", password: "secret123" },
    });
    check("登录成功返回 token", login.status === 200 && !!login.body.accessToken);
    const token = login.body.accessToken;

    // 4. 带 token 访问 → 200
    console.log("\n[3] 带 token 访问受保护资源");
    const withToken = await fetchJson(baseUrl, "/api/findings", {
      headers: { Authorization: `Bearer ${token}` },
    });
    check("GET /api/findings 带 token → 200", withToken.status === 200, `(status=${withToken.status})`);

    const me = await fetchJson(baseUrl, "/api/auth/me", {
      headers: { Authorization: `Bearer ${token}` },
    });
    check("GET /api/auth/me 返回真实用户", me.body.user?.username === "admin1", `(user=${me.body.user?.username})`);

    // 5. 错误 token → 401
    console.log("\n[4] 错误 token");
    const badToken = await fetchJson(baseUrl, "/api/findings", {
      headers: { Authorization: "Bearer invalidtoken123" },
    });
    check("错误 token → 401", badToken.status === 401);

    // 6. 提交扫描也需 token
    console.log("\n[5] 扫描提交需认证");
    const scanNoToken = await fetchJson(baseUrl, "/api/scan", {
      method: "POST", body: { scanRequest: { scanId: "x" }, toolOutputs: {} },
    });
    check("POST /api/scan 无 token → 401", scanNoToken.status === 401);
  } finally {
    server.close();
  }

  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} 强制认证测试全部通过 (${pass}/${pass + fail})`);
    console.log("  ✓ 无 token 被 401 拦截");
    console.log("  ✓ 登录拿 token 后正常访问");
    console.log("  ✓ health/auth 仍免认证");
    console.log("  ✓ 错误 token 被拒");
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试失败 (${pass}/${pass + fail})`);
    process.exit(1);
  }
}

main().catch((e) => { console.error(FAIL + " 异常:", e); process.exit(1); });
