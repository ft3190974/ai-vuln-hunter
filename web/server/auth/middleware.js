// auth/middleware.js — Express 认证中间件
//
// 从 Authorization: Bearer <token> 提取 access token 验证。
// 验证通过注入 req.user；失败返回 401。
//
// AUTH_ENABLED=0（默认）时放行（不强制），但若带了有效 token 仍解析注入真实用户
// （这样 /me 等接口在两种模式下都能正确返回当前用户）。

const { verify } = require("./jwt");

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);

  if (m) {
    // 带了 token：解析，有效则注入真实用户
    const payload = verify(m[1]);
    if (payload && payload.type === "access") {
      req.user = { id: payload.sub, username: payload.username, role: payload.role };
      return next();
    }
    // token 无效：若启用认证则拒绝，否则继续（匿名）
    if (process.env.AUTH_ENABLED === "1") {
      return res.status(401).json({ error: "token 无效或已过期" });
    }
  }

  // 未带 token：若启用认证则拒绝，否则匿名放行（向后兼容）
  if (process.env.AUTH_ENABLED === "1") {
    return res.status(401).json({ error: "缺少认证 token（Authorization: Bearer <token>）" });
  }
  req.user = { username: "anonymous", role: "admin" };
  next();
}

module.exports = { authMiddleware };
