// routes/auth.js — 认证路由
//
// POST /api/auth/register  注册（首个用户自动 admin）
// POST /api/auth/login     登录，返回 access + refresh token
// POST /api/auth/refresh   用 refresh token 换新 access token
// GET  /api/auth/me        查询当前用户（需 access token）
//
// 这些路由免 authMiddleware（除 /me）。

const express = require("express");
const { signTokenPair, verify } = require("../auth/jwt");

function authRoutes({ userStore }) {
  const router = express.Router();

  // 注册
  router.post("/auth/register", async (req, res) => {
    try {
      const { username, password } = req.body || {};
      const user = await userStore.create({ username, password });
      const tokens = signTokenPair(user);
      res.status(201).json({ user, ...tokens });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // 登录
  router.post("/auth/login", async (req, res) => {
    try {
      const { username, password } = req.body || {};
      if (!username || !password) {
        return res.status(400).json({ error: "需要 username 和 password" });
      }
      const user = await userStore.verifyPassword(username, password);
      if (!user) {
        return res.status(401).json({ error: "用户名或密码错误" });
      }
      const tokens = signTokenPair(user);
      res.json({ user: { id: user.id, username: user.username, role: user.role }, ...tokens });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 刷新 token
  router.post("/auth/refresh", async (req, res) => {
    try {
      const { refreshToken } = req.body || {};
      if (!refreshToken) return res.status(400).json({ error: "需要 refreshToken" });
      const payload = verify(refreshToken);
      if (!payload || payload.type !== "refresh") {
        return res.status(401).json({ error: "refreshToken 无效" });
      }
      const user = await userStore.findById(payload.sub);
      if (!user) return res.status(401).json({ error: "用户不存在" });
      const tokens = signTokenPair(user);
      res.json(tokens);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // 当前用户（需 access token；此路由用局部中间件）
  const { authMiddleware } = require("../auth/middleware");
  router.get("/auth/me", authMiddleware, (req, res) => {
    res.json({ user: req.user });
  });

  return router;
}

module.exports = authRoutes;
