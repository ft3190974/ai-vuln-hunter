// auth/jwt.js — JWT 签发/验证/刷新
//
// Access token: 15 分钟过期，放 Authorization: Bearer
// Refresh token: 7 天，用于换新 access token
//
// 密钥从 JWT_SECRET 环境变量读；未设则生成临时密钥并 warn（仅开发用）。

const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const ACCESS_EXPIRES = "15m";
const REFRESH_EXPIRES = "7d";

let secret = process.env.JWT_SECRET;
if (!secret) {
  secret = crypto.randomBytes(32).toString("hex");
  console.warn("[auth] 未设置 JWT_SECRET，已生成临时密钥（仅开发用，重启后失效）。生产请设环境变量 JWT_SECRET");
}

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role, type: "access" },
    secret,
    { expiresIn: ACCESS_EXPIRES }
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, type: "refresh" },
    secret,
    { expiresIn: REFRESH_EXPIRES }
  );
}

function signTokenPair(user) {
  return {
    accessToken: signAccessToken(user),
    refreshToken: signRefreshToken(user),
    expiresIn: 15 * 60,
  };
}

function verify(token) {
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
}

module.exports = { signAccessToken, signRefreshToken, signTokenPair, verify };
