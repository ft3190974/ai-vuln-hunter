// src/pages/LoginPage.jsx — 登录/注册页
import { useState } from "react";
import { api, auth } from "../api.js";

export default function LoginPage({ onLoggedIn }) {
  const [mode, setMode] = useState("login"); // login | register
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = mode === "login"
        ? await api.login(username, password)
        : await api.register(username, password);
      auth.setSession(result.accessToken, result.user);
      if (onLoggedIn) onLoggedIn(result.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: 360, margin: "80px auto" }}>
      <h1 style={{ textAlign: "center", color: "#37DCF2", marginBottom: 8 }}>🛡️ AI 漏洞挖掘</h1>
      <p style={{ textAlign: "center", color: "#94a3b8", marginBottom: 32 }}>
        {mode === "login" ? "登录到你的账户" : "创建新账户"}
      </p>

      <form onSubmit={submit} className="card">
        <div className="form-group">
          <label>用户名</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
        </div>
        <div className="form-group">
          <label>密码</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"} required />
        </div>
        {error && <div className="msg msg-error">{error}</div>}
        <button type="submit" disabled={loading || !username || !password} style={{ width: "100%" }}>
          {loading ? "处理中..." : mode === "login" ? "登录" : "注册"}
        </button>
      </form>

      <p style={{ textAlign: "center", marginTop: 16, fontSize: 14, color: "#94a3b8" }}>
        {mode === "login" ? "没有账户？" : "已有账户？"}
        <a href="#/login" onClick={(e) => { e.preventDefault(); setMode(mode === "login" ? "register" : "login"); }}
          style={{ color: "#37DCF2", marginLeft: 6 }}>
          {mode === "login" ? "注册" : "登录"}
        </a>
      </p>

      <p style={{ textAlign: "center", marginTop: 24, fontSize: 12, color: "#64748b" }}>
        提示：首个注册用户自动成为 admin
      </p>
    </div>
  );
}
