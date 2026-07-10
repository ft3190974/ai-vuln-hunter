// src/App.jsx — 路由 + 布局（含认证 + 主题切换）
import { useState, useEffect } from "react";
import { Routes, Route, NavLink, useNavigate } from "react-router-dom";
import { api, auth } from "./api.js";
import { useTheme } from "./hooks/useTheme.js";
import ScanPage from "./pages/ScanPage.jsx";
import FindingsPage from "./pages/FindingsPage.jsx";
import TasksPage from "./pages/TasksPage.jsx";
import StatusPage from "./pages/StatusPage.jsx";
import RulesPage from "./pages/RulesPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";

export default function App() {
  const [user, setUser] = useState(auth.getUser());
  const [authChecked, setAuthChecked] = useState(false);
  const navigate = useNavigate();
  const { theme, toggle: toggleTheme } = useTheme();

  // 启动时探测后端是否启用认证（若启用且未登录 → 跳登录）
  useEffect(() => {
    api.health().then((h) => {
      if (h?.authEnabled && !auth.isLoggedIn()) {
        navigate("/login");
      }
      setAuthChecked(true);
    }).catch(() => setAuthChecked(true));
  }, [navigate]);

  const handleLoggedIn = (u) => {
    setUser(u);
    navigate("/");
  };

  const logout = () => {
    auth.clear();
    setUser(null);
    navigate("/login");
  };

  if (!authChecked) return <div style={{ padding: 40, textAlign: "center", color: "#94a3b8" }}>加载中...</div>;

  // 未登录且后端启用认证 → 只渲染登录页
  if (!user && auth.isLoggedIn() === false) {
    // 再探一次 health：未启用认证就不强制登录
    // （authChecked 后已知，这里用 user 状态控制）
    return <Routes><Route path="*" element={<LoginPage onLoggedIn={handleLoggedIn} />} /></Routes>;
  }

  return (
    <div className="app">
      <div className="topbar">
        <button className="theme-toggle" onClick={toggleTheme} title="切换主题">
          {theme === "dark" ? "☀️ 亮色" : "🌙 暗色"}
        </button>
      </div>
      <aside className="sidebar">
        <div className="logo">🛡️ AI 漏洞挖掘</div>
        <nav>
          <NavLink to="/" end className="nav-link">扫描任务</NavLink>
          <NavLink to="/tasks" className="nav-link">📋 任务管理</NavLink>
          <NavLink to="/findings" className="nav-link">漏洞清单</NavLink>
          <NavLink to="/rules" className="nav-link">⚙️ 规则配置</NavLink>
          <NavLink to="/status" className="nav-link">引擎状态</NavLink>
        </nav>
        {user && (
          <div style={{ marginTop: "auto", padding: "16px 24px", borderTop: "1px solid #334155", fontSize: 12 }}>
            <div style={{ color: "#94a3b8" }}>当前用户</div>
            <div style={{ color: "#e2e8f0", marginTop: 4 }}>{user.username} ({user.role})</div>
            <button className="secondary" style={{ marginTop: 8, padding: "4px 10px", fontSize: 12 }} onClick={logout}>登出</button>
          </div>
        )}
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<ScanPage />} />
          <Route path="/tasks" element={<TasksPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="/login" element={<LoginPage onLoggedIn={handleLoggedIn} />} />
        </Routes>
      </main>
    </div>
  );
}
