// src/pages/StatusPage.jsx — 引擎状态页（含计数动画）
import { useState, useEffect } from "react";
import { api } from "../api.js";
import { useCountUp } from "../hooks/useCountUp.js";

function StatCard({ label, value, sub }) {
  const animated = useCountUp(value);
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{animated}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export default function StatusPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const d = await api.status();
      setData(d);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const sync = async () => {
    setSyncing(true);
    try { await api.syncVulnDb(); await load(); }
    finally { setSyncing(false); }
  };

  if (loading) return <p className="loading">加载中...</p>;
  if (!data) return null;
  const { engine, vulnDb } = data;

  return (
    <div>
      <h1>引擎状态</h1>

      <h2>编排引擎</h2>
      <div className="card-grid">
        <StatCard label="误报库模式" value={engine.fpPatterns} sub="条过滤规则" />
        <StatCard label="知识图谱节点" value={engine.knowledgeGraph.nodes} sub={`${engine.knowledgeGraph.edges} 条边`} />
        <StatCard label="判定规则" value={engine.rules} sub="条规则" />
        <StatCard label="Finding 总数" value={engine.findings.total} sub={JSON.stringify(engine.findings.byStatus)} />
      </div>

      <h2>漏洞库同步</h2>
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <span style={{ fontSize: 14, color: "var(--text-dim)" }}>
            模式: <code>{vulnDb.live ? "live（联网）" : "mock"}</code>
            {vulnDb.lastSyncAt ? ` · 最后同步: ${vulnDb.lastSyncAt}` : " · 未同步"}
          </span>
          <button onClick={sync} disabled={syncing}>
            {syncing ? "同步中..." : "立即同步"}
          </button>
        </div>
        <table>
          <thead>
            <tr><th>数据源</th><th>启用</th><th>入库数</th><th>最后同步</th><th>错误</th></tr>
          </thead>
          <tbody>
            {vulnDb.sources.map((s) => (
              <tr key={s.source}>
                <td><code>{s.source}</code></td>
                <td>{s.enabled ? "✓" : "✗"}</td>
                <td>{s.lastSyncCount}</td>
                <td style={{ fontSize: 12 }}>{s.lastSyncAt || "—"}</td>
                <td style={{ color: s.lastError ? "#fca5a5" : "var(--text-muted)", fontSize: 12 }}>
                  {s.lastError || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
