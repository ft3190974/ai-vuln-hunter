// src/pages/TasksPage.jsx — 任务管理页（扫描任务列表 + 按任务查看漏洞）
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";

export default function TasksPage() {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.listScans();
      setTasks(list);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // 每 3 秒刷新（更新运行中任务的状态）
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  const viewFindings = (scanId) => {
    navigate(`/tasks/${scanId}/findings`);
  };

  const deleteTask = async (scanId, e) => {
    e.stopPropagation();
    if (!confirm(`确定删除任务 ${scanId}？该任务的所有漏洞也会一起删除，不可恢复。`)) return;
    try {
      await api.deleteScan(scanId);
      await load();
    } catch (err) {
      setError(err.message);
    }
  };

  // 清理孤儿数据：任务已删但漏洞残留、或早期无 scanId 关联的漏洞
  const cleanupOrphans = async () => {
    if (!confirm("清理残留漏洞数据？\n\n这会删除所有没有对应任务记录的漏洞（任务已被删除但漏洞未清理的情况）。\n清理后态势总览数据会同步更新。")) return;
    try {
      const r = await api.cleanupOrphanFindings();
      alert(`清理完成：删除了 ${r.removed} 个残留漏洞，剩余 ${r.remaining} 个`);
      await load();
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading && tasks.length === 0) return <p className="loading">加载中...</p>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>任务管理</h1>
        <button
          className="secondary"
          style={{ fontSize: 13, padding: "6px 12px" }}
          onClick={cleanupOrphans}
          title="清理任务已删除但漏洞残留的数据，同步更新态势总览"
        >
          🧹 清理残留数据
        </button>
      </div>

      {error && <div className="msg msg-error">{error}</div>}

      {tasks.length === 0 ? (
        <div className="msg msg-info">
          暂无任务。去「扫描任务」页提交代码或上传文件开始挖掘。
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>任务 ID</th>
              <th>目标</th>
              <th>语言</th>
              <th>状态</th>
              <th>漏洞数</th>
              <th>开始时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((t) => (
              <tr key={t.scanId}>
                <td style={{ fontFamily: "monospace", fontSize: 12 }}>{t.scanId}</td>
                <td style={{ fontSize: 13, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {t.target}
                </td>
                <td><code>{t.language}</code></td>
                <td>
                  <span className={`badge badge-${t.status === "completed" ? "confirmed" : t.status === "failed" ? "false_positive" : "candidate"}`}>
                    {t.status === "running" ? "⏳ 运行中" : t.status === "completed" ? "✓ 完成" : t.status === "failed" ? "✗ 失败" : t.status}
                  </span>
                </td>
                <td style={{ fontWeight: 700, color: t.findingsCount > 0 ? "var(--accent)" : "var(--text-muted)" }}>
                  {t.findingsCount}
                </td>
                <td style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {t.startedAt ? new Date(t.startedAt).toLocaleString("zh-CN", { hour12: false }) : "—"}
                </td>
                <td>
                  {t.status === "completed" && (
                    <button
                      style={{ fontSize: 12, padding: "4px 10px", marginRight: 6 }}
                      onClick={(e) => { e.stopPropagation(); viewFindings(t.scanId); }}
                    >
                      查看漏洞 →
                    </button>
                  )}
                  <button
                    className="secondary"
                    style={{ fontSize: 12, padding: "4px 10px", color: "#fca5a5" }}
                    onClick={(e) => deleteTask(t.scanId, e)}
                  >
                    删除
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
