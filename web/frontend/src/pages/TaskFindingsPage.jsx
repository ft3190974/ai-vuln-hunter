// src/pages/TaskFindingsPage.jsx — 任务漏洞详情（二级页面）
//
// 从任务管理「查看漏洞」进入，只显示该任务的漏洞。
// 和漏洞清单（全局汇总）分开，互不影响。
import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import FindingDetail from "../components/FindingDetail.jsx";

function getVulnType(f) {
  if (f.isZeroDay) return "zeroday";
  if (f.linkedCves && f.linkedCves.length > 0) return "known";
  if (f.sources?.[0]?.toolId === "ai-security-hunter") {
    const rule = f.sources?.[0]?.rawRuleId || "";
    if (rule.startsWith("AI-SKILL") || rule.startsWith("AI-MCP")) return "ai_mcp";
    if (rule.startsWith("AI-MODEL")) return "ai_model";
    return "ai_logic";
  }
  if (f.category === "business_logic") return "logic";
  if (f.sources?.[0]?.toolId === "llm-hunter" || f.sources?.[0]?.toolId === "c-hunter" || f.sources?.[0]?.toolId === "binary-hunter") return "logic";
  return "logic";
}

const TYPE_LABELS = {
  known: { label: "已知漏洞", color: "#3b82f6", icon: "📋" },
  logic: { label: "逻辑漏洞", color: "#14b8a6", icon: "🧩" },
  zeroday: { label: "0-day", color: "#fbbf24", icon: "⚡" },
  ai_logic: { label: "LLM 应用逻辑", color: "#a855f7", icon: "🧠" },
  ai_mcp: { label: "Skill/MCP", color: "#ec4899", icon: "🔧" },
  ai_model: { label: "模型项目", color: "#6366f1", icon: "🤖" },
};

export default function TaskFindingsPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState({ status: "", type: "" });
  const [expandedId, setExpandedId] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      let data = await api.findings({ scanId });
      if (filter.status) data = data.filter((f) => f.status === filter.status);
      if (filter.type) data = data.filter((f) => getVulnType(f) === filter.type);
      data.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      setFindings(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [scanId, filter.status, filter.type]); // eslint-disable-line

  // 统计三类
  const counts = { known: 0, logic: 0, zeroday: 0, ai_logic: 0, ai_mcp: 0, ai_model: 0 };
  // 需要全量数据统计
  const [allData, setAllData] = useState([]);
  useEffect(() => {
    api.findings({ scanId }).then((d) => { setAllData(d); }).catch(() => {});
  }, [scanId]); // eslint-disable-line
  for (const f of allData) counts[getVulnType(f)]++;

  return (
    <div>
      {/* 顶部：返回 + 任务标识 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 20 }}>
            任务漏洞详情
          </h1>
          <span style={{ fontSize: 13, color: "var(--text-dim)" }}>
            任务 ID: <code style={{ color: "var(--accent)" }}>{scanId}</code>
          </span>
        </div>
        <button className="secondary" onClick={() => navigate("/tasks")}>← 返回任务列表</button>
      </div>

      {/* 三分类汇总 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
        {Object.entries(TYPE_LABELS).map(([key, cfg]) => (
          <div
            key={key}
            onClick={() => setFilter({ ...filter, type: filter.type === key ? "" : key })}
            className="stat-card"
            style={{ cursor: "pointer", borderTop: "3px solid " + cfg.color, background: filter.type === key ? cfg.color + "15" : "var(--bg-elev)" }}
          >
            <div className="stat-label">{cfg.icon} {cfg.label}</div>
            <div className="stat-value" style={{ color: cfg.color }}>{counts[key]}</div>
          </div>
        ))}
      </div>

      {/* 筛选 */}
      <div className="card" style={{ display: "flex", gap: 16, alignItems: "flex-end", marginBottom: 12 }}>
        <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
          <label>状态</label>
          <select value={filter.status} onChange={(e) => setFilter({ ...filter, status: e.target.value })}>
            <option value="">全部</option>
            <option value="candidate">候选</option>
            <option value="confirmed">已确认</option>
            <option value="false_positive">误报</option>
            <option value="fixed">已修复</option>
          </select>
        </div>
        <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
          <label>漏洞类型</label>
          <select value={filter.type} onChange={(e) => setFilter({ ...filter, type: e.target.value })}>
            <option value="">全部</option>
            <option value="known">📋 已知漏洞</option>
            <option value="logic">🧩 逻辑漏洞</option>
            <option value="zeroday">⚡ 0-day</option>
          </select>
        </div>
      </div>

      {error && <div className="msg msg-error">{error}</div>}

      {loading ? (
        <p className="loading">加载中...</p>
      ) : findings.length === 0 ? (
        <div className="msg msg-info">该任务暂无漏洞</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>漏洞 ID</th>
              <th>类型</th>
              <th>漏洞分类</th>
              <th>严重度</th>
              <th>置信度</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => {
              const vt = getVulnType(f);
              const cfg = TYPE_LABELS[vt];
              return (
                <>
                  <tr key={f.findingId} style={{ cursor: "pointer" }} onClick={() => setExpandedId(expandedId === f.findingId ? null : f.findingId)}>
                    <td style={{ fontFamily: "monospace", fontSize: 12 }}>{f.findingId}</td>
                    <td><code>{f.category}</code></td>
                    <td><span className="badge" style={{ background: cfg.color + "30", color: cfg.color }}>{cfg.icon} {cfg.label}</span></td>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td>{(f.confidence * 100).toFixed(0)}%</td>
                  </tr>
                  {expandedId === f.findingId && (
                    <tr key={f.findingId + "-detail"}>
                      <td colSpan={5} style={{ background: "var(--bg)" }}>
                        <FindingDetail finding={f} />
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
