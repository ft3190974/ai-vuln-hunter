// src/pages/FindingsPage.jsx — 漏洞清单（全局汇总 + 三类分类）
//
// 漏洞分类：
//   已知漏洞（linkedCves 不空的 / 来源是工具的）
//   逻辑漏洞（category === business_logic）
//   0-day（isZeroDay === true）
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import FindingDetail from "../components/FindingDetail.jsx";

// 漏洞分类判定
function getVulnType(f) {
  if (f.isZeroDay) return "zeroday";
  if (f.category === "business_logic") return "logic";
  if (f.linkedCves && f.linkedCves.length > 0) return "known";
  // 无 CVE 号 + 非 business_logic + 非 0-day → 也算逻辑（LLM 发现的代码缺陷）
  if (f.sources?.[0]?.toolId === "llm-hunter" || f.sources?.[0]?.toolId === "c-hunter" || f.sources?.[0]?.toolId === "binary-hunter") return "logic";
  return "logic";
}

const TYPE_CONFIG = {
  known:   { label: "已知漏洞", color: "#3b82f6", icon: "📋", desc: "有 CVE 编号的已公开漏洞（未来接 SCA 后自动填充）" },
  logic:   { label: "逻辑漏洞", color: "#14b8a6", icon: "🧩", desc: "LLM 自主发现的业务逻辑/代码缺陷（SAST 工具发现不了的）" },
  zeroday: { label: "0-day",    color: "#fbbf24", icon: "⚡", desc: "基于已知漏洞变种外推的未知漏洞候选" },
};

export default function FindingsPage() {
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
      let data = await api.findings({});
      // 按时间倒序
      data.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      // 本地按类型过滤
      if (filter.type) {
        data = data.filter((f) => getVulnType(f) === filter.type);
      }
      if (filter.status) {
        data = data.filter((f) => f.status === filter.status);
      }
      setFindings(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [filter]); // eslint-disable-line

  // 统计三类数量
  const counts = { known: 0, logic: 0, zeroday: 0 };
  // 需要从全量数据统计（不受当前 filter 影响）
  const [allFindings, setAllFindings] = useState([]);
  useEffect(() => {
    api.findings({}).then((data) => {
      setAllFindings(data);
      for (const f of data) counts[getVulnType(f)]++;
    }).catch(() => {});
  }, []); // eslint-disable-line

  for (const f of allFindings) counts[getVulnType(f)]++;

  return (
    <div>
      <h1>漏洞清单</h1>
      <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 16 }}>
        所有任务的漏洞汇总，按类型分类。点击行展开查看详情。
      </p>

      {/* 三类汇总卡（可点击筛选） */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 20 }}>
        {Object.entries(TYPE_CONFIG).map(([key, cfg]) => (
          <div
            key={key}
            onClick={() => setFilter({ ...filter, type: filter.type === key ? "" : key })}
            className="stat-card"
            style={{
              cursor: "pointer",
              borderTop: `3px solid ${cfg.color}`,
              background: filter.type === key ? cfg.color + "15" : "var(--bg-elev)",
              transition: "all 0.15s",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div className="stat-label">{cfg.icon} {cfg.label}</div>
                <div className="stat-value" style={{ color: cfg.color }}>{counts[key]}</div>
              </div>
              {filter.type === key && <span style={{ fontSize: 20, color: cfg.color }}>●</span>}
            </div>
            <div className="stat-sub" style={{ marginTop: 4 }}>{cfg.desc}</div>
          </div>
        ))}
      </div>

      {/* 状态筛选 */}
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
        <div className="msg msg-info">
          {filter.type ? `暂无${TYPE_CONFIG[filter.type].label}，去「扫描任务」页提交代码挖掘。` : "暂无漏洞。去「扫描任务」页提交代码，或「任务管理」查看已完成的任务。"}
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>漏洞 ID</th>
              <th>类型</th>
              <th>漏洞分类</th>
              <th>所属任务</th>
              <th>严重度</th>
              <th>置信度</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => {
              const vt = getVulnType(f);
              const cfg = TYPE_CONFIG[vt];
              return (
                <>
                  <tr
                    key={f.findingId}
                    style={{ cursor: "pointer" }}
                    onClick={() => setExpandedId(expandedId === f.findingId ? null : f.findingId)}
                  >
                    <td style={{ fontFamily: "monospace", fontSize: 12 }}>{f.findingId}</td>
                    <td><code>{f.category}</code></td>
                    <td>
                      <span className="badge" style={{ background: cfg.color + "30", color: cfg.color }}>
                        {cfg.icon} {cfg.label}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--text-dim)" }}>{f.scanId || "—"}</td>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td>{(f.confidence * 100).toFixed(0)}%</td>
                  </tr>
                  {expandedId === f.findingId && (
                    <tr key={f.findingId + "-detail"}>
                      <td colSpan={6} style={{ background: "var(--bg)" }}>
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
