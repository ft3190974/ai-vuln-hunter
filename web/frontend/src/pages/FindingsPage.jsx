// src/pages/FindingsPage.jsx — 漏洞清单（全局汇总，标注所属任务）
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import FindingDetail from "../components/FindingDetail.jsx";

export default function FindingsPage() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState({ status: "", category: "" });
  const [expandedId, setExpandedId] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const f = {};
      if (filter.status) f.status = filter.status;
      if (filter.category) f.category = filter.category;
      const data = await api.findings(f);
      // 按时间倒序（最新任务的漏洞在前）
      data.sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));
      setFindings(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []); // eslint-disable-line

  return (
    <div>
      <h1>漏洞清单</h1>
      <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 16 }}>
        所有任务的漏洞汇总。每条漏洞标注所属任务，点击行展开查看详情。
      </p>

      {/* 筛选 */}
      <div className="card" style={{ display: "flex", gap: 16, alignItems: "flex-end" }}>
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
          <select value={filter.category} onChange={(e) => setFilter({ ...filter, category: e.target.value })}>
            <option value="">全部</option>
            <option value="sqli">SQL 注入</option>
            <option value="cmdi">命令注入</option>
            <option value="xss">XSS</option>
            <option value="authz">越权</option>
            <option value="business_logic">业务逻辑</option>
            <option value="overflow">缓冲区溢出</option>
            <option value="double_free">Double-Free</option>
            <option value="uaf">UAF/泄漏</option>
            <option value="fmt_string">格式化字符串</option>
            <option value="deserialization">反序列化</option>
            <option value="config">配置/硬编码</option>
          </select>
        </div>
        <button onClick={load} disabled={loading}>{loading ? "加载中..." : "查询"}</button>
      </div>

      {error && <div className="msg msg-error">{error}</div>}

      {loading ? (
        <p className="loading">加载中...</p>
      ) : findings.length === 0 ? (
        <div className="msg msg-info">
          暂无漏洞。去「扫描任务」页提交代码，或「任务管理」查看已完成的任务。
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>漏洞 ID</th>
              <th>漏洞类型</th>
              <th>所属任务</th>
              <th>严重度</th>
              <th>置信度</th>
              <th>0-day</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <>
                <tr
                  key={f.findingId}
                  style={{ cursor: "pointer" }}
                  onClick={() => setExpandedId(expandedId === f.findingId ? null : f.findingId)}
                >
                  <td style={{ fontFamily: "monospace", fontSize: 12 }}>{f.findingId}</td>
                  <td><code>{f.category}</code></td>
                  <td style={{ fontSize: 12 }}>
                    {f.scanId ? (
                      <a
                        href="#"
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); navigate(`/tasks`); }}
                        style={{ color: "var(--accent)", textDecoration: "none" }}
                      >
                        {f.scanId}
                      </a>
                    ) : "—"}
                  </td>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>{(f.confidence * 100).toFixed(0)}%</td>
                  <td>{f.isZeroDay ? "⚠️" : ""}</td>
                </tr>
                {expandedId === f.findingId && (
                  <tr key={f.findingId + "-detail"}>
                    <td colSpan={6} style={{ background: "var(--bg)" }}>
                      <FindingDetail finding={f} />
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
