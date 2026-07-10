// src/pages/FindingsPage.jsx — 漏洞清单（按任务隔离）
import { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { api } from "../api.js";
import SeverityBadge from "../components/SeverityBadge.jsx";
import FindingDetail from "../components/FindingDetail.jsx";

export default function FindingsPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const scanId = searchParams.get("scanId");

  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState({ status: "", category: "" });
  const [expandedId, setExpandedId] = useState(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const f = { scanId };
      if (filter.status) f.status = filter.status;
      if (filter.category) f.category = filter.category;
      const data = await api.findings(f);
      setFindings(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (scanId) load();
    else setLoading(false);
  }, [scanId]); // eslint-disable-line

  // 没有 scanId → 提示去任务管理选任务
  if (!scanId) {
    return (
      <div>
        <h1>漏洞清单</h1>
        <div className="msg msg-info">
          请先在「任务管理」中选择一个已完成的任务，查看该任务的漏洞清单。
        </div>
        <button onClick={() => navigate("/tasks")}>前往任务管理 →</button>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>
          漏洞清单
          <span style={{ fontSize: 14, color: "var(--text-dim)", marginLeft: 12 }}>
            任务: {scanId}
          </span>
        </h1>
        <button className="secondary" onClick={() => navigate("/tasks")}>← 返回任务列表</button>
      </div>

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
          <label>类别</label>
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
        <div className="msg msg-info">该任务暂无漏洞（或筛选条件无匹配）</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>标题</th>
              <th>📍 位置</th>
              <th>类别</th>
              <th>严重度</th>
              <th>状态</th>
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
                  <td>{f.title}</td>
                  <td style={{ fontFamily: "monospace", fontSize: 12, color: "var(--accent)" }}>
                    {(f.location?.file || "?").split(/[\\/]/).pop()}:{f.location?.startLine || "?"}
                  </td>
                  <td><code>{f.category}</code></td>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td><span className={`badge badge-${f.status}`}>{f.status}</span></td>
                  <td>{(f.confidence * 100).toFixed(0)}%</td>
                  <td>{f.isZeroDay ? "⚠️" : ""}</td>
                </tr>
                {expandedId === f.findingId && (
                  <tr key={f.findingId + "-detail"}>
                    <td colSpan={8} style={{ background: "var(--bg)" }}>
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
