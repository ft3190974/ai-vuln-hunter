// src/pages/SettingsPage.jsx — 系统设置（LLM 配置 + 工具集成配置）
//
// 两个 Tab：
//   1. LLM 配置：添加/编辑/删除/测试多个大模型实例（GLM/OpenAI/Mock 等）
//   2. 工具集成：通过 MCP 接入 SAST/SCA/BAT/MST/FUZZ/DAST 等工具
import { useState, useEffect } from "react";
import { api } from "../api.js";

const TOOL_TYPES = [
  { value: "SAST", label: "SAST（静态代码分析）" },
  { value: "SCA", label: "SCA（组件分析）" },
  { value: "BAT", label: "BAT（二进制分析）" },
  { value: "MST", label: "MST（模型安全检测）" },
  { value: "FUZZ", label: "FUZZ（模糊测试）" },
  { value: "DAST", label: "DAST（动态分析）" },
  { value: "IAST", label: "IAST（交互式分析）" },
];

export default function SettingsPage() {
  const [tab, setTab] = useState("llm");

  return (
    <div>
      <h1>系统设置</h1>
      <div style={{ marginBottom: 16, borderBottom: "1px solid var(--border)" }}>
        <button className={tab === "llm" ? "" : "secondary"} style={{ marginRight: 4, padding: "8px 14px", borderRadius: "4px 4px 0 0", borderBottom: "none" }} onClick={() => setTab("llm")}>🧠 LLM 配置</button>
        <button className={tab === "tools" ? "" : "secondary"} style={{ padding: "8px 14px", borderRadius: "4px 4px 0 0", borderBottom: "none" }} onClick={() => setTab("tools")}>🔧 工具集成（MCP）</button>
      </div>
      {tab === "llm" && <LlmConfig />}
      {tab === "tools" && <ToolConfig />}
    </div>
  );
}

// ═══ LLM 配置 ═══
function LlmConfig() {
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null);
  const [testResult, setTestResult] = useState(null);

  const load = async () => { setLoading(true); try { setConfigs(await api.listLlmConfigs()); } finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  const test = async (id) => {
    setTestResult({ id, testing: true });
    try {
      const r = await api.testLlmConfig(id);
      setTestResult({ id, ...r });
    } catch (e) { setTestResult({ id, success: false, message: e.message }); }
  };

  if (loading) return <p className="loading">加载中...</p>;

  if (editing) {
    return (
      <div className="card">
        <h2>{editing.id ? "编辑 LLM 配置" : "添加 LLM 配置"}</h2>
        <div className="form-group"><label>名称 *</label><input value={editing.name || ""} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="如：GLM-4-Plus 生产" /></div>
        <div style={{ display: "flex", gap: 16 }}>
          <div className="form-group" style={{ flex: 1 }}><label>提供商</label>
            <select value={editing.provider || "glm"} onChange={(e) => setEditing({ ...editing, provider: e.target.value })}>
              <option value="glm">智谱 GLM</option><option value="openai">OpenAI</option><option value="mock">Mock（本地测试）</option><option value="custom">自定义</option>
            </select>
          </div>
          <div className="form-group" style={{ flex: 1 }}><label>模型</label><input value={editing.model || ""} onChange={(e) => setEditing({ ...editing, model: e.target.value })} placeholder="glm-4-plus" /></div>
        </div>
        <div className="form-group"><label>API 地址</label><input value={editing.baseUrl || ""} onChange={(e) => setEditing({ ...editing, baseUrl: e.target.value })} placeholder="https://open.bigmodel.cn/api/paas/v4" /></div>
        <div className="form-group"><label>API Key</label><input type="password" value={editing.apiKey || ""} onChange={(e) => setEditing({ ...editing, apiKey: e.target.value })} placeholder="你的 API Key" /></div>
        <div style={{ display: "flex", gap: 16 }}>
          <div className="form-group" style={{ flex: 1 }}><label>温度</label><input type="number" step="0.1" value={editing.temperature ?? 0.2} onChange={(e) => setEditing({ ...editing, temperature: Number(e.target.value) })} /></div>
          <div className="form-group" style={{ flex: 1 }}><label>最大 Token</label><input type="number" value={editing.maxTokens || 2048} onChange={(e) => setEditing({ ...editing, maxTokens: Number(e.target.value) })} /></div>
          <div className="form-group" style={{ flex: 1 }}><label>任务难度路由</label>
            <select value={editing.difficulty || "auto"} onChange={(e) => setEditing({ ...editing, difficulty: e.target.value })}>
              <option value="auto">自动</option><option value="low">低成本（归一化）</option><option value="medium">中等</option><option value="high">高精度（0-day/逻辑）</option>
            </select>
          </div>
        </div>
        <div style={{ display: "flex", gap: 12 }}>
          <button onClick={async () => {
            if (editing.id) await api.updateLlmConfig(editing.id, editing);
            else await api.createLlmConfig(editing);
            setEditing(null); await load();
          }}>💾 保存</button>
          <button className="secondary" onClick={() => setEditing(null)}>取消</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: 12 }}>
        <button onClick={() => setEditing({ provider: "glm", model: "glm-4-plus", temperature: 0.2, maxTokens: 2048, difficulty: "auto", enabled: true })}>+ 添加 LLM</button>
      </div>
      <table>
        <thead><tr><th>名称</th><th>提供商</th><th>模型</th><th>难度路由</th><th>状态</th><th>连通性</th><th>操作</th></tr></thead>
        <tbody>
          {configs.map((c) => (
            <tr key={c.id}>
              <td>{c.name}{c.isDefault && <span style={{ fontSize: 11, color: "var(--text-muted)" }}>（默认）</span>}</td>
              <td><code>{c.provider}</code></td>
              <td><code>{c.model}</code></td>
              <td>{c.difficulty}</td>
              <td><span className={`badge badge-${c.enabled ? "confirmed" : "false_positive"}`}>{c.enabled ? "启用" : "禁用"}</span></td>
              <td>{testResult?.id === c.id ? (testResult.testing ? "测试中..." : <span style={{ color: testResult.success ? "#86efac" : "#fca5a5" }}>{testResult.success ? "✓" : "✗"} {testResult.message?.slice(0, 30)}</span>) : "—"}</td>
              <td>
                <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 4 }} onClick={() => test(c.id)}>测试</button>
                <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 4 }} onClick={() => setEditing(c)}>编辑</button>
                {!c.isDefault && <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", color: "#fca5a5" }} onClick={async () => { await api.deleteLlmConfig(c.id); await load(); }}>删除</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 12 }}>
        提示：可配置多个 LLM 实例，按"难度路由"自动选择模型（低成本任务用便宜模型，高难度任务用强模型）。
      </p>
    </div>
  );
}

// ═══ 工具集成配置 ═══
function ToolConfig() {
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null);

  const load = async () => { setLoading(true); try { setConfigs(await api.listToolConfigs()); } finally { setLoading(false); } };
  useEffect(() => { load(); }, []);

  if (loading) return <p className="loading">加载中...</p>;

  if (editing) {
    return (
      <div className="card">
        <h2>{editing.id ? "编辑工具集成" : "添加工具集成"}</h2>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
          通过 MCP（Model Context Protocol）接入外部安全工具。配置后，编排引擎会自动调用这些工具获取扫描结果。
        </p>
        <div className="form-group"><label>名称 *</label><input value={editing.name || ""} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="如：软安 SAST 静兮" /></div>
        <div style={{ display: "flex", gap: 16 }}>
          <div className="form-group" style={{ flex: 1 }}><label>工具类型 *</label>
            <select value={editing.toolType || "SAST"} onChange={(e) => setEditing({ ...editing, toolType: e.target.value })}>
              {TOOL_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          <div className="form-group" style={{ flex: 1, marginBottom: 0, display: "flex", alignItems: "flex-end", gap: 8 }}>
            <input type="checkbox" id="autoRun" checked={editing.autoRun !== false} onChange={(e) => setEditing({ ...editing, autoRun: e.target.checked })} style={{ width: "auto" }} />
            <label htmlFor="autoRun" style={{ marginBottom: 0 }}>扫描时自动运行</label>
          </div>
        </div>
        <div className="form-group"><label>MCP 启动命令</label><input value={editing.mcpCommand || ""} onChange={(e) => setEditing({ ...editing, mcpCommand: e.target.value })} placeholder="node" /></div>
        <div className="form-group"><label>MCP 启动参数</label><input value={editing.mcpArgs || ""} onChange={(e) => setEditing({ ...editing, mcpArgs: e.target.value })} placeholder="/path/to/tool-mcp/server.js" /></div>
        <div className="form-group"><label>MCP HTTP URL（可选，与命令二选一）</label><input value={editing.mcpUrl || ""} onChange={(e) => setEditing({ ...editing, mcpUrl: e.target.value })} placeholder="http://localhost:8080/mcp" /></div>
        <div style={{ display: "flex", gap: 12 }}>
          <button onClick={async () => {
            if (editing.id) await api.updateToolConfig(editing.id, editing);
            else await api.createToolConfig(editing);
            setEditing(null); await load();
          }}>💾 保存</button>
          <button className="secondary" onClick={() => setEditing(null)}>取消</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: 12 }}>
        <button onClick={() => setEditing({ toolType: "SAST", autoRun: true, enabled: true })}>+ 添加工具</button>
      </div>
      <table>
        <thead><tr><th>名称</th><th>类型</th><th>MCP 命令/URL</th><th>自动运行</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          {configs.map((c) => (
            <tr key={c.id}>
              <td>{c.name}{c.isExample && <span style={{ fontSize: 11, color: "var(--text-muted)" }}>（示例）</span>}</td>
              <td><span className="badge badge-info">{c.toolType}</span></td>
              <td style={{ fontSize: 12, fontFamily: "monospace" }}>{c.mcpCommand} {c.mcpArgs || c.mcpUrl || "—"}</td>
              <td>{c.autoRun ? "✓" : "✗"}</td>
              <td><span className={`badge badge-${c.enabled ? "confirmed" : "false_positive"}`}>{c.enabled ? "启用" : "禁用"}</span></td>
              <td>
                <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 4 }} onClick={() => setEditing(c)}>编辑</button>
                {!c.isExample && <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", color: "#fca5a5" }} onClick={async () => { await api.deleteToolConfig(c.id); await load(); }}>删除</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="msg msg-info" style={{ marginTop: 12, fontSize: 12 }}>
        💡 通过 MCP 协议接入外部工具。每个工具配置 MCP server 的启动命令或 URL，编排引擎会按工具类型自动调用。
        <br />支持类型：SAST / SCA / BAT / MST / FUZZ / DAST / IAST
      </div>
    </div>
  );
}
