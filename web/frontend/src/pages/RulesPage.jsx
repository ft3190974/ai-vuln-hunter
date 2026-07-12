// src/pages/RulesPage.jsx — 自定义漏洞挖掘规则管理（含三大分类）
//
// 规则分类：
//   逻辑漏洞规则：业务逻辑/状态机/金额/幂等等 SAST 工具发现不了的
//   代码漏洞规则：注入/溢出/反序列化等代码层面缺陷
//   固件漏洞规则：硬编码/弱加密/暴露面等二进制固件缺陷
import { useState, useEffect } from "react";
import { api } from "../api.js";

const EMPTY_RULE = {
  name: "",
  ruleDomain: "logic",
  category: "business_logic",
  severity: "high",
  languages: "",
  description: "",
  detectionHints: "",
  sinks: "",
  exampleVulnerable: "",
  exampleSafe: "",
};

const DOMAIN_CONFIG = {
  logic: { label: "逻辑漏洞规则", short: "逻辑漏洞", icon: "🧩", color: "#14b8a6", desc: "业务逻辑/状态机/金额/幂等等 SAST 发现不了的" },
  code: { label: "代码漏洞规则", short: "代码漏洞", icon: "💻", color: "#3b82f6", desc: "注入/溢出/反序列化等代码层面缺陷" },
  firmware: { label: "固件漏洞规则", short: "固件漏洞", icon: "🔌", color: "#f97316", desc: "硬编码/弱加密/暴露面等二进制固件缺陷" },
  ai_logic: { label: "LLM 应用逻辑漏洞", short: "LLM 逻辑", icon: "🧠", color: "#a855f7", desc: "提示词注入/越狱/信息泄露/输出注入/不安全函数调用" },
  ai_mcp: { label: "Skill/MCP 漏洞", short: "Skill/MCP", icon: "🔧", color: "#ec4899", desc: "Skill 命令注入/MCP 路径穿越/权限提升/数据泄露" },
  ai_model: { label: "模型项目代码漏洞", short: "模型项目", icon: "🤖", color: "#6366f1", desc: "推理服务 RCE/模型反序列化/未授权访问/数据投毒" },
};

const CATEGORY_OPTIONS = {
  logic: [
    { value: "business_logic", label: "业务逻辑" },
    { value: "authz", label: "越权/认证" },
    { value: "authn", label: "认证缺陷" },
  ],
  code: [
    { value: "sqli", label: "SQL 注入" },
    { value: "cmdi", label: "命令注入" },
    { value: "xss", label: "XSS" },
    { value: "overflow", label: "缓冲区溢出" },
    { value: "fmt_string", label: "格式化字符串" },
    { value: "deserialization", label: "反序列化" },
    { value: "integer_overflow", label: "整数溢出" },
    { value: "double_free", label: "Double-Free" },
    { value: "uaf", label: "UAF/泄漏" },
    { value: "path_traversal", label: "路径穿越" },
    { value: "ssrf", label: "SSRF" },
  ],
  firmware: [
    { value: "config", label: "配置缺陷" },
    { value: "hardcoded_secret", label: "硬编码凭据" },
    { value: "crypto_weak", label: "弱加密" },
  ],
  ai_logic: [
    { value: "prompt_injection", label: "提示词注入" },
    { value: "jailbreak", label: "越狱防护" },
    { value: "info_leak", label: "信息泄露" },
    { value: "output_injection", label: "输出注入" },
    { value: "unsafe_tool_use", label: "不安全函数调用" },
  ],
  ai_mcp: [
    { value: "cmdi", label: "Skill 命令注入" },
    { value: "path_traversal", label: "MCP 路径穿越" },
    { value: "authz", label: "MCP 权限提升" },
  ],
  ai_model: [
    { value: "cmdi", label: "推理服务 RCE" },
    { value: "deserialization", label: "模型反序列化" },
    { value: "authz", label: "未授权访问" },
    { value: "business_logic", label: "数据投毒" },
  ],
};

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState(EMPTY_RULE);
  const [error, setError] = useState(null);
  const [domainFilter, setDomainFilter] = useState("");

  const load = async () => {
    setLoading(true);
    try { setRules(await api.listRules()); } catch (e) { setError(e.message); } finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const startCreate = () => { setForm(EMPTY_RULE); setEditing({ isNew: true }); setError(null); };
  const startEdit = (rule) => {
    setForm({
      name: rule.name, ruleDomain: rule.ruleDomain || "logic", category: rule.category,
      severity: rule.severity, languages: (rule.languages || []).join(","),
      description: rule.description || "", detectionHints: rule.detectionHints || "",
      sinks: (rule.sinks || []).join(","), exampleVulnerable: rule.exampleVulnerable || "",
      exampleSafe: rule.exampleSafe || "",
    });
    setEditing({ isNew: false, ruleId: rule.ruleId }); setError(null);
  };

  const save = async () => {
    try {
      if (!form.name.trim() || !form.description.trim()) { setError("规则名称和描述必填"); return; }
      const body = { ...form, languages: form.languages.split(",").map(s=>s.trim()).filter(Boolean), sinks: form.sinks.split(",").map(s=>s.trim()).filter(Boolean) };
      if (editing.isNew) await api.createRule(body); else await api.updateRule(editing.ruleId, body);
      setEditing(null); await load();
    } catch (e) { setError(e.message); }
  };

  const toggle = async (id) => { try { await api.toggleRule(id); await load(); } catch (e) { setError(e.message); } };
  const remove = async (id, origin) => {
    if (origin === "builtin") { setError("内置规则不可删除"); return; }
    if (!confirm("确定删除？")) return;
    try { await api.deleteRule(id); await load(); } catch (e) { setError(e.message); }
  };

  if (loading) return <p className="loading">加载中...</p>;

  // ── 编辑/新建 ──
  if (editing) {
    const cats = CATEGORY_OPTIONS[form.ruleDomain] || CATEGORY_OPTIONS.logic;
    return (
      <div>
        <h1>{editing.isNew ? "新建规则" : "编辑规则"}</h1>
        <div className="card">
          {/* 规则分类选择 */}
          <div className="form-group">
            <label>规则分类 *</label>
            <div style={{ display: "flex", gap: 8 }}>
              {Object.entries(DOMAIN_CONFIG).map(([key, cfg]) => (
                <div key={key} onClick={() => setForm({ ...form, ruleDomain: key, category: (CATEGORY_OPTIONS[key] && CATEGORY_OPTIONS[key][0] ? CATEGORY_OPTIONS[key][0].value : "unknown") })}
                  className="stat-card" style={{ cursor: "pointer", flex: 1, padding: 14, borderTop: form.ruleDomain === key ? "3px solid " + cfg.color : "3px solid transparent", background: form.ruleDomain === key ? cfg.color + "15" : "var(--bg-elev)" }}>
                  <div style={{ fontSize: 20 }}>{cfg.icon}</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: form.ruleDomain === key ? cfg.color : "var(--text-dim)", marginTop: 4 }}>{cfg.label}</div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>{cfg.desc}</div>
                </div>
              ))}
            </div>
          </div>
          <div className="form-group"><label>规则名称 *</label><input value={form.name} onChange={(e)=>setForm({...form,name:e.target.value})} placeholder="例：未校验属主的资源查询" /></div>
          <div style={{ display: "flex", gap: 16 }}>
            <div className="form-group" style={{ flex: 1 }}>
              <label>漏洞类别</label>
              <select value={form.category} onChange={(e)=>setForm({...form,category:e.target.value})}>{cats.map((c)=> <option key={c.value} value={c.value}>{c.label}</option>)}</select>
            </div>
            <div className="form-group" style={{ flex: 1 }}>
              <label>严重度</label>
              <select value={form.severity} onChange={(e)=>setForm({...form,severity:e.target.value})}>
                <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
              </select>
            </div>
          </div>
          <div className="form-group"><label>适用语言（逗号分隔，留空=全语言）</label><input value={form.languages} onChange={(e)=>setForm({...form,languages:e.target.value})} placeholder="例：java,python" /></div>
          <div className="form-group"><label>规则描述 *</label><textarea value={form.description} onChange={(e)=>setForm({...form,description:e.target.value})} placeholder="例：按 ID 查询资源时未校验属主" style={{ minHeight: 80 }} /></div>
          <div className="form-group"><label>检测提示</label><textarea value={form.detectionHints} onChange={(e)=>setForm({...form,detectionHints:e.target.value})} placeholder="例：关注 findById 等调用" style={{ minHeight: 80 }} /></div>
          <div className="form-group"><label>关注关键词（逗号分隔）</label><input value={form.sinks} onChange={(e)=>setForm({...form,sinks:e.target.value})} placeholder="例：findById,getById" /></div>
          <div className="form-group"><label>漏洞代码示例（可选）</label><textarea value={form.exampleVulnerable} onChange={(e)=>setForm({...form,exampleVulnerable:e.target.value})} style={{ minHeight: 80, fontFamily: "Consolas, monospace" }} /></div>
          <div className="form-group"><label>安全代码示例（可选）</label><textarea value={form.exampleSafe} onChange={(e)=>setForm({...form,exampleSafe:e.target.value})} style={{ minHeight: 80, fontFamily: "Consolas, monospace" }} /></div>
          {error && <div className="msg msg-error">{error}</div>}
          <div style={{ display: "flex", gap: 12 }}><button onClick={save}>💾 保存</button><button className="secondary" onClick={()=>setEditing(null)}>取消</button></div>
        </div>
      </div>
    );
  }

  // ── 列表 ──
  const filtered = domainFilter ? rules.filter((r) => (r.ruleDomain || "logic") === domainFilter) : rules;
  const counts = { logic: 0, code: 0, firmware: 0, ai_logic: 0, ai_mcp: 0, ai_model: 0 };
  for (const r of rules) counts[r.ruleDomain || "logic"]++;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>规则配置</h1>
        <button onClick={startCreate}>+ 新建规则</button>
      </div>

      {/* 六分类汇总卡 */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 20 }}>
        {Object.entries(DOMAIN_CONFIG).map(([key, cfg]) => (
          <div key={key} onClick={() => setDomainFilter(domainFilter === key ? "" : key)} className="stat-card"
            style={{ cursor: "pointer", borderTop: "3px solid " + cfg.color, background: domainFilter === key ? cfg.color + "15" : "var(--bg-elev)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div><div className="stat-label">{cfg.icon} {cfg.label}</div><div className="stat-value" style={{ color: cfg.color }}>{counts[key]}</div></div>
              {domainFilter === key && <span style={{ fontSize: 20, color: cfg.color }}>●</span>}
            </div>
            <div className="stat-sub" style={{ marginTop: 4 }}>{cfg.desc}</div>
          </div>
        ))}
      </div>

      {error && <div className="msg msg-error">{error}</div>}

      <table>
        <thead>
          <tr><th>规则名称</th><th>分类</th><th>类别</th><th>严重度</th><th>来源</th><th>状态</th><th>操作</th></tr>
        </thead>
        <tbody>
          {filtered.map((r) => {
            const dom = DOMAIN_CONFIG[r.ruleDomain || "logic"] || DOMAIN_CONFIG.logic;
            return (
              <tr key={r.ruleId}>
                <td><div style={{ fontWeight: 600 }}>{r.name}</div><div style={{ fontSize: 12, color: "var(--text-muted)", maxWidth: 350, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.description}</div></td>
                <td><span className="badge" style={{ background: dom.color + "30", color: dom.color }}>{dom.icon} {dom.short}</span></td>
                <td><code>{r.category}</code></td>
                <td><span className={"badge badge-" + r.severity}>{r.severity}</span></td>
                <td>{r.origin === "builtin" ? "内置" : "自定义"}</td>
                <td><span className={"badge badge-" + (r.enabled ? "confirmed" : "false_positive")}>{r.enabled ? "启用" : "禁用"}</span></td>
                <td>
                  <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 6 }} onClick={()=>toggle(r.ruleId)}>{r.enabled ? "禁用" : "启用"}</button>
                  <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 6 }} onClick={()=>startEdit(r)}>编辑</button>
                  {r.origin !== "builtin" && <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", color: "#fca5a5" }} onClick={()=>remove(r.ruleId, r.origin)}>删除</button>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {filtered.length === 0 && <div className="msg msg-info">暂无规则，点「+ 新建规则」开始</div>}
    </div>
  );
}
