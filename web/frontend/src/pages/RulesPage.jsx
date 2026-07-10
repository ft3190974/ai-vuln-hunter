// src/pages/RulesPage.jsx — 自定义漏洞挖掘规则管理
//
// 让用户持续"喂"漏洞挖掘方法/缺陷代码规则给系统。
// 创建的规则会在 LLM 自主挖掘时自动加载使用。
import { useState, useEffect } from "react";
import { api } from "../api.js";

const EMPTY_RULE = {
  name: "",
  category: "business_logic",
  severity: "high",
  languages: "",
  description: "",
  detectionHints: "",
  sinks: "",
  exampleVulnerable: "",
  exampleSafe: "",
};

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(null); // null=列表模式；对象=编辑模式
  const [form, setForm] = useState(EMPTY_RULE);
  const [error, setError] = useState(null);

  const load = async () => {
    setLoading(true);
    try { setRules(await api.listRules()); }
    catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const startCreate = () => { setForm(EMPTY_RULE); setEditing({ isNew: true }); setError(null); };
  const startEdit = (rule) => {
    setForm({
      name: rule.name, category: rule.category, severity: rule.severity,
      languages: (rule.languages || []).join(","), description: rule.description || "",
      detectionHints: rule.detectionHints || "", sinks: (rule.sinks || []).join(","),
      exampleVulnerable: rule.exampleVulnerable || "", exampleSafe: rule.exampleSafe || "",
    });
    setEditing({ isNew: false, ruleId: rule.ruleId });
    setError(null);
  };

  const save = async () => {
    try {
      if (!form.name.trim() || !form.description.trim()) {
        setError("规则名称和描述必填");
        return;
      }
      const body = {
        ...form,
        languages: form.languages.split(",").map((s) => s.trim()).filter(Boolean),
        sinks: form.sinks.split(",").map((s) => s.trim()).filter(Boolean),
      };
      if (editing.isNew) {
        await api.createRule(body);
      } else {
        await api.updateRule(editing.ruleId, body);
      }
      setEditing(null);
      await load();
    } catch (e) { setError(e.message); }
  };

  const toggle = async (ruleId) => {
    try { await api.toggleRule(ruleId); await load(); }
    catch (e) { setError(e.message); }
  };

  const remove = async (ruleId, source) => {
    if (source === "builtin") { setError("内置规则不可删除"); return; }
    if (!confirm("确定删除这条规则？")) return;
    try { await api.deleteRule(ruleId); await load(); }
    catch (e) { setError(e.message); }
  };

  if (loading) return <p className="loading">加载中...</p>;

  // ── 编辑/新建模式 ──
  if (editing) {
    return (
      <div>
        <h1>{editing.isNew ? "新建漏洞挖掘规则" : "编辑规则"}</h1>
        <div className="card">
          <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 16 }}>
            描述"什么样的代码有什么漏洞、该怎么判定"。LLM 在分析代码时会按你的描述挖掘。
            持续添加规则，系统的挖掘能力会越来越强。
          </p>

          <div className="form-group">
            <label>规则名称 *</label>
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="例：未校验属主的资源查询" />
          </div>

          <div style={{ display: "flex", gap: 16 }}>
            <div className="form-group" style={{ flex: 1 }}>
              <label>漏洞类别</label>
              <select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>
                <option value="business_logic">业务逻辑</option>
                <option value="authz">越权/认证</option>
                <option value="sqli">SQL 注入</option>
                <option value="cmdi">命令注入</option>
                <option value="xss">XSS</option>
                <option value="deserialization">反序列化</option>
                <option value="overflow">缓冲区溢出</option>
                <option value="crypto_weak">弱加密</option>
                <option value="config">配置缺陷</option>
                <option value="unknown">其他</option>
              </select>
            </div>
            <div className="form-group" style={{ flex: 1 }}>
              <label>严重度</label>
              <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div className="form-group">
            <label>适用语言（逗号分隔，留空=全语言）</label>
            <input value={form.languages} onChange={(e) => setForm({ ...form, languages: e.target.value })}
              placeholder="例：java,python（留空则适用所有语言）" />
          </div>

          <div className="form-group">
            <label>规则描述 *（核心：什么样的代码有什么漏洞）</label>
            <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="例：按 ID 查询/修改资源时，未校验当前用户是该资源的属主，导致可遍历他人数据"
              style={{ minHeight: 80 }} />
          </div>

          <div className="form-group">
            <label>检测提示（告诉 LLM 该关注哪些代码模式）</label>
            <textarea value={form.detectionHints} onChange={(e) => setForm({ ...form, detectionHints: e.target.value })}
              placeholder="例：关注 findById/getById/getOrder 等按 ID 取资源的调用，检查是否有 isOwner/@PreAuthorize/currentUser 等属主校验"
              style={{ minHeight: 80 }} />
          </div>

          <div className="form-group">
            <label>关注关键词（逗号分隔，用于初筛代码，省 LLM 调用）</label>
            <input value={form.sinks} onChange={(e) => setForm({ ...form, sinks: e.target.value })}
              placeholder="例：findById,getById,getOrder（留空则每段代码都查）" />
          </div>

          <div className="form-group">
            <label>漏洞代码示例（可选，给 LLM 参考，提高准确率）</label>
            <textarea value={form.exampleVulnerable} onChange={(e) => setForm({ ...form, exampleVulnerable: e.target.value })}
              placeholder={"public Order getOrder(Long id) {\n  return orderRepo.findById(id); // 未校验属主\n}"}
              style={{ minHeight: 100, fontFamily: "Consolas, monospace" }} />
          </div>

          <div className="form-group">
            <label>安全代码示例（可选，给 LLM 对比参考）</label>
            <textarea value={form.exampleSafe} onChange={(e) => setForm({ ...form, exampleSafe: e.target.value })}
              placeholder={"public Order getOrder(Long id) {\n  Order o = orderRepo.findById(id);\n  if (!o.getUserId().equals(currentUserId())) throw new Forbidden();\n  return o;\n}"}
              style={{ minHeight: 100, fontFamily: "Consolas, monospace" }} />
          </div>

          {error && <div className="msg msg-error">{error}</div>}

          <div style={{ display: "flex", gap: 12 }}>
            <button onClick={save}>💾 保存</button>
            <button className="secondary" onClick={() => setEditing(null)}>取消</button>
          </div>
        </div>
      </div>
    );
  }

  // ── 列表模式 ──
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>规则配置</h1>
        <button onClick={startCreate}>+ 新建规则</button>
      </div>

      <div className="msg msg-info" style={{ marginBottom: 16 }}>
        💡 在这里告诉系统漏洞挖掘方法。每条规则描述"什么代码有什么漏洞、怎么判定"，
        LLM 扫描代码时会按你的规则挖掘。<strong>规则越多，挖掘能力越强。</strong>
        内置规则可禁用但不可删；自定义规则可自由增删改。
      </div>

      {error && <div className="msg msg-error">{error}</div>}

      <table>
        <thead>
          <tr>
            <th>规则名称</th>
            <th>类别</th>
            <th>严重度</th>
            <th>来源</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.ruleId}>
              <td>
                <div style={{ fontWeight: 600 }}>{r.name}</div>
                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2, maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {r.description}
                </div>
              </td>
              <td><code>{r.category}</code></td>
              <td><span className={`badge badge-${r.severity}`}>{r.severity}</span></td>
              <td>{r.origin === "builtin" ? "内置" : "自定义"}</td>
              <td>
                <span className={`badge badge-${r.enabled ? "confirmed" : "false_positive"}`}>
                  {r.enabled ? "启用" : "禁用"}
                </span>
              </td>
              <td>
                <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 6 }}
                  onClick={() => toggle(r.ruleId)}>
                  {r.enabled ? "禁用" : "启用"}
                </button>
                <button className="secondary" style={{ fontSize: 12, padding: "4px 8px", marginRight: 6 }}
                  onClick={() => startEdit(r)}>
                  编辑
                </button>
                {r.origin !== "builtin" && (
                  <button className="secondary" style={{ fontSize: 12, padding: "4px 8px" }}
                    onClick={() => remove(r.ruleId, r.origin)}>
                    删除
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {rules.length === 0 && <div className="msg msg-info">暂无规则，点「+ 新建规则」开始</div>}
    </div>
  );
}
