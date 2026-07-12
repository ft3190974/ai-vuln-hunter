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

// 漏洞分类判定（10 类，按优先级精确匹配）
function getVulnType(f) {
  // 1. 0-day 最高优先级
  if (f.isZeroDay) return "zeroday";
  // 2. 已知漏洞（有 CVE）
  if (f.linkedCves && f.linkedCves.length > 0) return "known";
  // 3. AI 安全漏洞（ai-security-hunter 发现）
  if (f.sources?.[0]?.toolId === "ai-security-hunter") {
    const rule = f.sources?.[0]?.rawRuleId || "";
    if (rule.startsWith("AI-SKILL") || rule.startsWith("AI-MCP")) return "ai_mcp";
    if (rule.startsWith("AI-MODEL")) return "ai_code";
    return "ai_logic"; // 提示词注入/越狱/信息泄露/输出注入/不安全函数调用
  }
  // 4. Web 渗透漏洞（web-pentest-hunter 发现）
  if (f.sources?.[0]?.toolId === "web-pentest-hunter") return "web_pentest";
  // 5. 按 category 精确分类（不再笼统归 logic）
  const cat = f.category || "";
  // 业务逻辑漏洞
  if (cat === "business_logic") return "logic";
  // 代码质量缺陷（非安全问题）
  if (["race_condition", "integer_overflow", "config"].includes(cat)) return "quality";
  // 代码安全缺陷（注入/溢出/反序列化等）
  if (["sqli", "cmdi", "xss", "path_traversal", "ssrf", "overflow", "uaf", "double_free",
       "fmt_string", "deserialization", "csrf", "xxe", "redirect", "crypto_weak",
       "hardcoded_secret", "prompt_injection", "jailbreak", "info_leak", "output_injection",
       "unsafe_tool_use"].includes(cat)) return "code_vuln";
  // 兜底：无法分类的归代码质量缺陷
  return "quality";
}

const TYPE_CONFIG = {
  known:      { label: "已知漏洞",       color: "#3b82f6", icon: "📋", desc: "有 CVE 编号的已公开漏洞（SCA 接入后填充）" },
  logic:      { label: "业务逻辑漏洞",   color: "#14b8a6", icon: "🧩", desc: "LLM 发现的业务逻辑缺陷（状态机/金额/幂等/越权）" },
  code_vuln:  { label: "代码安全缺陷",   color: "#ef4444", icon: "🔒", desc: "注入/溢出/反序列化/硬编码等安全漏洞" },
  quality:    { label: "代码质量缺陷",   color: "#64748b", icon: "⚠️", desc: "竞态/整数溢出/配置等代码质量问题" },
  zeroday:    { label: "0-day 漏洞",     color: "#fbbf24", icon: "⚡", desc: "基于已知漏洞变种外推的未知漏洞候选" },
  ai_logic:   { label: "LLM 逻辑漏洞",  color: "#a855f7", icon: "🧠", desc: "提示词注入/越狱/信息泄露/输出注入" },
  ai_code:    { label: "LLM 代码与文件漏洞", color: "#6366f1", icon: "🤖", desc: "推理服务 RCE/模型反序列化/未授权访问/数据投毒" },
  ai_mcp:     { label: "Skill/MCP 漏洞", color: "#ec4899", icon: "🔧", desc: "Skill 命令注入/MCP 路径穿越/权限提升" },
  web_pentest:{ label: "Web 渗透漏洞",   color: "#f97316", icon: "🌐", desc: "Web URL 实际渗透测试发现的漏洞" },
};

// category 英文→中文映射
const CATEGORY_CN = {
  sqli: "SQL注入", cmdi: "命令注入", xss: "XSS跨站脚本", path_traversal: "路径穿越",
  ssrf: "SSRF", overflow: "缓冲区溢出", uaf: "释放后使用", double_free: "双重释放",
  fmt_string: "格式化字符串", deserialization: "反序列化", csrf: "CSRF", xxe: "XXE",
  redirect: "开放重定向", crypto_weak: "弱加密", hardcoded_secret: "硬编码凭据",
  business_logic: "业务逻辑", authz: "越权", authn: "认证缺陷", idor: "IDOR",
  config: "配置缺陷", race_condition: "竞态条件", integer_overflow: "整数溢出",
  prompt_injection: "提示词注入", jailbreak: "越狱", info_leak: "信息泄露",
  output_injection: "输出注入", unsafe_tool_use: "不安全函数调用", unknown: "其他",
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
  const counts = { known: 0, logic: 0, code_vuln: 0, quality: 0, zeroday: 0, ai_logic: 0, ai_code: 0, ai_mcp: 0, web_pentest: 0 };
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
            <option value="logic">🧩 业务逻辑漏洞</option>
            <option value="code_vuln">🔒 代码安全缺陷</option>
            <option value="quality">⚠️ 代码质量缺陷</option>
            <option value="zeroday">⚡ 0-day 漏洞</option>
            <option value="ai_logic">🧠 LLM 逻辑漏洞</option>
            <option value="ai_code">🤖 LLM 代码与文件漏洞</option>
            <option value="ai_mcp">🔧 Skill/MCP 漏洞</option>
            <option value="web_pentest">🌐 Web 渗透漏洞</option>
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
                    <td><code>{CATEGORY_CN[f.category] || f.category}</code></td>
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
