// src/pages/DashboardPage.jsx — 态势总览（首页）
//
// 6 个核心指标卡 + 趋势柱状图 + 类别饼图 + 严重度分布
// 全部纯 SVG/CSS 绘制，零图表库依赖
import { useState, useEffect } from "react";
import { api } from "../api.js";
import { useCountUp } from "../hooks/useCountUp.js";

const CATEGORY_COLORS = {
  business_logic: "#14b8a6", sqli: "#ef4444", cmdi: "#f97316", xss: "#eab308",
  authz: "#3b82f6", overflow: "#ec4899", double_free: "#a855f7", uaf: "#dc2626",
  fmt_string: "#f59e0b", deserialization: "#8b5cf6", config: "#64748b", unknown: "#94a3b8",
};
const SEVERITY_COLORS = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#64748b" };
const CATEGORY_LABELS = {
  business_logic: "业务逻辑", sqli: "SQL注入", cmdi: "命令注入", xss: "XSS",
  authz: "越权", overflow: "缓冲区溢出", double_free: "Double-Free", uaf: "UAF/泄漏",
  fmt_string: "格式化字符串", deserialization: "反序列化", config: "配置/硬编码", unknown: "其他",
};

function MetricCard({ label, value, icon, color, sub }) {
  const animated = useCountUp(value);
  return (
    <div className="stat-card" style={{ borderTop: `3px solid ${color}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div className="stat-label">{label}</div>
          <div className="stat-value" style={{ color }}>{animated}</div>
          {sub && <div className="stat-sub">{sub}</div>}
        </div>
        <span style={{ fontSize: 28, opacity: 0.5 }}>{icon}</span>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try { setData(await api.dashboard()); }
      finally { setLoading(false); }
    };
    load();
    const timer = setInterval(load, 10000); // 10 秒刷新
    return () => clearInterval(timer);
  }, []);

  if (loading) return <p className="loading">加载中...</p>;
  if (!data) return null;

  const m = data.metrics;

  return (
    <div>
      <h1>态势总览</h1>

      {/* 6 个核心指标 */}
      <div className="card-grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))" }}>
        <MetricCard label="挖掘漏洞总数" value={m.totalFindings} icon="🔍" color="#37DCF2" />
        <MetricCard label="业务逻辑漏洞" value={m.logicVulns} icon="🧩" color="#14b8a6"
          sub={m.totalFindings ? `占 ${((m.logicVulns / m.totalFindings) * 100).toFixed(0)}%` : ""} />
        <MetricCard label="高危漏洞" value={m.highSeverity} icon="🔴" color="#ef4444"
          sub={m.totalFindings ? `占 ${((m.highSeverity / m.totalFindings) * 100).toFixed(0)}%` : ""} />
        <MetricCard label="近 7 天新增" value={m.newThisWeek} icon="📈" color="#f97316" />
        <MetricCard label="POC 生成数" value={m.pocCount} icon="⚔️" color="#a855f7"
          sub={m.totalFindings ? `覆盖率 ${((m.pocCount / m.totalFindings) * 100).toFixed(0)}%` : ""} />
        <MetricCard label="已验证 0-day" value={m.zeroDayCount} icon="⚡" color="#fbbf24" />
        <MetricCard label="0-day 候选" value={m.zeroDayCandidateCount} icon="🔍" color="#a855f7"
          sub={m.zeroDayCount + m.zeroDayCandidateCount > 0 ? `已验证 ${m.zeroDayCount} / 候选 ${m.zeroDayCandidateCount}` : ""} />
      </div>

      {/* 趋势柱状图 */}
      <div className="card">
        <h2>漏洞挖掘趋势（近 14 天）</h2>
        <BarChart data={data.trend} />
      </div>

      {/* 类别分布 + 严重度分布 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div className="card">
          <h2>漏洞类别分布</h2>
          {data.categoryDist.length > 0 ? (
            <DonutChart data={data.categoryDist} colors={CATEGORY_COLORS} labels={CATEGORY_LABELS} />
          ) : <p className="loading">暂无数据</p>}
        </div>
        <div className="card">
          <h2>严重度分布</h2>
          {data.severityDist.length > 0 ? (
            <>
              <SeverityBars data={data.severityDist} />
            </>
          ) : <p className="loading">暂无数据</p>}
        </div>
      </div>

      {/* 引擎能力 */}
      <div className="card">
        <h2>引擎能力</h2>
        <div style={{ display: "flex", gap: 32, fontSize: 14 }}>
          <div><span style={{ color: "var(--text-dim)" }}>判定规则:</span> <strong style={{ color: "var(--accent)" }}>{data.engine.rules}</strong> 条</div>
          <div><span style={{ color: "var(--text-dim)" }}>知识图谱:</span> <strong style={{ color: "var(--accent)" }}>{data.engine.graphNodes}</strong> 节点</div>
          <div><span style={{ color: "var(--text-dim)" }}>误报库:</span> <strong style={{ color: "var(--accent)" }}>{data.engine.fpPatterns}</strong> 条</div>
        </div>
      </div>
    </div>
  );
}

// ── 柱状图（纯 SVG）──
function BarChart({ data }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  const barW = 40;
  const gap = 12;
  const chartH = 160;
  const totalW = data.length * (barW + gap);
  return (
    <div style={{ overflowX: "auto" }}>
      <svg width={Math.max(totalW, 600)} height={chartH + 40} style={{ minWidth: "100%" }}>
        {data.map((d, i) => {
          const h = (d.count / max) * chartH;
          const x = i * (barW + gap) + 10;
          const y = chartH - h + 10;
          return (
            <g key={i}>
              <rect x={x} y={y} width={barW} height={h} rx="3"
                fill={d.count > 0 ? "var(--accent)" : "var(--border)"} opacity={d.count > 0 ? 0.8 : 0.3} />
              {d.count > 0 && (
                <text x={x + barW / 2} y={y - 5} textAnchor="middle" fontSize="11" fill="var(--accent)" fontWeight="700">
                  {d.count}
                </text>
              )}
              <text x={x + barW / 2} y={chartH + 25} textAnchor="middle" fontSize="10" fill="var(--text-muted)">
                {d.date}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── 饼图/环形图（纯 SVG）──
function DonutChart({ data, colors, labels }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const cx = 100, cy = 100, r = 70, sw = 28;
  let angle = -90;

  return (
    <div style={{ display: "flex", gap: 24, alignItems: "center", flexWrap: "wrap" }}>
      <svg width={200} height={200}>
        {data.map((d, i) => {
          const pct = (d.value / total) * 360;
          const startAngle = angle;
          const endAngle = angle + pct;
          angle = endAngle;
          const largeArc = pct > 180 ? 1 : 0;
          const x1 = cx + r * Math.cos((startAngle * Math.PI) / 180);
          const y1 = cy + r * Math.sin((startAngle * Math.PI) / 180);
          const x2 = cx + r * Math.cos((endAngle * Math.PI) / 180);
          const y2 = cy + r * Math.sin((endAngle * Math.PI) / 180);
          const path = `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`;
          return (
            <path key={i} d={path} fill="none"
              stroke={colors[d.name] || "#94a3b8"} strokeWidth={sw}
              strokeLinecap="butt" />
          );
        })}
        <text x={cx} y={cy - 5} textAnchor="middle" fontSize="28" fontWeight="700" fill="var(--text)">{total}</text>
        <text x={cx} y={cy + 15} textAnchor="middle" fontSize="11" fill="var(--text-dim)">总计</text>
      </svg>
      {/* 图例 */}
      <div style={{ fontSize: 12, lineHeight: 1.8 }}>
        {data.slice(0, 8).map((d, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 10, height: 10, borderRadius: 2, background: colors[d.name] || "#94a3b8" }} />
            <span>{labels[d.name] || d.name}: <strong>{d.value}</strong></span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── 严重度横条图 ──
function SeverityBars({ data }) {
  const max = Math.max(...data.map((d) => d.value), 1);
  const labels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "8px 0" }}>
      {data.map((d) => (
        <div key={d.name}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
            <span style={{ color: SEVERITY_COLORS[d.name], fontWeight: 600 }}>{labels[d.name] || d.name}</span>
            <span style={{ color: "var(--text-dim)" }}>{d.value}</span>
          </div>
          <div style={{ height: 20, background: "var(--bg-code)", borderRadius: 4, overflow: "hidden" }}>
            <div style={{
              height: "100%", width: `${(d.value / max) * 100}%`,
              background: SEVERITY_COLORS[d.name], borderRadius: 4,
              transition: "width 0.6s ease",
            }} />
          </div>
        </div>
      ))}
    </div>
  );
}
