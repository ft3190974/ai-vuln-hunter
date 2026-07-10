// src/components/AttackChainDiagram.jsx — POC 攻击链路示意图（纯 SVG，零依赖）
//
// 把漏洞的攻击链路可视化：
//   攻击者 → 入口点 → 漏洞点 → 影响
//
// 数据来源：finding 的 location / poc / exploitability / impact

export default function AttackChainDiagram({ finding }) {
  if (!finding) return null;

  // 构造链路节点
  const nodes = buildChainNodes(finding);

  return (
    <div style={{ overflowX: "auto", padding: "8px 0" }}>
      <svg width={nodes.length * 220} height="180" style={{ minWidth: "100%" }}>
        {/* 连接线 + 箭头 */}
        {nodes.slice(0, -1).map((n, i) => {
          const x1 = i * 220 + 170;
          const x2 = (i + 1) * 220 + 20;
          const y = 90;
          return (
            <g key={`line-${i}`}>
              <line x1={x1} y1={y} x2={x2 - 8} y2={y}
                stroke="var(--text-muted)" strokeWidth="2" strokeDasharray="4 2" />
              <polygon points={`${x2-8},${y-5} ${x2},${y} ${x2-8},${y+5}`}
                fill="var(--text-muted)" />
            </g>
          );
        })}

        {/* 节点 */}
        {nodes.map((n, i) => (
          <g key={`node-${i}`} transform={`translate(${i * 220 + 20}, 30)`}>
            {/* 卡片背景 */}
            <rect width="150" height="120" rx="8"
              fill={n.bgColor} stroke={n.borderColor} strokeWidth="2" />
            {/* 图标 */}
            <text x="75" y="28" textAnchor="middle" fontSize="22">{n.icon}</text>
            {/* 标签 */}
            <text x="75" y="52" textAnchor="middle" fontSize="11"
              fill={n.textColor} fontWeight="700">{n.label}</text>
            {/* 详情 */}
            {n.detail.split("\n").slice(0, 3).map((line, j) => (
              <text key={j} x="75" y={68 + j * 14} textAnchor="middle" fontSize="10" fill={n.textColor}>
                {line.length > 20 ? line.slice(0, 18) + "…" : line}
              </text>
            ))}
          </g>
        ))}
      </svg>
    </div>
  );
}

function buildChainNodes(finding) {
  const nodes = [];
  const exploit = finding.exploitability || {};
  const impact = finding.impact || {};
  const poc = finding.poc || {};
  const loc = finding.location || {};

  // 1. 攻击者
  nodes.push({
    label: "攻击者",
    icon: "👤",
    detail: exploit.accessNeeded || "外部攻击者",
    bgColor: "rgba(239,68,68,0.1)",
    borderColor: "#ef4444",
    textColor: "#fca5a5",
  });

  // 2. 入口点（攻击者怎么进来的）
  nodes.push({
    label: "入口点",
    icon: "🚪",
    detail: poc.entry || loc.file?.split(/[\\/]/).pop() || "未知接口",
    bgColor: "rgba(251,191,36,0.1)",
    borderColor: "#fbbf24",
    textColor: "#fde68a",
  });

  // 3. 攻击载荷（怎么打的）
  if (poc.payload) {
    nodes.push({
      label: "攻击载荷",
      icon: "💉",
      detail: poc.payload.slice(0, 40),
      bgColor: "rgba(168,85,247,0.1)",
      borderColor: "#a855f7",
      textColor: "#c4b5fd",
    });
  }

  // 4. 漏洞点（代码哪里有问题）
  nodes.push({
    label: "漏洞点",
    icon: "🐛",
    detail: `${loc.function || "?"}\n${loc.file?.split(/[\\/]/).pop() || "?"}:${loc.startLine || "?"}`,
    bgColor: "rgba(55,220,242,0.1)",
    borderColor: "var(--accent)",
    textColor: "var(--accent)",
  });

  // 5. 沙箱验证结果
  nodes.push({
    label: poc.sandboxVerified ? "✓ 验证通过" : "⚠ 未验证",
    icon: poc.sandboxVerified ? "✅" : "⚠️",
    detail: poc.sandboxVerified ? "沙箱确认可利用" : "待人工确认",
    bgColor: poc.sandboxVerified ? "rgba(34,197,94,0.1)" : "rgba(156,163,175,0.1)",
    borderColor: poc.sandboxVerified ? "#22c55e" : "#9ca3af",
    textColor: poc.sandboxVerified ? "#86efac" : "#d1d5db",
  });

  // 6. 影响
  nodes.push({
    label: "影响",
    icon: "💥",
    detail: (impact.worstCase || "未知影响").slice(0, 40),
    bgColor: "rgba(239,68,68,0.15)",
    borderColor: "#dc2626",
    textColor: "#fecaca",
  });

  return nodes;
}
