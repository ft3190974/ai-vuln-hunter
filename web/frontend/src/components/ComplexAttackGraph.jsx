// src/components/ComplexAttackGraph.jsx — 复杂多漏洞组合攻击路径（DAG）
//
// 从任务的 attackScenario 数据渲染有向无环图：
// 攻击者 → 漏洞A → 漏洞B → ... → 影响
// 支持分叉/合并（多条路径并排）

const NODE_COLORS = {
  entry: { bg: "rgba(239,68,68,0.15)", border: "#ef4444", text: "#fca5a5" },
  vuln: { bg: "rgba(55,220,242,0.1)", border: "var(--accent)", text: "var(--accent)" },
  impact: { bg: "rgba(220,38,38,0.2)", border: "#dc2626", text: "#fecaca" },
};

export default function ComplexAttackGraph({ scenario }) {
  if (!scenario || !scenario.paths || scenario.paths.length === 0) {
    return <p className="loading">暂无复杂攻击场景数据（漏洞不足或无法组合）</p>;
  }

  return (
    <div>
      {/* 场景摘要 */}
      <div className="card" style={{ marginBottom: 16, padding: 14, borderLeft: "4px solid #fbbf24" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <strong style={{ color: "var(--text)", fontSize: 14 }}>{scenario.summary}</strong>
          <div style={{ display: "flex", gap: 12, fontSize: 12 }}>
            <span className="badge badge-info">难度: {scenario.difficulty}</span>
            <span className="badge badge-critical">{scenario.paths.length} 条路径</span>
          </div>
        </div>
        <p style={{ fontSize: 13, color: "#fca5a5", marginTop: 8 }}>💥 最终影响: {scenario.impact}</p>
      </div>

      {/* 每条路径一个 SVG DAG */}
      {scenario.paths.map((path, pi) => (
        <div key={pi} style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, color: "var(--text-dim)", marginBottom: 12 }}>
            路径 {pi + 1}: {path.name}
          </h3>
          <DAGRenderer nodes={path.nodes} edges={path.edges} />
        </div>
      ))}
    </div>
  );
}

// ── DAG 渲染器（纯 SVG，纵向排列节点）──
function DAGRenderer({ nodes, edges }) {
  const nodeW = 240;
  const nodeH = 70;
  const gapY = 30;
  const totalH = nodes.length * (nodeH + gapY) + 40;
  const cx = 160; // 中心 X

  // 给每个节点分配位置（纵向，有分叉时横向偏移）
  const positions = {};
  // 简化布局：线性纵向排列（分支场景左右偏移）
  const incomingEdges = {};
  for (const e of edges) {
    incomingEdges[e.to] = (incomingEdges[e.to] || 0) + 1;
  }

  nodes.forEach((n, i) => {
    positions[n.id] = { x: cx, y: 20 + i * (nodeH + gapY) };
  });

  return (
    <div style={{ overflowX: "auto" }}>
      <svg width={nodeW + 200} height={totalH} style={{ minWidth: "100%" }}>
        {/* 连线 */}
        {edges.map((e, i) => {
          const from = positions[e.from];
          const to = positions[e.to];
          if (!from || !to) return null;
          const y1 = from.y + nodeH;
          const y2 = to.y;
          const midY = (y1 + y2) / 2;
          return (
            <g key={`e-${i}`}>
              <path
                d={`M ${from.x + nodeW / 2} ${y1} C ${from.x + nodeW / 2} ${midY}, ${to.x + nodeW / 2} ${midY}, ${to.x + nodeW / 2} ${y2 - 4}`}
                fill="none"
                stroke="var(--text-muted)"
                strokeWidth="2"
                strokeDasharray="4 2"
              />
              <polygon
                points={`${to.x + nodeW / 2 - 5},${y2 - 8} ${to.x + nodeW / 2},${y2 - 2} ${to.x + nodeW / 2 + 5},${y2 - 8}`}
                fill="var(--text-muted)"
              />
              {e.label && (
                <text x={to.x + nodeW / 2 + 15} y={midY} fontSize="10" fill="var(--text-dim)">
                  {e.label}
                </text>
              )}
            </g>
          );
        })}

        {/* 节点 */}
        {nodes.map((n, i) => {
          const pos = positions[n.id];
          if (!pos) return null;
          const colors = NODE_COLORS[n.type] || NODE_COLORS.vuln;
          return (
            <g key={n.id} transform={`translate(${pos.x}, ${pos.y})`}>
              <rect width={nodeW} height={nodeH} rx="8"
                fill={colors.bg} stroke={colors.border} strokeWidth="2" />
              {/* 图标 + 标签 */}
              <text x="12" y="22" fontSize="11" fontWeight="700" fill={colors.text}>
                {n.type === "entry" ? "👤" : n.type === "impact" ? "💥" : "🎯"} {n.label?.slice(0, 32)}
              </text>
              {/* Finding ID */}
              {n.findingId && (
                <text x="12" y="40" fontSize="10" fill="var(--text-dim)" fontFamily="monospace">
                  {n.findingId}
                </text>
              )}
              {/* 输出 */}
              {n.output && (
                <text x="12" y={n.findingId ? 56 : 40} fontSize="10" fill={colors.text}>
                  → {n.output?.slice(0, 30)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
