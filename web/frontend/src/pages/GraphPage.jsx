// src/pages/GraphPage.jsx — 知识图谱可视化（cytoscape）
import { useState, useEffect, useRef } from "react";
import { api as apiClient } from "../api.js";
import cytoscape from "cytoscape";

const CATEGORY_COLORS = {
  sqli: "#ef4444",
  cmdi: "#f97316",
  xss: "#eab308",
  deserialization: "#a855f7",
  overflow: "#ec4899",
  authz: "#3b82f6",
  business_logic: "#14b8a6",
  config: "#64748b",
  unknown: "#94a3b8",
};

export default function GraphPage() {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [stats, setStats] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await apiClient.graph();
        if (!mounted) return;
        setStats(data.stats);
        renderGraph(data);
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => { mounted = false; };
  }, []);

  const renderGraph = (data) => {
    if (!containerRef.current) return;
    // 销毁旧实例
    if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }

    const elements = [...data.nodes, ...data.edges];
    cyRef.current = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "label": "data(label)",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "9px",
            "color": "#e2e8f0",
            "background-color": (ele) => {
              const cats = ele.data("categories") || [];
              return CATEGORY_COLORS[cats[0]] || CATEGORY_COLORS.unknown;
            },
            "width": 60,
            "height": 60,
            "border-width": 2,
            "border-color": "#334155",
          },
        },
        {
          selector: "edge",
          style: {
            "width": 1,
            "line-color": "#475569",
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "label": "data(type)",
            "font-size": "7px",
            "color": "#64748b",
            "text-background-color": "#0b1220",
            "text-background-padding": 2,
          },
        },
        {
          selector: ":selected",
          style: { "border-width": 4, "border-color": "#37DCF2" },
        },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: 8000, idealEdgeLength: 100 },
    });

    cyRef.current.on("tap", "node", (evt) => {
      const n = evt.target;
      setSelected({
        id: n.data("id"),
        title: n.data("fullTitle"),
        categories: n.data("categories"),
        attackPattern: n.data("attackPattern"),
      });
    });
  };

  return (
    <div>
      <h1>知识图谱</h1>
      {stats && (
        <div className="card-grid">
          <div className="stat-card">
            <div className="stat-label">节点</div>
            <div className="stat-value">{stats.nodes}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">边</div>
            <div className="stat-value">{stats.edges}</div>
          </div>
        </div>
      )}
      <div ref={containerRef} id="graph-container" />
      {loading && <p className="loading">渲染中...</p>}

      {selected && (
        <div className="card">
          <h2>选中节点</h2>
          <p><strong>ID:</strong> <code>{selected.id}</code></p>
          <p style={{ marginTop: 8 }}><strong>标题:</strong> {selected.title}</p>
          <p style={{ marginTop: 8 }}>
            <strong>类别:</strong>{" "}
            {(selected.categories || []).map((c) => (
              <span key={c} className="badge badge-info" style={{ marginRight: 6, background: CATEGORY_COLORS[c] || "#64748b" }}>{c}</span>
            ))}
          </p>
          {selected.attackPattern && <p style={{ marginTop: 8, color: "#37DCF2" }}>⚠ 含攻击模式</p>}
        </div>
      )}
    </div>
  );
}
