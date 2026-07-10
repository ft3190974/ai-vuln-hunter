// src/components/SeverityBadge.jsx — 严重度徽章
export default function SeverityBadge({ severity }) {
  const cls = `badge badge-${severity || "info"}`;
  const text = (severity || "info").toUpperCase();
  return <span className={cls}>{text}</span>;
}
