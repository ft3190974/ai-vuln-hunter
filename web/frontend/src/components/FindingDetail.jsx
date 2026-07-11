// src/components/FindingDetail.jsx — Finding 详情（可利用性 + 上下文 + 沙箱过程）
import { useState, useEffect } from "react";
import CodeBlock from "./CodeBlock.jsx";
import AttackChainDiagram from "./AttackChainDiagram.jsx";
import ComplexAttackGraph from "./ComplexAttackGraph.jsx";
import { api } from "../api.js";

export default function FindingDetail({ finding }) {
  const [showFullContext, setShowFullContext] = useState(false);
  const [tab, setTab] = useState("overview");
  const [chainMode, setChainMode] = useState("simple"); // simple | complex
  const [attackScenario, setAttackScenario] = useState(null);
  if (!finding) return null;

  // 加载任务的攻击场景（点击复杂模式时才加载）
  useEffect(() => {
    if (chainMode === "complex" && finding.scanId && !attackScenario) {
      api.getScan(finding.scanId).then((data) => {
        setAttackScenario(data?.report?.attackScenario || null);
      }).catch(() => {});
    }
  }, [chainMode]); // eslint-disable-line

  const tabs = [
    { key: "overview", label: "📋 概览" },
    { key: "chain", label: "🔗 攻击链路" },
    { key: "snippet", label: "📍 漏洞定位" },
    { key: "poc", label: "⚔️ POC 与验证" },
    { key: "patch", label: "🔧 修复" },
  ];

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(finding, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${finding.findingId}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const loc = finding.location || {};
  const locText = `${loc.file || "?"}:${loc.startLine || "?"}${loc.function ? ` (${loc.function})` : ""}`;
  const exploit = finding.exploitability || {};
  const impact = finding.impact || {};

  return (
    <div style={{ padding: "12px 0" }}>
      {/* 顶部：定位 + 导出 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}>
        <div style={{ flex: 1 }}>
          <p style={{ color: "var(--text)", fontSize: 14 }}>{finding.description?.split("\n")[0]}</p>
          <p style={{ fontSize: 13, color: "var(--accent)", marginTop: 6, fontFamily: "Consolas, monospace" }}>
            📍 {locText}
            {finding.isZeroDay ? "  · ⚠️ 0-day 候选" : ""}
            {finding.linkedCves?.length > 0 ? `  · 关联 ${finding.linkedCves.join(",")}` : ""}
          </p>
        </div>
        <button className="secondary" style={{ marginLeft: 12, padding: "4px 10px", fontSize: 12 }} onClick={exportJson}>
          ⬇ 导出 JSON
        </button>
      </div>

      {/* Tab 切换 */}
      <div style={{ marginBottom: 12, borderBottom: "1px solid var(--border)" }}>
        {tabs.map((t) => (
          <button
            key={t.key}
            className={tab === t.key ? "" : "secondary"}
            style={{ marginRight: 4, padding: "8px 14px", fontSize: 13, borderRadius: "4px 4px 0 0", borderBottom: "none" }}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── 概览：可利用性 + 影响 + 攻击场景 ── */}
      {tab === "overview" && (
        <div>
          {/* 可利用性 */}
          <div className="card" style={{ padding: 14, marginBottom: 12 }}>
            <h3 style={{ fontSize: 14, marginBottom: 10, color: "var(--text)" }}>🎯 可利用性评估</h3>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, fontSize: 13 }}>
              <div>
                <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>利用难度</div>
                <span className={`badge badge-${exploit.difficulty === "low" ? "critical" : exploit.difficulty === "medium" ? "high" : "low"}`}>
                  {exploit.difficulty || "unknown"}
                </span>
              </div>
              <div>
                <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>可远程利用</div>
                <span style={{ color: impact.remote ? "#fca5a5" : "#86efac" }}>{impact.remote ? "是 ⚠️" : "否"}</span>
              </div>
              <div>
                <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>无需认证</div>
                <span style={{ color: impact.noAuth ? "#fca5a5" : "#86efac" }}>{impact.noAuth ? "是 ⚠️" : "否"}</span>
              </div>
            </div>
            <div style={{ marginTop: 10, fontSize: 13 }}>
              <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>前置条件</div>
              <div>{exploit.prerequisites || "(未评估)"}</div>
            </div>
            <div style={{ marginTop: 8, fontSize: 13 }}>
              <div style={{ color: "var(--text-dim)", marginBottom: 4 }}>所需权限</div>
              <div>{exploit.accessNeeded || "(未评估)"}</div>
            </div>
          </div>

          {/* 影响 */}
          <div className="card" style={{ padding: 14, marginBottom: 12 }}>
            <h3 style={{ fontSize: 14, marginBottom: 10, color: "var(--text)" }}>💥 影响评估</h3>
            <div style={{ fontSize: 13, marginBottom: 8 }}>
              <span style={{ color: "var(--text-dim)" }}>受影响资产: </span>
              <span style={{ color: "#fde68a" }}>{impact.assets || "(未评估)"}</span>
            </div>
            <div style={{ fontSize: 13 }}>
              <span style={{ color: "var(--text-dim)" }}>最坏后果: </span>
              <span style={{ color: "#fca5a5" }}>{impact.worstCase || "(未评估)"}</span>
            </div>
          </div>

          {/* 攻击场景 */}
          {finding.businessContext?.attackScenario && (
            <div className="card" style={{ padding: 14 }}>
              <h3 style={{ fontSize: 14, marginBottom: 10, color: "var(--text)" }}>⚔️ 攻击场景</h3>
              <p style={{ fontSize: 13, color: "var(--text)", fontFamily: "Consolas, monospace" }}>
                {finding.businessContext.attackScenario}
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── 攻击链路示意图 ── */}
      {tab === "chain" && (
        <div>
          {/* 切换：简单 / 复杂 */}
          <div style={{ marginBottom: 16 }}>
            <button
              className={chainMode === "simple" ? "" : "secondary"}
              style={{ marginRight: 8, padding: "6px 14px", fontSize: 12 }}
              onClick={() => setChainMode("simple")}
            >
              简单链路（单漏洞）
            </button>
            <button
              className={chainMode === "complex" ? "" : "secondary"}
              style={{ padding: "6px 14px", fontSize: 12 }}
              onClick={() => setChainMode("complex")}
            >
              复杂攻击路径（多漏洞组合）
            </button>
          </div>

          {chainMode === "simple" ? (
            <div>
              <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 16 }}>
                攻击链路：从攻击者到漏洞触发到最终影响的完整路径
              </p>
              <AttackChainDiagram finding={finding} />

              <div className="card" style={{ marginTop: 16, padding: 14 }}>
                <h3 style={{ fontSize: 14, marginBottom: 10 }}>链路说明</h3>
                <ol style={{ paddingLeft: 20, fontSize: 13, lineHeight: 1.8, color: "var(--text)" }}>
                  <li><strong style={{ color: "#fca5a5" }}>攻击者</strong>：{(finding.exploitability || {}).accessNeeded || "外部攻击者"}</li>
                  <li><strong style={{ color: "#fde68a" }}>入口点</strong>：{(finding.poc || {}).entry || (finding.location || {}).file || "未知"}</li>
                  {(finding.poc || {}).payload && (
                    <li><strong style={{ color: "#c4b5fd" }}>攻击载荷</strong>：<code>{(finding.poc || {}).payload}</code></li>
                  )}
                  <li><strong style={{ color: "var(--accent)" }}>漏洞点</strong>：{(finding.location || {}).function || "?"} ({(finding.location || {}).file?.split(/[\\/]/).pop()}:{(finding.location || {}).startLine})</li>
                  <li>
                    <strong style={{ color: finding.poc?.sandboxVerified ? "#86efac" : "#d1d5db" }}>
                      {finding.poc?.sandboxVerified ? "验证通过" : "待验证"}
                    </strong>：
                    {finding.poc?.sandboxVerified ? "沙箱确认漏洞可利用" : "沙箱未触发，需人工确认"}
                  </li>
                  <li><strong style={{ color: "#fecaca" }}>影响</strong>：{(finding.impact || {}).worstCase || "未知"}</li>
                </ol>
              </div>
            </div>
          ) : (
            <ComplexAttackGraph scenario={attackScenario} />
          )}
        </div>
      )}

      {/* ── 漏洞定位：代码段 或 文件/二进制位置 ── */}
      {tab === "snippet" && (
        <div>
          {/* 情况 A：有代码片段 → 展示代码（行号高亮） */}
          {finding.snippet && finding.snippet.code ? (
            <div>
              <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 8 }}>
                漏洞代码（<span style={{ color: "#ef4444" }}>红色行</span> 为漏洞位置）：
              </p>
              <CodeBlockWithLineNumbers
                code={finding.snippet.code}
                language={finding.snippet.language || "javascript"}
                startLine={finding.snippet.startLine}
                primaryLine={finding.snippet.primaryLine}
              />

              {/* 完整上下文切换 */}
              {finding.fullContext && finding.fullContext !== finding.snippet.code && (
                <div style={{ marginTop: 12 }}>
                  <button className="secondary" style={{ fontSize: 12, padding: "4px 10px" }} onClick={() => setShowFullContext(!showFullContext)}>
                    {showFullContext ? "▲ 收起完整文件" : "▼ 查看完整文件上下文"}
                  </button>
                  {showFullContext && (
                    <div style={{ marginTop: 8 }}>
                      <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 6 }}>
                        完整文件（{finding.fullContext.split("\n").length} 行，漏洞在 <span style={{ color: "#ef4444" }}>第 {loc.startLine} 行</span>）：
                      </p>
                      <CodeBlockWithLineNumbers
                        code={finding.fullContext}
                        language={finding.snippet.language || "javascript"}
                        startLine={1}
                        primaryLine={loc.startLine}
                      />
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            /* 情况 B：无代码片段（固件/二进制/文件级漏洞）→ 展示文件位置 */
            <div className="card" style={{ padding: 20 }}>
              <h3 style={{ fontSize: 14, marginBottom: 16, color: "var(--text)" }}>📂 漏洞位置</h3>
              <div style={{ fontSize: 14, lineHeight: 2 }}>
                {loc.binary && (
                  <div>
                    <span style={{ color: "var(--text-dim)" }}>二进制文件: </span>
                    <code style={{ color: "var(--accent)" }}>{loc.binary}</code>
                  </div>
                )}
                {loc.file && (
                  <div>
                    <span style={{ color: "var(--text-dim)" }}>源文件: </span>
                    <code style={{ color: "var(--accent)" }}>{loc.file}</code>
                  </div>
                )}
                {loc.function && (
                  <div>
                    <span style={{ color: "var(--text-dim)" }}>函数: </span>
                    <code style={{ color: "#fde68a" }}>{loc.function}</code>
                  </div>
                )}
                {loc.address && (
                  <div>
                    <span style={{ color: "var(--text-dim)" }}>地址: </span>
                    <code style={{ color: "#fca5a5" }}>{loc.address}</code>
                  </div>
                )}
                {loc.startLine && (
                  <div>
                    <span style={{ color: "var(--text-dim)" }}>行号: </span>
                    <code style={{ color: "var(--accent)" }}>{loc.startLine}{loc.endLine && loc.endLine !== loc.startLine ? `-${loc.endLine}` : ""}</code>
                  </div>
                )}
                {!loc.binary && !loc.file && !loc.function && !loc.address && (
                  <div style={{ color: "var(--text-muted)" }}>无具体位置信息</div>
                )}
              </div>

              {/* 二进制/固件的证据（如果有 snippet.code 存反汇编等） */}
              {finding.snippet?.code && (
                <div style={{ marginTop: 16 }}>
                  <p style={{ fontSize: 12, color: "var(--text-dim)", marginBottom: 6 }}>
                    {finding.snippet.type === "disasm" ? "反汇编" : finding.snippet.type === "pseudocode" ? "伪代码" : "相关内容"}：
                  </p>
                  <CodeBlock code={finding.snippet.code} language="bash" showCopy={false} />
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── POC + 沙箱验证过程 ── */}
      {tab === "poc" && (
        finding.poc ? (
          <div>
            {/* 沙箱验证结论 */}
            <div className="card" style={{ padding: 14, marginBottom: 12, borderLeft: `4px solid ${finding.poc.sandboxVerified ? "#86efac" : "#fde68a"}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong style={{ color: finding.poc.sandboxVerified ? "#86efac" : "#fde68a", fontSize: 15 }}>
                  {finding.poc.sandboxVerified ? "✓ 沙箱验证通过 — 漏洞确认可利用" : "⚠ 沙箱未触发 — 待人工复核"}
                </strong>
                <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
                  置信度 {((finding.poc.confidence || 0.7) * 100).toFixed(0)}% · 耗时 {finding.poc.sandboxRun?.durationMs || 0}ms
                </span>
              </div>
              <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 8 }}>
                判定依据: {finding.poc.sandboxEvidence}
              </p>
            </div>

            {/* 沙箱执行过程（步骤化） */}
            {finding.poc.sandboxRun && (
              <div className="card" style={{ padding: 14, marginBottom: 12 }}>
                <h3 style={{ fontSize: 14, marginBottom: 12, color: "var(--text)" }}>
                  🔬 验证过程（沙箱: {finding.poc.sandboxRun.impl}）
                </h3>
                <ul className="timeline" style={{ paddingLeft: 0 }}>
                  {(finding.poc.sandboxRun.steps || []).map((s, i) => (
                    <li key={i} className="timeline-item done">
                      <div className="timeline-state">步骤 {s.step}: {s.action}</div>
                      <div className="timeline-desc" style={{ fontFamily: "Consolas, monospace", color: "var(--text)", marginTop: 4 }}>
                        {s.detail}
                      </div>
                    </li>
                  ))}
                </ul>

                {/* 原始响应 */}
                <div style={{ marginTop: 12 }}>
                  <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 6 }}>原始响应:</p>
                  <CodeBlock code={JSON.stringify(finding.poc.sandboxRun.response, null, 2)} language="json" showCopy={false} />
                </div>
              </div>
            )}

            {/* POC 结构化描述 */}
            <div>
              <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 6 }}>POC 结构化描述:</p>
              <CodeBlock
                code={JSON.stringify({
                  vulnType: finding.poc.vulnType,
                  entry: finding.poc.entry,
                  payload: finding.poc.payload,
                  precondition: finding.poc.precondition,
                  expected: finding.poc.expected,
                }, null, 2)}
                language="json"
              />
            </div>
          </div>
        ) : <p className="loading">未生成 POC（漏洞未达到验证阈值）</p>
      )}

      {/* ── 修复 ── */}
      {tab === "patch" && (
        finding.patch ? (
          <div>
            <div className="card" style={{ marginBottom: 12, padding: 14 }}>
              <strong style={{ fontSize: 14 }}>修复策略: {finding.patch.strategy}</strong>
              <span style={{ marginLeft: 12, fontSize: 13 }}>
                风险: <span className={`badge badge-${finding.patch.riskLevel === "low" ? "low" : finding.patch.riskLevel === "high" ? "high" : "medium"}`}>{finding.patch.riskLevel}</span>
              </span>
              {finding.patch.equivalenceCheck === false && (
                <span style={{ marginLeft: 12, fontSize: 13, color: "#fca5a5" }}>⚠ 等价性未通过，需人工 review</span>
              )}
              <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 8 }}>{finding.patch.rationale}</p>
            </div>

            {/* ★ 修复验证区块 */}
            {finding.patch.verification && (
              <div className="card" style={{ marginBottom: 12, padding: 14, borderLeft: `4px solid ${finding.patch.verification.overallPassed ? "#22c55e" : "#fbbf24"}` }}>
                <h3 style={{ fontSize: 14, marginBottom: 12, color: finding.patch.verification.overallPassed ? "#86efac" : "#fde68a" }}>
                  {finding.patch.verification.overallPassed ? "✅ 修复验证通过" : "⚠️ 修复验证未完全通过"}
                </h3>

                {/* POC 回归 */}
                {finding.patch.verification.pocRegression && (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>🔬 POC 回归验证</div>
                    <div style={{ fontSize: 13, display: "flex", gap: 16 }}>
                      <span>修复前: <span style={{ color: "#fca5a5" }}>{finding.patch.verification.pocRegression.originalTriggered ? "❌ 可利用" : "— 不可利用"}</span></span>
                      <span>修复后: <span style={{ color: "#86efac" }}>{finding.patch.verification.pocRegression.afterPatchTriggered ? "❌ 仍可利用" : "✓ 无法利用"}</span></span>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-dim)", marginTop: 4 }}>
                      {finding.patch.verification.pocRegression.evidence}
                    </div>
                  </div>
                )}

                {/* 单元测试 */}
                {finding.patch.verification.unitTests && (
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                      🧪 单元测试 {finding.patch.verification.unitTests.passed}/{finding.patch.verification.unitTests.generated} 通过
                    </div>
                    <table style={{ fontSize: 12 }}>
                      <thead>
                        <tr>
                          <th>测试名</th>
                          <th>输入</th>
                          <th>期望</th>
                          <th>结果</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(finding.patch.verification.unitTests.cases || []).map((tc, i) => (
                          <tr key={i}>
                            <td style={{ fontFamily: "monospace" }}>{tc.name}</td>
                            <td style={{ maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }}>{tc.input}</td>
                            <td style={{ maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis" }}>{tc.expected}</td>
                            <td>
                              <span style={{ color: tc.passed ? "#86efac" : "#fca5a5" }}>
                                {tc.passed ? "✓ 通过" : "✗ 失败"}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 6 }}>修复后代码（可复制）:</p>
            <CodeBlock code={finding.patch.code} language={finding.snippet?.language || "javascript"} />
          </div>
        ) : <p className="loading">未生成 Patch</p>
      )}
    </div>
  );
}

// 带行号 + 漏洞行高亮的代码块
function CodeBlockWithLineNumbers({ code, language, startLine, primaryLine }) {
  const lines = code.split("\n");
  const primaryIdx = (primaryLine || 1) - 1;
  return (
    <div style={{ background: "var(--bg-code)", border: "1px solid var(--border)", borderRadius: 4, overflow: "auto", maxHeight: 500 }}>
      <pre style={{ margin: 0, padding: 0 }}>
        {lines.map((line, i) => {
          const lineNo = startLine + i;
          const isVuln = i === primaryIdx;
          return (
            <div key={i} style={{
              display: "flex",
              background: isVuln ? "rgba(239, 68, 68, 0.18)" : "transparent",
              borderLeft: isVuln ? "3px solid #ef4444" : "3px solid transparent",
            }}>
              <span style={{
                color: isVuln ? "#ef4444" : "var(--text-muted)",
                padding: "0 12px", minWidth: 60, textAlign: "right",
                userSelect: "none", fontWeight: isVuln ? 700 : 400,
                fontFamily: "Consolas, monospace", fontSize: 13,
              }}>
                {isVuln ? "▶ " : ""}{lineNo}
              </span>
              <span style={{
                color: isVuln ? "#fecaca" : "var(--text)",
                fontFamily: "Consolas, monospace", fontSize: 13,
                whiteSpace: "pre", padding: "0 8px",
              }}>
                {line || " "}
              </span>
            </div>
          );
        })}
      </pre>
    </div>
  );
}
