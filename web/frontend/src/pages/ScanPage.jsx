// src/pages/ScanPage.jsx — 扫描任务页（支持文件上传 + 路径 + 粘贴代码）
import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { useCountUp } from "../hooks/useCountUp.js";

const STATES = [
  ["INIT", "预处理"],
  ["LLM_HUNT", "★ LLM 自主挖掘"],
  ["FILTER", "误报库过滤"],
  ["DISPATCH", "分类分发"],
  ["DETECT", "检测"],
  ["RAG_MATCH", "图谱关联"],
  ["ZERO_DAY", "0-day 变种"],
  ["VERIFY", "验证 + POC"],
  ["FIX", "修复"],
  ["LEARN", "学习闭环"],
  ["REPORT", "报告"],
];

function ResultStat({ label, value }) {
  const animated = useCountUp(value);
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{animated}</div>
    </div>
  );
}

export default function ScanPage() {
  const [mode, setMode] = useState("upload"); // upload | path | code
  const [uploadedFile, setUploadedFile] = useState(null); // {path, type, filename, sourceFiles}
  const [uploading, setUploading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [manualPath, setManualPath] = useState("");
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [job, setJob] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  // 文件上传处理
  const handleFile = async (file) => {
    setError(null);
    setUploading(true);
    setUploadedFile(null);
    try {
      const result = await api.uploadFile(file);
      setUploadedFile(result);
      console.log("上传结果:", result);
    } catch (e) {
      setError(e.message);
    } finally {
      setUploading(false);
    }
  };

  const onFileSelect = (e) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  // 提交扫描
  const submit = async () => {
    setSubmitting(true);
    setError(null);
    setJob(null);
    try {
      const id = `scan-${Date.now()}`;
      setScanId(id);
      let sourceInput;

      if (mode === "upload" && uploadedFile) {
        const f = uploadedFile;
        if (f.type === "source_dir") {
          sourceInput = { path: f.path };
        } else if (f.type === "jar") {
          sourceInput = { path: f.path, file: f.filename };
        } else {
          // binary
          sourceInput = { path: f.path, file: f.filename };
        }
      } else if (mode === "path" && manualPath.trim()) {
        sourceInput = { path: manualPath.trim() };
      } else if (mode === "code" && code.trim()) {
        sourceInput = { code, file: `input.${language || "txt"}` };
        if (language) sourceInput.language = language;
      } else {
        setError("请先上传文件 / 填写路径 / 粘贴代码");
        setSubmitting(false);
        return;
      }

      if (language) sourceInput.language = language;

      await api.submitScan(
        { scanId: id, target: { type: "source", path: sourceInput.path || "(code)", language: language || "auto" }, options: { depth: "deep", timeoutSec: 120 } },
        {},
        sourceInput
      );
      pollJob(id);
    } catch (e) {
      setError(e.message);
      setSubmitting(false);
    }
  };

  const pollJob = async (id) => {
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const j = await api.getScan(id);
        setJob(j);
        if (j.status === "completed" || j.status === "failed") {
          setSubmitting(false);
          if (j.status === "failed") setError(j.error || "扫描失败");
          return;
        }
      } catch (e) {
        setError(e.message);
        setSubmitting(false);
        return;
      }
    }
    setSubmitting(false);
    setError("扫描超时");
  };

  const reachedStates = new Set();
  if (job?.report?.log) job.report.log.forEach((l) => reachedStates.add(l.state));

  const canSubmit = (mode === "upload" && uploadedFile) || (mode === "path" && manualPath.trim()) || (mode === "code" && code.trim());

  return (
    <div>
      <h1>扫描任务</h1>

      {/* 模式切换 */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button className={mode === "upload" ? "" : "secondary"} onClick={() => setMode("upload")}>
          📦 上传文件（推荐）
        </button>
        <button className={mode === "path" ? "" : "secondary"} onClick={() => setMode("path")}>
          📁 指定路径
        </button>
        <button className={mode === "code" ? "" : "secondary"} onClick={() => setMode("code")}>
          ✏️ 粘贴代码
        </button>
      </div>

      <div className="card">
        {/* 语言选择（通用，可选） */}
        <div style={{ display: "flex", gap: 16, marginBottom: 16 }}>
          <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
            <label>语言（可选，留空自动识别）</label>
            <select value={language} onChange={(e) => setLanguage(e.target.value)}>
              <option value="">自动识别</option>
              <option value="java">Java</option>
              <option value="python">Python</option>
              <option value="javascript">JavaScript</option>
              <option value="go">Go</option>
              <option value="c">C/C++</option>
              <option value="php">PHP</option>
            </select>
          </div>
        </div>

        {/* 上传模式 */}
        {mode === "upload" && (
          <div>
            <div
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              onClick={() => fileInputRef.current?.click()}
              style={{
                border: `2px dashed ${dragOver ? "var(--accent)" : "var(--border)"}`,
                borderRadius: 8,
                padding: "40px 20px",
                textAlign: "center",
                cursor: "pointer",
                transition: "all 0.2s",
                background: dragOver ? "var(--accent-bg)" : "transparent",
              }}
            >
              <input ref={fileInputRef} type="file" style={{ display: "none" }}
                onChange={onFileSelect}
                accept=".zip,.tar,.gz,.bin,.elf,.exe,.so,.dll,.o,.jar,.class,.img,.fw" />
              {uploading ? (
                <p style={{ color: "var(--accent)" }}>上传中...</p>
              ) : uploadedFile ? (
                <div>
                  <p style={{ fontSize: 32 }}>✅</p>
                  <p style={{ color: "var(--text)", fontWeight: 600 }}>{uploadedFile.filename}</p>
                  <p style={{ fontSize: 13, color: "var(--text-dim)", marginTop: 4 }}>
                    {uploadedFile.type === "source_dir"
                      ? `源码目录（${uploadedFile.sourceFiles || 0} 个源码文件）`
                      : uploadedFile.type === "jar"
                      ? `Java 二进制（${(uploadedFile.size / 1024).toFixed(1)} KB）`
                      : `二进制文件（${(uploadedFile.size / 1024).toFixed(1)} KB）`}
                  </p>
                  <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8, fontFamily: "monospace" }}>
                    {uploadedFile.path}
                  </p>
                </div>
              ) : (
                <div>
                  <p style={{ fontSize: 32 }}>📁</p>
                  <p style={{ color: "var(--text-dim)" }}>点击或拖拽文件到此处上传</p>
                  <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>
                    支持：源码包 (.zip/.tar.gz)、Java 二进制 (.jar/.class)、C/C++ 二进制 (.bin/.elf/.exe)
                  </p>
                </div>
              )}
            </div>
            {uploadedFile && (
              <button className="secondary" style={{ marginTop: 12, fontSize: 12 }}
                onClick={() => { setUploadedFile(null); if (fileInputRef.current) fileInputRef.current.value = ""; }}>
                重新上传
              </button>
            )}
          </div>
        )}

        {/* 路径模式 */}
        {mode === "path" && (
          <div className="form-group">
            <label>源代码路径（文件或目录）</label>
            <input value={manualPath} onChange={(e) => setManualPath(e.target.value)}
              placeholder="/workspace/project 或 C:\project\src" />
          </div>
        )}

        {/* 粘贴代码模式 */}
        {mode === "code" && (
          <div className="form-group">
            <label>源代码（粘贴要分析的代码）</label>
            <textarea value={code} onChange={(e) => setCode(e.target.value)}
              style={{ minHeight: 280, fontFamily: "Consolas, monospace" }} />
          </div>
        )}

        {error && <div className="msg msg-error" style={{ marginTop: 12 }}>{error}</div>}

        <button onClick={submit} disabled={!canSubmit || submitting} style={{ marginTop: 16 }}>
          {submitting ? "🔍 挖掘中..." : "🚀 开始挖掘"}
        </button>
      </div>

      {scanId && !job && submitting && (
        <div className="msg msg-info">分析中: {scanId}...</div>
      )}

      {/* 编排进度 */}
      {job?.report?.log && (
        <div className="card">
          <h2>编排进度</h2>
          <ul className="timeline">
            {STATES.map(([state, desc]) => (
              <li key={state} className={`timeline-item ${reachedStates.has(state) ? "done" : ""}`}>
                <div className="timeline-state">{state}</div>
                <div className="timeline-desc">{desc}</div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* 结果 */}
      {job?.status === "completed" && job.report && (
        <div className="card">
          <h2>挖掘结果</h2>
          <div className="card-grid">
            <ResultStat label="漏洞总数" value={job.report.findings.length} />
            <ResultStat label="业务逻辑漏洞" value={job.report.findings.filter((f) => f.category === "business_logic").length} />
            <ResultStat label="POC 生成" value={job.report.pocs.length} />
            <ResultStat label="Patch 生成" value={job.report.patches.length} />
          </div>
          <p style={{ fontSize: 14, color: "var(--accent)" }}>
            ✓ 共发现 {job.report.findings.length} 个漏洞。
          </p>
          <button onClick={() => navigate(`/findings?scanId=${scanId}`)} style={{ marginTop: 8 }}>
            查看本任务漏洞 →
          </button>
        </div>
      )}
    </div>
  );
}
