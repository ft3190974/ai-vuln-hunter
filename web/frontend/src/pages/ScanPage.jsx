// src/pages/ScanPage.jsx — 扫描任务页（支持文件上传 + 路径 + 粘贴代码）
import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { useCountUp } from "../hooks/useCountUp.js";

const STATES = [
  ["INIT", "预处理", "1-3s", "fast"],
  ["PROJECT_UNDERSTAND", "项目理解", "5-15s", "fast"],
  ["LLM_HUNT", "★ LLM 自主挖掘", "30s-5min", "slow"],
  ["FILTER", "误报库过滤", "1-2s", "fast"],
  ["DISPATCH", "分类分发", "1s", "fast"],
  ["DETECT", "深度检测", "10-60s", "medium"],
  ["RAG_MATCH", "图谱关联", "1-3s", "fast"],
  ["ZERO_DAY", "0-day 变种挖掘", "10-60s", "medium"],
  ["VERIFY", "验证 + POC + 0-day验证", "10-90s", "medium"],
  ["ATTACK_SCENARIO", "攻击路径构建", "5-15s", "fast"],
  ["FIX", "修复 + 修复验证", "10-60s", "medium"],
  ["LEARN", "学习闭环", "5-15s", "fast"],
  ["REPORT", "报告", "1s", "fast"],
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
  const [mode, setMode] = useState("upload"); // upload | path | code | web
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [webUrl, setWebUrl] = useState("");
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [loginUrl, setLoginUrl] = useState("");
  const [loginUser, setLoginUser] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [cookieStr, setCookieStr] = useState("");
  const [isAiProject, setIsAiProject] = useState(false);
  const [gitUrl, setGitUrl] = useState("");
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

  // 文件上传处理（带前端大小预检）
  const MAX_UPLOAD_MB = 20;
  const handleFile = async (file) => {
    setError(null);
    // 前端预检：超过 20MB 直接拦截，避免传一半才失败
    if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
      setError(`文件过大（${(file.size / 1024 / 1024).toFixed(1)} MB），当前限制 ${MAX_UPLOAD_MB} MB。请压缩或拆分后上传。`);
      return;
    }
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
      // ★ Git 地址优先处理（clone 后走静态分析）
      let sourceInput;
      if (gitUrl.trim()) {
        sourceInput = { gitUrl: gitUrl.trim(), type: "git" };
        if (isAiProject) sourceInput.aiSecurity = true;
        if (language) sourceInput.language = language;
      } else if (mode === "upload" && uploadedFile) {
        const f = uploadedFile;
        if (f.type === "source_dir" || f.type === "source_file") {
          sourceInput = { path: f.path };
        } else if (f.type === "jar") {
          sourceInput = { path: f.path, file: f.filename };
        } else {
          // binary
          sourceInput = { path: f.path, file: f.filename };
        }
      } else if (mode === "web" && webUrl.trim()) {
        if (!authConfirmed) { setError("请先勾选授权确认"); setSubmitting(false); return; }
        sourceInput = { type: "web", url: webUrl.trim() };
        if (loginUrl.trim()) sourceInput.loginUrl = loginUrl.trim();
        if (loginUser.trim()) sourceInput.loginUser = loginUser.trim();
        if (loginPass.trim()) sourceInput.loginPass = loginPass.trim();
        if (cookieStr.trim()) sourceInput.cookie = cookieStr.trim();
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
    let consecutiveErrors = 0; // 连续失败计数（服务崩溃/重启时容错）
    for (let i = 0; i < 120; i++) {
      await new Promise((r) => setTimeout(r, 500));
      try {
        const j = await api.getScan(id);
        consecutiveErrors = 0; // 请求成功，重置
        setJob(j);
        if (j.status === "completed" || j.status === "failed") {
          setSubmitting(false);
          if (j.status === "failed") setError(j.error || "扫描失败");
          return;
        }
      } catch (e) {
        consecutiveErrors++;
        // 服务可能崩溃/重启中，容忍前 6 次连续失败（≈3 秒），超过才判定失败
        if (consecutiveErrors >= 6) {
          setError(`服务暂不可用：${e.message}（可能因扫描目标过大导致服务重启，请减小被测包后重试）`);
          setSubmitting(false);
          return;
        }
        // 否则继续轮询，等服务恢复
      }
    }
    setSubmitting(false);
    setError("扫描超时");
  };

  const reachedStates = new Set();
  if (job?.report?.log) job.report.log.forEach((l) => reachedStates.add(l.state));

  // 计算每个状态的实际耗时
  const stateTimings = {};
  if (job?.report?.log) {
    const times = job.report.log.filter((l) => l.at).map((l) => ({ state: l.state, at: new Date(l.at).getTime() })).sort((a, b) => a.at - b.at);
    for (let i = 0; i < times.length; i++) {
      const next = times.slice(i + 1).find((t) => t.state !== times[i].state);
      const dur = next ? next.at - times[i].at : 0;
      if (!stateTimings[times[i].state]) stateTimings[times[i].state] = dur;
    }
  }
  const speedColor = { fast: "#86efac", medium: "#fde68a", slow: "#fca5a5" };
  const startedAt = job?.startedAt ? new Date(job.startedAt).getTime() : 0;
  const elapsedSec = startedAt ? Math.round((Date.now() - startedAt) / 1000) : 0;

  const canSubmit = gitUrl.trim() || (mode === "upload" && uploadedFile) || (mode === "path" && manualPath.trim()) || (mode === "code" && code.trim()) || (mode === "web" && webUrl.trim() && authConfirmed);

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
        <button className={mode === "web" ? "" : "secondary"} onClick={() => setMode("web")}>
          🌐 Web 渗透
        </button>
      </div>

      <div className="card">
        {/* 语言选择 + AI 项目选项 */}
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
          <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
            <label>AI/LLM 项目？（启用 AI 安全检测）</label>
            <div style={{ display: "flex", alignItems: "center", gap: 8, height: 36 }}>
              <input type="checkbox" id="aiProject" checked={isAiProject}
                onChange={(e) => setIsAiProject(e.target.checked)} style={{ width: "auto" }} />
              <label htmlFor="aiProject" style={{ marginBottom: 0, fontSize: 13, color: isAiProject ? "#14b8a6" : "var(--text-dim)" }}>
                {isAiProject ? "🧠 已启用 AI 安全检测（提示词注入/越狱/Skill 漏洞/模型 RCE）" : "勾选启用"}
              </label>
            </div>
          </div>
        </div>

        {/* Git 仓库地址（拉取源码扫描） */}
        <div className="form-group">
          <label>Git 仓库地址（可选，填入后自动 clone 拉取源码）</label>
          <input value={gitUrl} onChange={(e) => setGitUrl(e.target.value)}
            placeholder="https://github.com/org/repo.git" />
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
                      : uploadedFile.type === "source_file"
                      ? `源码文件（${(uploadedFile.size / 1024).toFixed(1)} KB）`
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
                  <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                    ⚠️ 大小限制 <strong style={{ color: "var(--accent)" }}>{MAX_UPLOAD_MB} MB</strong>（demo 环境，大包易内存溢出）
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
            <label>被测件路径（源码目录 / 固件 / 二进制文件）</label>
            <input value={manualPath} onChange={(e) => setManualPath(e.target.value)}
              placeholder="/opt/project/src 或 /tmp/firmware.bin 或 /home/user/app.jar" />
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

        {/* Web 渗透测试模式 */}
        {mode === "web" && (
          <div>
            <div className="msg msg-error" style={{ marginBottom: 16 }}>
              ⚠️ <strong>法律警告</strong>：Web 渗透测试会对目标发起真实 HTTP 请求。
              仅可用于你拥有所有权或已获得书面授权的目标。未经授权的渗透测试是违法行为。
            </div>
            <div className="form-group">
              <label>目标 URL</label>
              <input value={webUrl} onChange={(e) => setWebUrl(e.target.value)}
                placeholder="http://target-app.example.com" />
            </div>
            <div className="form-group" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <input type="checkbox" id="authConfirm" checked={authConfirmed}
                onChange={(e) => setAuthConfirmed(e.target.checked)}
                style={{ width: "auto" }} />
              <label htmlFor="authConfirm" style={{ marginBottom: 0, color: authConfirmed ? "#86efac" : "#fca5a5" }}>
                我确认拥有该目标的所有权或已获得书面授权进行安全测试
              </label>
            </div>
            <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
              系统将：① 爬取目标页面提取接口/参数 ② LLM 分析构造攻击 ③ 实际发送请求验证漏洞
            </p>

            {/* 认证配置（可选） */}
            <div style={{ marginTop: 16, padding: 12, border: "1px solid var(--border)", borderRadius: 8 }}>
              <p style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 10 }}>🔐 认证配置（可选，用于测试需登录的系统）</p>
              <div style={{ display: "flex", gap: 12 }}>
                <div className="form-group" style={{ flex: 1, marginBottom: 8 }}>
                  <label>登录 URL（留空则用目标 URL + /login）</label>
                  <input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} placeholder="http://target:8080/login" />
                </div>
              </div>
              <div style={{ display: "flex", gap: 12 }}>
                <div className="form-group" style={{ flex: 1, marginBottom: 8 }}>
                  <label>用户名</label>
                  <input value={loginUser} onChange={(e) => setLoginUser(e.target.value)} placeholder="admin" />
                </div>
                <div className="form-group" style={{ flex: 1, marginBottom: 8 }}>
                  <label>密码</label>
                  <input type="password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} placeholder="password" />
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>或直接提供 Cookie/Token（优先于用户名密码）</label>
                <input value={cookieStr} onChange={(e) => setCookieStr(e.target.value)} placeholder="JSESSIONID=xxx; token=yyy" />
              </div>
            </div>
          </div>
        )}

        {error && <div className="msg msg-error" style={{ marginTop: 12 }}>{error}</div>}

        <button onClick={submit} disabled={!canSubmit || submitting}
          style={{
            marginTop: 16,
            opacity: submitting ? 0.7 : 1,
            cursor: submitting ? "wait" : "pointer",
            background: submitting ? "var(--border)" : undefined,
            color: submitting ? "var(--accent)" : undefined,
          }}>
          {submitting ? "⏳ 正在挖掘中...（请勿重复提交，预计 1-5 分钟）" : "🚀 开始挖掘"}
        </button>
        {submitting && (
          <div className="msg msg-info" style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8 }}>
            <span className="loading" style={{ fontSize: 18 }}>🔄</span>
            <span>任务进行中：LLM 正在分析，编排引擎逐个状态执行。请耐心等待，可在下方查看实时进度。</span>
          </div>
        )}
      </div>

      {scanId && !job && submitting && (
        <div className="msg msg-info">分析中: {scanId}...</div>
      )}

      {/* 编排进度 */}
        {job?.report?.log && (
        <div className="card">
          <h2>编排进度 <span style={{ fontSize: 13, color: "var(--text-dim)", marginLeft: 12 }}>已耗时 {elapsedSec}s</span></h2>
          <ul className="timeline">
            {STATES.map(([state, desc, estimate, speed]) => {
              const isDone = reachedStates.has(state);
              const actualMs = stateTimings[state] || 0;
              const actualSec = Math.round(actualMs / 1000);
              return (
                <li key={state} className={`timeline-item ${isDone ? "done" : ""}`}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <span className="timeline-state">{state}</span>
                      <span className="timeline-desc" style={{ marginLeft: 8 }}>{desc}</span>
                    </div>
                    <div style={{ fontSize: 11, display: "flex", gap: 8, alignItems: "center" }}>
                      {/* 预估时间 */}
                      <span style={{ color: "var(--text-muted)" }}>预估 {estimate}</span>
                      {/* 实际耗时 */}
                      {isDone && actualSec > 0 && (
                        <span style={{ color: speedColor[speed] || "var(--text-dim)" }}>
                          实际 {actualSec}s
                        </span>
                      )}
                      {/* 速度指示色块 */}
                      <span style={{ width: 8, height: 8, borderRadius: "50%", background: speedColor[speed] || "#64748b", display: "inline-block" }} />
                    </div>
                  </div>
                </li>
              );
            })}
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
