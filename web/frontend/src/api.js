// src/api.js — 后端 API 封装（含 JWT token 自动注入 + 401 处理）
const BASE = "/api";

const TOKEN_KEY = "ai_vuln_hunter_token";
const USER_KEY = "ai_vuln_hunter_user";

// token 存取（localStorage）
export const auth = {
  getToken: () => localStorage.getItem(TOKEN_KEY),
  getUser: () => {
    try { return JSON.parse(localStorage.getItem(USER_KEY) || "null"); } catch { return null; }
  },
  setSession: (accessToken, user) => {
    localStorage.setItem(TOKEN_KEY, accessToken);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  clear: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
  isLoggedIn: () => !!localStorage.getItem(TOKEN_KEY),
};

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  // 自动注入 token
  const token = auth.getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const resp = await fetch(BASE + path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  // 401：清 token，跳登录（避免死循环：login 请求本身的 401 不跳）
  if (resp.status === 401 && !path.startsWith("/auth/")) {
    auth.clear();
    if (location.hash !== "#/login" && !location.pathname.endsWith("/login")) {
      location.hash = "#/login";
    }
    throw new Error("未登录或登录已过期");
  }

  let data;
  try { data = await resp.json(); } catch { data = null; }
  if (!resp.ok && data) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

export const api = {
  health: () => request("/health"),
  status: () => request("/status"),
  dashboard: () => request("/dashboard"),
  graph: () => request("/graph"),
  graphVariants: (id) => request(`/graph/variants/${id}`),
  findings: (filter = {}) => {
    const qs = new URLSearchParams(filter).toString();
    return request(`/findings${qs ? "?" + qs : ""}`);
  },
  finding: (id) => request(`/findings/${id}`),
  findingsStats: () => request("/findings-stats/summary"),
  submitScan: (scanRequest, toolOutputs, sourceInput) =>
    request("/scan", { method: "POST", body: { scanRequest, toolOutputs, sourceInput } }),
  getScan: (id) => request(`/scan/${id}`),
  listScans: () => request("/scan"),
  deleteScan: (id) => request(`/scan/${id}`, { method: "DELETE" }),
  vulnDbSources: () => request("/vuln-db/sources"),
  syncVulnDb: (source) =>
    request(`/vuln-db/sync${source ? "?source=" + source : ""}`, { method: "POST" }),

  // 认证
  register: (username, password) =>
    request("/auth/register", { method: "POST", body: { username, password } }),
  login: (username, password) =>
    request("/auth/login", { method: "POST", body: { username, password } }),
  me: () => request("/auth/me"),

  // 自定义规则管理
  listRules: (filter = {}) => {
    const qs = new URLSearchParams(filter).toString();
    return request(`/rules${qs ? "?" + qs : ""}`);
  },
  createRule: (rule) => request("/rules", { method: "POST", body: rule }),
  updateRule: (ruleId, patch) => request(`/rules/${ruleId}`, { method: "PUT", body: patch }),
  deleteRule: (ruleId) => request(`/rules/${ruleId}`, { method: "DELETE" }),
  toggleRule: (ruleId) => request(`/rules/${ruleId}/toggle`, { method: "POST" }),

  // 文件上传（源码包 zip / 二进制）
  uploadFile: (file) => {
    const formData = new FormData();
    formData.append("file", file);
    return fetch(BASE + "/upload", { method: "POST", body: formData })
      .then(async (resp) => {
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
        return data;
      });
  },

  // 系统设置 — LLM 配置
  listLlmConfigs: () => request("/settings/llm"),
  createLlmConfig: (cfg) => request("/settings/llm", { method: "POST", body: cfg }),
  updateLlmConfig: (id, patch) => request(`/settings/llm/${id}`, { method: "PUT", body: patch }),
  deleteLlmConfig: (id) => request(`/settings/llm/${id}`, { method: "DELETE" }),
  testLlmConfig: (id) => request(`/settings/llm/${id}/test`, { method: "POST" }),

  // 系统设置 — 工具集成配置
  listToolConfigs: () => request("/settings/tools"),
  createToolConfig: (cfg) => request("/settings/tools", { method: "POST", body: cfg }),
  updateToolConfig: (id, patch) => request(`/settings/tools/${id}`, { method: "PUT", body: patch }),
  deleteToolConfig: (id) => request(`/settings/tools/${id}`, { method: "DELETE" }),
  testToolConfig: (id) => request(`/settings/tools/${id}/test`, { method: "POST" }),
};
