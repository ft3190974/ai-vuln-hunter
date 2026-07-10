// sandbox/docker-adapter.js — Docker 沙箱适配器
//
// 通过 child_process 调 `docker run` 在隔离容器里执行 POC。
// 强隔离：网络白名单（默认 none）、只读根文件系统、内存限制、无特权。
//
// 环境变量：
//   SANDBOX_IMAGE   执行镜像，默认 node:20-alpine（web 类 POC）
//   SANDBOX_NET     网络模式，默认 none（禁止外联）；验证 Web 服务时改 host
//
// 注意：本适配器需要本机已安装 Docker。无 Docker 时 execute 会返回 error，
// 上层（verifier）应据此降级到 mock 或 LLM 判定。

const { execFile } = require("child_process");
const { promisify } = require("util");
const { ISandbox } = require("./interface");

const execFileAsync = promisify(execFile);

class DockerSandbox extends ISandbox {
  constructor() {
    super();
    this.image = process.env.SANDBOX_IMAGE || "node:20-alpine";
    this.network = process.env.SANDBOX_NET || "none";
  }

  implName() {
    return "docker";
  }

  /**
   * 检查 Docker 是否可用（不抛异常，返回 boolean）
   */
  async available() {
    try {
      await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"], { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  async execute(req) {
    const poc = req.poc || {};
    const timeoutMs = req.timeoutMs || 30000;
    const targetType = req.targetType || "web";

    // 构造 POC 执行脚本（写入容器内 /tmp/poc.js 执行）
    const script = this._buildScript(poc, targetType);

    // docker run 参数：强隔离
    const args = [
      "run", "--rm",
      "--network", this.network,        // 默认 none，禁止外联
      "--read-only",                     // 只读根文件系统
      "--memory", "256m",                // 内存限制
      "--cpus", "0.5",                   // CPU 限制
      "--cap-drop", "ALL",               // 移除所有 capability
      "--security-opt", "no-new-privileges",
      "-e", `POC_ENTRY=${poc.entry || ""}`,
      "-e", `POC_PAYLOAD=${poc.payload || ""}`,
      "--tmpfs", "/tmp:rw,size=10m",     // 只读根下挂可写 /tmp
      this.image,
      "node", "-e", script,
    ];

    const t0 = Date.now();
    try {
      const { stdout, stderr } = await execFileAsync("docker", args, {
        timeout: timeoutMs,
        maxBuffer: 1024 * 1024,
      });
      const dt = Date.now() - t0;
      // 解析容器输出（脚本以 JSON 输出执行结果）
      const result = this._parseOutput(stdout, stderr, dt);
      return result;
    } catch (e) {
      // 超时或容器异常也可能是漏洞信号（如崩溃）
      const dt = Date.now() - t0;
      return this._handleError(e, dt);
    }
  }

  /**
   * 构造容器内执行的脚本
   * 真实实现：根据 targetType 用 fetch（web）/child_process（firmware）/业务接口回放
   * 这里给出 web 类（fetch HTTP）的基础实现
   */
  _buildScript(poc, targetType) {
    // 用环境变量避免命令注入
    return `
const entry = process.env.POC_ENTRY || "";
const payload = process.env.POC_PAYLOAD || "";
(async () => {
  try {
    const result = { triggered: false, evidence: "", response: {} };
    ${targetType === "web" ? `
    if (entry) {
      const resp = await fetch(entry, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: payload }),
      }).catch(e => ({ status: 0, statusText: e.message, text: async () => "" }));
      const text = typeof resp.text === "function" ? await resp.text() : "";
      result.response = { status: resp.status, body: text.slice(0, 500) };
      // 简单判定：响应含 payload 或状态异常
      if (text.includes(payload.slice(0, 20)) || resp.status >= 500) {
        result.triggered = true;
        result.evidence = "响应中反射 payload 或服务端异常";
      }
    }` : `
    // firmware / business 场景：真实实现调二进制或业务接口
    result.evidence = "非 web 场景需定制执行器";
    `}
    process.stdout.write(JSON.stringify(result));
  } catch (e) {
    process.stdout.write(JSON.stringify({ triggered: false, evidence: "执行异常: " + e.message, response: {} }));
  }
})();
`;
  }

  _parseOutput(stdout, stderr, durationMs) {
    let parsed = {};
    try {
      parsed = JSON.parse(stdout.trim().split("\n").pop());
    } catch {
      parsed = {
        triggered: false,
        evidence: `无法解析容器输出: ${stdout.slice(0, 200)}`,
        response: { stdout: stdout.slice(0, 500), stderr: stderr.slice(0, 500) },
      };
    }
    return { ...parsed, sandboxImpl: "docker", durationMs };
  }

  _handleError(e, durationMs) {
    // 容器被 OOM kill / 超时 / 目标崩溃，都可能是漏洞信号
    const msg = String(e.message || "");
    let triggered = false;
    let evidence = `沙箱执行错误: ${msg}`;
    if (msg.includes("timeout") || msg.includes("TIMEDOUT")) {
      evidence = "POC 执行超时（可能触发死循环或资源耗尽）";
      triggered = true;
    } else if (msg.includes("non-zero") || msg.includes("137") || msg.includes("139")) {
      evidence = "容器异常退出（OOM kill 或 segfault），疑似漏洞触发";
      triggered = true;
    }
    return {
      triggered,
      evidence,
      response: { error: msg.slice(0, 300) },
      sandboxImpl: "docker",
      durationMs,
    };
  }
}

module.exports = { DockerSandbox };
