// sandbox/interface.js — 沙箱抽象接口
//
// 验证层（verifier）通过此接口执行 POC，不感知具体实现（mock / docker / firecracker）。
// 真实沙箱在隔离容器里执行 POC，返回执行结果（崩溃/异常/响应特征）。
//
// 用法：
//   const { getSandbox } = require("./sandbox");
//   const sb = getSandbox();
//   const result = await sb.execute(poc, { targetType: "web" });

/**
 * POC 执行请求
 * @typedef {Object} ExecutionRequest
 * @property {Object} poc          POC 对象（符合 finding.poc 结构：entry/payload/precondition/expected）
 * @property {string} targetType   "web" | "firmware" | "business"
 * @property {string} [language]   目标语言（web 场景）
 * @property {string} [binaryPath] 二进制路径（firmware 场景）
 * @property {number} [timeoutMs]  超时（默认 30000）
 */

/**
 * POC 执行结果
 * @typedef {Object} ExecutionResult
 * @property {boolean} triggered     POC 是否成功触发漏洞（核心判定）
 * @property {string}  evidence      触发证据（响应内容/崩溃信息/异常堆栈）
 * @property {object}  response      原始响应（HTTP 响应体 / 退出码 / 信号）
 * @property {string}  sandboxImpl   使用的沙箱实现（mock/docker/qemu）
 * @property {number}  durationMs    执行耗时
 */

class ISandbox {
  /**
   * 执行 POC
   * @param {ExecutionRequest} req
   * @returns {Promise<ExecutionResult>}
   */
  async execute(_req) {
    throw new Error("ISandbox.execute 必须由子类实现");
  }

  /** 实现标识 */
  implName() {
    return "abstract";
  }
}

module.exports = { ISandbox };
