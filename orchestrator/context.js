// context.js — 任务上下文
//
// 一次编排（一个 scanRequest 对应一次 run）的全部可变状态都装在这里。
// 各 Agent 函数签名统一为 (ctx) => ctx（纯函数风格，便于回放与测试）。
//
// 字段：
//   scanRequest   原始扫描请求
//   toolOutputs   各工具的归一化输出（ScaOutput/SastOutput/BatOutput）
//   findings      编排过程中产生的 Finding 列表（引用 finding-store，这里存 ID）
//   pendingCandidates  检测阶段产出的候选（待验证）
//   verifiedPocs       验证通过的 POC
//   patches            修复 patch
//   learnSuggestions   学习 Agent 的增量建议
//   log                状态机日志（每步记录）
//   current            当前状态（state-machine 的状态名）

class OrchestrationContext {
  constructor(scanRequest) {
    this.scanRequest = scanRequest;
    this.toolOutputs = {}; // { sast: SastOutput, sca: ScaOutput, bat: BatOutput }
    this.findings = []; // Finding 对象数组
    this.pendingCandidates = []; // 检测阶段候选（{findingId, ruleId, confidence}）
    this.verifiedPocs = []; // {findingId, poc}
    this.patches = []; // {findingId, patch, strategy}
    this.learnSuggestions = []; // 学习建议（{type, content}）
    this.log = []; // {state, at, msg, level}
    this.current = "INIT";
    this.startedAt = new Date().toISOString();
    this.completedAt = null;
  }

  /**
   * 记录日志
   * @param {string} state  当前状态
   * @param {string} msg    日志消息
   * @param {"debug"|"info"|"warn"|"error"} level
   */
  log_(state, msg, level = "info") {
    this.log.push({ state, msg, level, at: new Date().toISOString() });
  }

  /** 返回最终报告 */
  toReport() {
    return {
      scanId: this.scanRequest.scanId,
      startedAt: this.startedAt,
      completedAt: this.completedAt,
      current: this.current,
      findings: this.findings,
      pocs: this.verifiedPocs,
      patches: this.patches,
      learnSuggestions: this.learnSuggestions,
      log: this.log,
    };
  }
}

module.exports = { OrchestrationContext };
