// engine.js — 编排引擎核心
//
// 把状态机 + 五类 Agent + 内存组件串成完整闭环。
// 对外只暴露 run(scanRequest, toolOutputs)，内部按状态顺序驱动各 Agent。
//
// 设计要点：
//   - 状态 → handler 的映射集中注册（HANDLERS），便于扩展
//   - 每个 handler 签名统一：async (ctx, deps) => ctx
//   - deps 通过构造函数注入（fpStore / knowledgeGraph / ruleEngine / findingStore）
//   - 任一状态失败可跳转到 FAILED 终态，保留已完成结果

const { OrchestrationContext } = require("./context");
const { STATES, nextOf, TERMINAL_STATES } = require("./state-machine");
const config = require("./config");

const { FalsePositiveStore } = require("./memory/false-positive-store");
const { KnowledgeGraph } = require("./memory/knowledge-graph");
const { FindingStore } = require("./memory/finding-store");
const { RuleEngine } = require("./rules/rule-engine");

const dispatcher = require("./agents/dispatcher");
const detector = require("./agents/detector");
const verifier = require("./agents/verifier");
const fixer = require("./agents/fixer");
const learner = require("./agents/learner");
const zeroDayHunter = require("./agents/zero-day-hunter");
const llmHunter = require("./agents/llm-hunter");
const attackScenarioBuilder = require("./agents/attack-scenario-builder");
const projectUnderstand = require("./agents/project-understand");

// 颜色（降级兼容 Windows）
const C = (() => {
  if (process.platform.startsWith("win")) {
    try {
      require("child_process").execSync("node -e \"require('child_process').execSync('')\"", { stdio: "ignore" });
    } catch {}
  }
  return {
    info: "\x1b[36m",
    ok: "\x1b[32m",
    warn: "\x1b[33m",
    err: "\x1b[31m",
    dim: "\x1b[2m",
    reset: "\x1b[0m",
  };
})();

class OrchestratorEngine {
  constructor(options = {}) {
    // 依赖注入（默认用内置内存实现，可替换为 DB/Redis 版本）
    // 优先用 options 显式传入的 store；否则用 options.stores（来自 repository/factory）
    const stores = options.stores || null;
    this.fpStore_         = options.fpStore         || (stores && stores.fpStore)         || new FalsePositiveStore();
    this.knowledgeGraph_  = options.knowledgeGraph  || (stores && stores.knowledgeGraph)  || new KnowledgeGraph();
    this.ruleEngine_      = options.ruleEngine      || (stores && stores.ruleEngine)      || new RuleEngine();
    this.findingStore_    = options.findingStore    || (stores && stores.findingStore)    || new FindingStore();

    this.deps = {
      fpStore: this.fpStore_,
      knowledgeGraph: this.knowledgeGraph_,
      ruleEngine: this.ruleEngine_,
      findingStore: this.findingStore_,
    };

    // 状态 → handler 映射
    this.handlers = {
      INIT: (ctx) => dispatcher.normalize(ctx, this.deps),
      PROJECT_UNDERSTAND: (ctx) => projectUnderstand.understand(ctx, this.deps),
      LLM_HUNT: (ctx) => llmHunter.hunt(ctx, this.deps),
      FILTER: (ctx) => dispatcher.filterFalsePositives(ctx, this.deps),
      DISPATCH: (ctx) => dispatcher.dispatch(ctx, this.deps),
      DETECT: (ctx) => detector.detect(ctx, this.deps),
      RAG_MATCH: (ctx) => verifier.ragMatch(ctx, this.deps),
      ZERO_DAY: (ctx) => zeroDayHunter.huntZeroDay(ctx, this.deps),
      VERIFY: (ctx) => verifier.verify(ctx, this.deps),
      ATTACK_SCENARIO: (ctx) => attackScenarioBuilder.build(ctx, this.deps),
      FIX: (ctx) => fixer.fix(ctx, this.deps),
      LEARN: (ctx) => learner.learn(ctx, this.deps),
      REPORT: (ctx) => {
        ctx.completedAt = new Date().toISOString();
        ctx.log_("REPORT", "报告生成完成", "info");
        return ctx;
      },
    };
  }

  /**
   * 执行一次完整编排
   * @param {Object} scanRequest   符合 scan-request.schema.json
   * @param {Object} toolOutputs   { sast?, sca?, bat? } 各工具归一化输出（可选，无则纯 LLM 通道）
   * @param {Object} sourceInput   { code?, path?, language? } 源代码输入（LLM 自主挖掘用，可选）
   * @returns {Promise<Object>}    最终报告（ctx.toReport()）
   */
  async run(scanRequest, toolOutputs, sourceInput) {
    const ctx = new OrchestrationContext(scanRequest);
    ctx.sourceInput = sourceInput || null;
    ctx.toolOutputs = toolOutputs || {};

    // 打印启动信息
    const llmMode = config.llm.mode;
    console.log(`${C.info}┌─ 编排启动${C.reset}`);
    console.log(`${C.info}│ scanId: ${scanRequest.scanId}${C.reset}`);
    console.log(`${C.info}│ LLM 模式: ${llmMode}${C.reset}`);
    console.log(`${C.info}│ 工具输出: ${Object.keys(toolOutputs || {}).join(", ") || "(无)"}${C.reset}`);
    console.log(`${C.info}└──────────${C.reset}`);

    let stateName = "INIT";
    while (stateName) {
      const handler = this.handlers[stateName];
      if (!handler) {
        ctx.log_(stateName, `无 handler，跳过`, "warn");
        stateName = nextOf(stateName);
        continue;
      }
      ctx.current = stateName;
      const stateDef = STATES.find((s) => s.name === stateName);
      console.log(`${C.dim}▶ ${stateName}${C.reset} ${C.dim}${stateDef?.desc || ""}${C.reset}`);
      const t0 = Date.now();
      try {
        await handler(ctx);
        const dt = Date.now() - t0;
        console.log(`${C.ok}  ✓ ${stateName} (${dt}ms)${C.reset}`);
      } catch (e) {
        ctx.log_(stateName, `状态执行失败: ${e.message}`, "error");
        console.log(`${C.err}  ✗ ${stateName} 失败: ${e.message}${C.reset}`);
        ctx.current = "FAILED";
        ctx.error = e.message;
        break;
      }
      // REPORT 是终态，执行完即停（不再 nextOf）
      if (TERMINAL_STATES.includes(stateName)) break;
      stateName = nextOf(stateName);
    }

    // 终态处理
    if (ctx.current !== "FAILED") {
      ctx.current = "REPORT";
    }
    ctx.completedAt = ctx.completedAt || new Date().toISOString();

    // 给所有 Finding 补 scanId 并持久化（用于按任务隔离查询 + 删除任务时联动清理）
    const scanId = scanRequest.scanId;
    for (const f of ctx.findings) {
      if (!f.scanId) {
        f.scanId = scanId;
        // 持久化到 store（之前只改了内存引用，重启/删除时会丢失关联）
        try { await this.findingStore_.update(f.findingId, { scanId }); } catch {}
      }
    }

    return ctx.toReport();
  }

  /** 暴露内部状态供调试（async，因 store 全 async 化） */
  async inspect() {
    return {
      fpPatterns: (await this.fpStore_.list()).length,
      knowledgeGraph: await this.knowledgeGraph_.stats(),
      rules: (await this.ruleEngine_.list()).length,
      findings: await this.findingStore_.stats(),
    };
  }

  /** 暴露内部组件供 MCP 等外部访问 */
  get findingStore() {
    return this.findingStore_;
  }
  get fpStore() {
    return this.fpStore_;
  }
  get knowledgeGraph() {
    return this.knowledgeGraph_;
  }
  get ruleEngine() {
    return this.ruleEngine_;
  }
}

module.exports = { OrchestratorEngine };
