// vuln-db/sync-manager.js — 多源漏洞库同步管理器
//
// 协调所有 connector 的同步：并行同步全部、单源同步、记录状态、定时调度。
// 是 L（HTTP API）查询漏洞库状态的入口。

const config = require("./config");
const { NvdConnector } = require("./connectors/nvd-connector");
const { OsvConnector } = require("./connectors/osv-connector");
const { CapecConnector } = require("./connectors/capec-connector");
const { NucleiConnector } = require("./connectors/nuclei-connector");
const { CnvdConnector } = require("./connectors/cnvd-connector");
const { CnnvdConnector } = require("./connectors/cnnvd-connector");
const { GhsaConnector } = require("./connectors/ghsa-connector");
const { VulncheckConnector } = require("./connectors/vulncheck-connector");
const { ExploitDbConnector } = require("./connectors/exploitdb-connector");
const { SeebugConnector } = require("./connectors/seebug-connector");

class SyncManager {
  /**
   * @param {object} deps  { knowledgeGraph, ruleEngine }
   *   两个目标存储由编排引擎的 OrchestratorEngine 提供（getter 暴露）
   */
  constructor(deps) {
    this.deps = deps;
    this.live = config.live;
    // 实例化所有 connector（按配置 enabled 过滤）
    this.connectors = new Map();
    this._register(new NvdConnector());
    this._register(new OsvConnector());
    this._register(new CapecConnector());
    this._register(new NucleiConnector());
    this._register(new CnvdConnector());
    this._register(new CnnvdConnector());
    this._register(new GhsaConnector());
    this._register(new VulncheckConnector());
    this._register(new ExploitDbConnector());
    this._register(new SeebugConnector());

    this.lastSyncAt = null;
    this.timer = null;
  }

  _register(connector) {
    if (connector.config.enabled !== false) {
      this.connectors.set(connector.name, connector);
    }
  }

  /**
   * 同步所有启用的数据源（并行）
   * @param {string|Date} [since]  增量起点
   * @returns {Promise<{total, results, startedAt, completedAt}>}
   */
  async syncAll(since) {
    const startedAt = new Date().toISOString();
    const names = [...this.connectors.keys()];
    const results = await Promise.all(
      names.map((name) => this.syncOne(name, since))
    );
    this.lastSyncAt = new Date().toISOString();
    const total = results.reduce(
      (acc, r) => ({
        nodes: acc.nodes + (r.nodes || 0),
        edges: acc.edges + (r.edges || 0),
        rules: acc.rules + (r.rules || 0),
        errors: acc.errors + (r.error ? 1 : 0),
      }),
      { nodes: 0, edges: 0, rules: 0, errors: 0 }
    );
    return { total, results, startedAt, completedAt: this.lastSyncAt };
  }

  /**
   * 同步单个数据源
   */
  async syncOne(name, since) {
    const connector = this.connectors.get(name);
    if (!connector) {
      return { source: name, error: `未知数据源: ${name}` };
    }
    return connector.ingest(
      {
        knowledgeGraph: this.deps.knowledgeGraph,
        ruleEngine: this.deps.ruleEngine,
        live: this.live,
      },
      since
    );
  }

  /**
   * 返回所有数据源的同步状态（供 HTTP API 查询）
   */
  status() {
    return {
      live: this.live,
      lastSyncAt: this.lastSyncAt,
      sources: [...this.connectors.values()].map((c) => c.status()),
    };
  }

  /**
   * 启动定时同步（小时级）
   */
  startScheduled(intervalHours) {
    const h = intervalHours || config.syncIntervalHours;
    if (this.timer) this.stopScheduled();
    const ms = h * 3600 * 1000;
    this.timer = setInterval(() => {
      this.syncAll().catch((e) => console.error("[SyncManager] 定时同步失败:", e.message));
    }, ms);
    console.log(`[SyncManager] 定时同步已启动，每 ${h} 小时一次`);
  }

  stopScheduled() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

module.exports = { SyncManager };
