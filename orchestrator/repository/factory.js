// repository/factory.js — 存储工厂
//
// 按 DB_MODE 选择实现：
//   memory           全内存（默认，零依赖）
//   postgres+neo4j   Postgres + Neo4j（生产）
//
// DB 不可用时自动降级到内存版，保证本地无 DB 也能跑（核心设计）。
//
// 环境变量：
//   DB_MODE        memory | postgres+neo4j（默认 memory）
//   DATABASE_URL   postgres://user:pass@host:5432/dbname
//   NEO4J_URL      bolt://localhost:7687
//   NEO4J_USER     neo4j
//   NEO4J_PASSWORD password

const { FindingStore } = require("../memory/finding-store");
const { KnowledgeGraph } = require("../memory/knowledge-graph");
const { FalsePositiveStore } = require("../memory/false-positive-store");
const { RuleEngine } = require("../rules/rule-engine");

/**
 * 探测依赖是否可用（避免 require 失败直接崩）
 */
function tryRequire(name) {
  try { return require(name); } catch { return null; }
}

/**
 * 创建存储实例集合
 * @returns {{findingStore, knowledgeGraph, fpStore, ruleEngine, mode}}
 */
async function createStores(mode) {
  mode = mode || process.env.DB_MODE || "memory";

  if (mode === "postgres+neo4j") {
    const pg = tryRequire("pg");
    const neo4j = tryRequire("neo4j-driver");
    const databaseUrl = process.env.DATABASE_URL;
    const neo4jUrl = process.env.NEO4J_URL;

    if (!pg || !databaseUrl) {
      console.warn("[repository] Postgres 不可用（缺 pg 或 DATABASE_URL），降级到内存 FindingStore/FPStore/RuleEngine");
    }
    if (!neo4j || !neo4jUrl) {
      console.warn("[repository] Neo4j 不可用（缺 neo4j-driver 或 NEO4J_URL），降级到内存 KnowledgeGraph");
    }

    let pool = null;
    let driver = null;
    if (pg && databaseUrl) {
      try {
        pool = new pg.Pool({ connectionString: databaseUrl, max: 10 });
        await pool.query("SELECT 1"); // 探测连接
      } catch (e) {
        console.warn(`[repository] Postgres 连接失败: ${e.message}，降级到内存`);
        pool = null;
      }
    }
    if (neo4j && neo4jUrl) {
      try {
        driver = neo4j.driver(neo4jUrl, neo4j.auth.basic(process.env.NEO4J_USER || "neo4j", process.env.NEO4J_PASSWORD || ""));
        await driver.verifyConnectivity();
      } catch (e) {
        console.warn(`[repository] Neo4j 连接失败: ${e.message}，降级到内存`);
        if (driver) await driver.close().catch(() => {});
        driver = null;
      }
    }

    // 按可用性混合装配（pg 和 neo4j 各自独立降级）
    const { PgFindingStore } = require("./pg-finding-store");
    const { PgFpStore } = require("./pg-fp-store");
    const { PgRuleEngine } = require("./pg-rule-store");
    const { Neo4jKnowledgeGraph } = require("./neo4j-knowledge-graph");

    return {
      findingStore: pool ? new PgFindingStore(pool) : new FindingStore(),
      fpStore: pool ? new PgFpStore(pool) : new FalsePositiveStore(),
      ruleEngine: pool ? new PgRuleEngine(pool) : new RuleEngine(),
      knowledgeGraph: driver ? new Neo4jKnowledgeGraph(driver) : new KnowledgeGraph(),
      mode: `pg:${!!pool} neo4j:${!!driver}`,
    };
  }

  // 默认全内存
  return {
    findingStore: new FindingStore(),
    knowledgeGraph: new KnowledgeGraph(),
    fpStore: new FalsePositiveStore(),
    ruleEngine: new RuleEngine(),
    mode: "memory",
  };
}

module.exports = { createStores };
