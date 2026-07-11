// vuln-db/test-connectors.js — 多源漏洞库 connector 端到端测试
//
// 默认用 mock 数据测试（不联网），验证：
//   1. 4 个 connector 都能正确 normalize
//   2. ingest 能正确灌入知识图谱/规则库
//   3. 同步状态记录正确
//
// 真实联网测试：set VULNDB_LIVE=1 && node test-connectors.js

const { SyncManager } = require("./sync-manager");
const { KnowledgeGraph } = require("../orchestrator/memory/knowledge-graph");
const { RuleEngine } = require("../orchestrator/rules/rule-engine");

const PASS = "\x1b[32m✓\x1b[0m";
const FAIL = "\x1b[31m✗\x1b[0m";
const HDR = "\x1b[1;36m";

async function main() {
  console.log(HDR + "=".repeat(60));
  console.log("J 多源漏洞库 · Connector 端到端测试");
  console.log("=".repeat(60) + "\x1b[0m\n");

  // 用独立的知识图谱/规则库实例（不污染编排引擎）
  const knowledgeGraph = new KnowledgeGraph();
  const ruleEngine = new RuleEngine();
  const initialNodes = (await knowledgeGraph.stats()).nodes;
  const initialRules = (await ruleEngine.list()).length;
  console.log(`初始：图谱 ${initialNodes} 节点，规则 ${initialRules} 条\n`);

  const sync = new SyncManager({ knowledgeGraph, ruleEngine });

  // 1. 全量同步（mock 模式）
  console.log(HDR + "[1] 全量同步（4 个数据源并行）" + "\x1b[0m");
  const result = await sync.syncAll();
  console.log(`  ${PASS} 同步完成：${result.results.length} 个源`);
  console.log(`  ${PASS} 入库：${result.total.nodes} 节点, ${result.total.edges} 边, ${result.total.rules} 规则`);
  if (result.total.errors > 0) {
    console.log(`  ${FAIL} ${result.total.errors} 个源失败`);
  }

  // 2. 校验各 connector 产出
  let pass = 0;
  let fail = 0;
  const check = (name, cond, detail = "") => {
    if (cond) { pass++; console.log(`  ${PASS} ${name} ${detail}`); }
    else { fail++; console.log(`  ${FAIL} ${name} ${detail}`); }
  };

  console.log("\n" + HDR + "[2] 校验各数据源产出" + "\x1b[0m");
  const bySource = {};
  for (const r of result.results) bySource[r.source] = r;

  // NVD：应有 CVE 节点 + 至少 1 条 VARIANT_OF 边
  check("NVD 入库 CVE 节点", bySource.nvd.nodes >= 2, `(${bySource.nvd.nodes} 个)`);
  check("NVD 建立变种关系边", bySource.nvd.edges >= 1, `(${bySource.nvd.edges} 条 VARIANT_OF)`);

  // OSV：跨生态漏洞节点
  check("OSV 入库漏洞节点", bySource.osv.nodes >= 2, `(${bySource.osv.nodes} 个)`);

  // CAPEC：攻击模式节点
  check("CAPEC 入库攻击模式", bySource.capec.nodes >= 3, `(${bySource.capec.nodes} 个)`);
  check("CAPEC 建立 CWE 关联边", bySource.capec.edges >= 1, `(${bySource.capec.edges} 条)`);

  // Nuclei：转规则（不是节点）
  check("Nuclei 转换为规则", bySource.nuclei.rules >= 3, `(${bySource.nuclei.rules} 条规则)`);
  check("Nuclei 不产生图谱节点", bySource.nuclei.nodes === 0, `(nodes=${bySource.nuclei.nodes})`);

  // 3. 校验图谱实际内容
  console.log("\n" + HDR + "[3] 校验图谱与规则库内容" + "\x1b[0m");
  const kgStats = await knowledgeGraph.stats();
  check("图谱节点数增长", kgStats.nodes > initialNodes, `(${initialNodes} → ${kgStats.nodes})`);
  check("图谱边数增长", kgStats.edges >= 1, `(${kgStats.edges} 条边)`);

  // 验证 NVD 的 log4j 变种关系可查询
  const variants = await knowledgeGraph.findVariants("CVE-2021-44228");
  check("可查询 CVE-2021-44228 的变种", variants.length >= 1, `(找到 ${variants.length} 个变种)`);

  // 验证规则库增长
  const newRules = (await ruleEngine.list()).length - initialRules;
  check("规则库增长", newRules >= 3, `(新增 ${newRules} 条，含 Nuclei 转换的)`);

  // 验证规则字段正确
  const nucleiRule = (await ruleEngine.list()).find((r) => r.ruleId.startsWith("NUCLEI-"));
  check("Nuclei 规则字段完整", nucleiRule && nucleiRule.category && nucleiRule.severity, `(${nucleiRule?.ruleId})`);

  // 4. 同步状态查询
  console.log("\n" + HDR + "[4] 同步状态查询" + "\x1b[0m");
  const status = sync.status();
  check("状态记录 10 个源", status.sources.length === 10, `(${status.sources.length} 个)`);
  for (const s of status.sources) {
    check(`${s.source} 状态有 lastSyncAt`, !!s.lastSyncAt, `(${s.lastSyncAt?.slice(11, 19)})`);
  }

  // 5. 单源增量同步
  console.log("\n" + HDR + "[5] 单源同步" + "\x1b[0m");
  const single = await sync.syncOne("nvd");
  check("单源同步 NVD 成功", !single.error, `(nodes=${single.nodes})`);

  // 总结
  console.log("\n" + "=".repeat(60));
  if (fail === 0) {
    console.log(`${PASS} J 多源漏洞库测试全部通过 (${pass}/${pass + fail})`);
    console.log(`  ✓ 4 个 connector（NVD/OSV/CAPEC/Nuclei）normalize 正确`);
    console.log(`  ✓ ingest 正确灌入知识图谱与规则库`);
    console.log(`  ✓ 变种关系边 + CWE 关联边建立`);
    console.log(`  ✓ 同步状态可查询、单源同步可用`);
    console.log(`  当前：图谱 ${kgStats.nodes} 节点/${kgStats.edges} 边，规则 ${(await ruleEngine.list()).length} 条`);
    process.exit(0);
  } else {
    console.log(`${FAIL} 测试有 ${fail} 项未通过 (${pass} 通过 / ${fail} 失败)`);
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(FAIL + " 测试异常:", e);
  process.exit(1);
});
