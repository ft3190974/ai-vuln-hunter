// vuln-db/config.js — 多源漏洞库配置
//
// 各数据源的连接参数、同步周期、开关。
// 全部可通过环境变量覆盖（VULNDB_ 前缀）。

const config = {
  // 全局同步周期（小时）
  syncIntervalHours: Number(process.env.VULNDB_SYNC_INTERVAL_HOURS) || 24,

  // 是否启用真实联网（默认 false：测试用 mock；true：真实拉取）
  live: process.env.VULNDB_LIVE === "1",

  sources: {
    // NVD — 美国 NVD 官方 CVE 库
    nvd: {
      enabled: process.env.VULNDB_NVD_ENABLED !== "0",
      apiUrl:
        process.env.VULNDB_NVD_API_URL ||
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
      apiKey: process.env.VULNDB_NVD_API_KEY || "", // 可选，有 key 速率限制更宽
      batchSize: Number(process.env.VULNDB_NVD_BATCH) || 100, // 每页条数（NVD 最大 2000）
      maxPages: Number(process.env.VULNDB_NVD_MAX_PAGES) || 2, // 测试用限制页数，生产调大
      timeoutMs: 30000,
    },

    // OSV.dev — Google 开源漏洞聚合（跨生态）
    osv: {
      enabled: process.env.VULNDB_OSV_ENABLED !== "0",
      apiUrl: process.env.VULNDB_OSV_API_URL || "https://api.osv.dev/v1",
      // OSV 按 package 查询；seedPackages 提供初始查询种子（可空，走 /v1/query/batch）
      seedPackages: [
        { package: { name: "log4j-core", ecosystem: "Maven" } },
        { package: { name: "openssl", ecosystem: "OSS-Fuzz" } },
      ],
      timeoutMs: 30000,
    },

    // CAPEC — MITRE 攻击模式库
    capec: {
      enabled: process.env.VULNDB_CAPEC_ENABLED !== "0",
      xmlUrl:
        process.env.VULNDB_CAPEC_XML_URL ||
        "https://capec.mitre.org/data/xml/capec_latest.xml",
      timeoutMs: 60000,
    },

    // Nuclei Templates — 本地 YAML 检测模板（→ 规则库）
    nuclei: {
      enabled: process.env.VULNDB_NUCLEI_ENABLED !== "0",
      templatesPath:
        process.env.VULNDB_NUCLEI_PATH ||
        require("path").resolve(__dirname, "..", "vuln-db", "seed-templates"),
    },
  },
};

module.exports = config;
