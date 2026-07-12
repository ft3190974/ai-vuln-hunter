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

    // ── 以下为新增 6 个漏洞库 ──

    // CNVD — 中国国家信息安全漏洞共享平台
    cnvd: {
      enabled: process.env.VULNDB_CNVD_ENABLED !== "0",
      apiUrl: process.env.VULNDB_CNVD_API_URL || "https://www.cnvd.org.cn/flaw/listJSON",
      timeoutMs: 30000,
    },

    // CNNVD — 中国国家信息安全漏洞库
    cnnvd: {
      enabled: process.env.VULNDB_CNNVD_ENABLED !== "0",
      apiUrl: process.env.VULNDB_CNNVD_API_URL || "https://www.cnnvd.org.cn/web/data/listJSON",
      timeoutMs: 30000,
    },

    // GitHub Security Advisory — GitHub 安全公告
    ghsa: {
      enabled: process.env.VULNDB_GHSA_ENABLED !== "0",
      apiUrl: process.env.VULNDB_GHSA_API_URL || "https://api.github.com/advisories",
      token: process.env.GITHUB_TOKEN || "", // 可选，提高速率限制
      timeoutMs: 30000,
    },

    // Vulncheck NVD++ — 威胁情报增强漏洞库
    vulncheck: {
      enabled: process.env.VULNDB_VULNCHECK_ENABLED !== "0",
      apiUrl: process.env.VULNDB_VULNCHECK_API_URL || "https://api.vulncheck.com/v3/nvd",
      apiKey: process.env.VULNDB_VULNCHECK_API_KEY || "",
      timeoutMs: 30000,
    },

    // Exploit-DB — 公开漏洞利用代码库
    exploitdb: {
      enabled: process.env.VULNDB_EXPLOITDB_ENABLED !== "0",
      apiUrl: process.env.VULNDB_EXPLOITDB_API_URL || "https://www.exploit-db.com/search",
      timeoutMs: 30000,
    },

    // Seebug — 中文 PoC 漏洞平台
    seebug: {
      enabled: process.env.VULNDB_SEEBUG_ENABLED !== "0",
      apiUrl: process.env.VULNDB_SEEBUG_API_URL || "https://www.seebug.org/api/list",
      timeoutMs: 30000,
    },

    // ── 以下为 6 个 AI 安全漏洞库 ──

    // OWASP LLM Top 10 — AI 安全分类标准
    owasp_llm: {
      enabled: process.env.VULNDB_OWASP_LLM_ENABLED !== "0",
      apiUrl: process.env.VULNDB_OWASP_LLM_URL || "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    },

    // MITRE ATLAS — AI 攻击战术库
    atlas: {
      enabled: process.env.VULNDB_ATLAS_ENABLED !== "0",
      apiUrl: process.env.VULNDB_ATLAS_URL || "https://atlas.mitre.org/",
    },

    // PurpleLlama — Meta AI 安全评估规则
    purplellama: {
      enabled: process.env.VULNDB_PURPLELLAMA_ENABLED !== "0",
      apiUrl: process.env.VULNDB_PURPLELLAMA_URL || "https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/",
    },

    // AIVD — AI 漏洞数据库
    aivd: {
      enabled: process.env.VULNDB_AIVD_ENABLED !== "0",
      apiUrl: process.env.VULNDB_AIVD_URL || "https://aivd.org/api/",
    },

    // Garak — LLM 漏洞扫描基准
    garak: {
      enabled: process.env.VULNDB_GARAK_ENABLED !== "0",
      apiUrl: process.env.VULNDB_GARAK_URL || "https://raw.githubusercontent.com/leondz/garak/main/",
    },

    // AI-TVDs — 中文 AI 安全漏洞库
    ai_tvds: {
      enabled: process.env.VULNDB_AI_TVDS_ENABLED !== "0",
      apiUrl: process.env.VULNDB_AI_TVDS_URL || "https://ai-tvds.org/api/",
    },
  },
};

module.exports = config;
