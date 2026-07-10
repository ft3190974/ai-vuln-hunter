// agents/string-extractor.js — 二进制硬编码敏感信息提取
//
// 扫描二进制的字符串表，用模式匹配找：
//   - 密码/口令（password=, pwd=, secret=）
//   - 密钥（-----BEGIN, private key, API key）
//   - URL/IP（http://, https://, 内网 IP）
//   - 数据库连接串
//   - 默认凭据
//
// 这是二进制分析里准确率最高的（接近 100%），因为字符串是明文存储的。

// 敏感信息模式（正则）
const SENSITIVE_PATTERNS = [
  // 密码/口令
  { id: "password", severity: "high", pattern: /(?:password|passwd|pwd|pass|secret|token|apikey|api_key)\s*[=:]\s*['"]?([^\s'";,]{3,})/i, desc: "硬编码密码/口令" },
  { id: "password_str", severity: "high", pattern: /(?:password|passwd|pwd)\s*['"]?\s*[=:]\s*([^\s'";,]{4,})/i, desc: "密码字符串" },
  // 私钥/证书
  { id: "private_key", severity: "critical", pattern: /-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----/, desc: "硬编码私钥" },
  { id: "certificate", severity: "medium", pattern: /-----BEGIN\s+CERTIFICATE-----/, desc: "硬编码证书" },
  // URL（可能是 C2/回调/更新服务器）
  { id: "url", severity: "medium", pattern: /https?:\/\/[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}[^\s]*/i, desc: "硬编码 URL" },
  // 内网 IP
  { id: "internal_ip", severity: "low", pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/, desc: "内网 IP 地址" },
  // 数据库连接串
  { id: "db_conn", severity: "high", pattern: /(?:mysql|postgres|mongodb|redis|jdbc):\/\/[^\s]+/i, desc: "数据库连接串" },
  // AWS/云凭据
  { id: "aws_key", severity: "critical", pattern: /AKIA[0-9A-Z]{16}/, desc: "AWS Access Key" },
  { id: "jwt", severity: "high", pattern: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/, desc: "硬编码 JWT Token" },
  // 调试/后门口令特征
  { id: "backdoor", severity: "critical", pattern: /(?:admin|root|debug|test|backdoor|shell)\s*[=:]\s*['"]?([^\s'";,]{3,})/i, desc: "疑似后门/默认凭据" },
  // JWT 密钥
  { id: "jwt_secret", severity: "high", pattern: /(?:jwt[_-]?secret|signing[_-]?key)\s*[=:]\s*['"]?([^\s'";,]{8,})/i, desc: "硬编码 JWT 密钥" },
];

/**
 * 从字符串列表提取敏感信息
 * @param {Array} strings  binary-loader 的 strings 数组 [{value, offset}]
 * @param {string} binaryPath
 * @returns {Array} 发现的敏感信息 [{type, severity, value, offset, line, evidence, desc}]}
 */
function extract(strings, binaryPath) {
  const findings = [];
  const seen = new Set(); // 去重（同一字符串同一类型只报一次）

  for (const s of strings) {
    for (const p of SENSITIVE_PATTERNS) {
      const m = s.value.match(p.pattern);
      if (m) {
        const key = `${p.id}:${s.value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        // 提取敏感值（捕获组或整个字符串）
        const sensitiveValue = m[1] || s.value;
        // 脱敏（只显示前后 2 字符）
        const masked = maskValue(sensitiveValue);
        findings.push({
          type: p.id,
          severity: p.severity,
          value: masked,
          rawLength: sensitiveValue.length,
          offset: s.offset,
          evidence: s.value.length > 100 ? s.value.slice(0, 100) + "..." : s.value,
          desc: p.desc,
          binary: binaryPath,
        });
      }
    }
  }
  return findings;
}

/**
 * 脱敏：只显示前 2 + 后 2 字符
 */
function maskValue(value) {
  if (value.length <= 6) return "***";
  return value.slice(0, 2) + "*".repeat(Math.min(value.length - 4, 20)) + value.slice(-2);
}

module.exports = { extract, SENSITIVE_PATTERNS };
