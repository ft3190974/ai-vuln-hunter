// agents/danger-func-scanner.js — 二进制危险函数扫描
//
// 扫描二进制的符号表/字符串，找危险函数的使用：
//   strcpy/strcat/sprintf/gets → 缓冲区溢出风险
//   system/popen/exec          → 命令注入风险
//   memcpy/memset              → 长度可控时风险
//
// 基于 binary-loader 的 symbols 字段（从字符串表提取的函数名）。

// 危险函数清单（按类别）
const DANGER_FUNCTIONS = {
  buffer_overflow: {
    severity: "high",
    desc: "缓冲区溢出风险函数",
    funcs: ["strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "fscanf"],
  },
  bounded_buffer: {
    severity: "medium",
    desc: "有界缓冲区操作（仍可能误用）",
    funcs: ["strncpy", "strncat", "snprintf", "vsnprintf"],
  },
  command_exec: {
    severity: "critical",
    desc: "命令执行函数（命令注入风险）",
    funcs: ["system", "popen", "execve", "execvp", "execl", "execle", "execlp", "fork", "vfork"],
  },
  memory_op: {
    severity: "medium",
    desc: "内存操作函数（长度可控时风险）",
    funcs: ["memcpy", "memmove", "memset", "bcopy"],
  },
  format_string: {
    severity: "high",
    desc: "格式化输出函数（格式化字符串风险）",
    funcs: ["printf", "fprintf", "syslog", "snprintf"],
  },
  // 弱加密/随机
  crypto_weak: {
    severity: "high",
    desc: "弱加密/伪随机函数",
    funcs: ["rand", "srand", "crypt", "des_encrypt", "rc4"],
  },
};

/**
 * 扫描符号表找危险函数
 * @param {Array} symbols  binary-loader 的 symbols [{name, offset}]
 * @param {string} binaryPath
 * @returns {Array} 发现的危险函数使用 [{category, severity, func, offset, desc}]}
 */
function scan(symbols, binaryPath) {
  const findings = [];
  const found = new Set(); // 去重（同一函数只报一次）

  for (const sym of symbols) {
    for (const [category, info] of Object.entries(DANGER_FUNCTIONS)) {
      // 精确匹配 或 包含（符号可能有前缀如 __strcpy, _strcpy, __libc_strcpy）
      const matched = info.funcs.find((f) => {
        const s = sym.name.toLowerCase();
        return s === f || s.endsWith("_" + f) || s.endsWith("__" + f) || s.includes("__libc_" + f);
      });
      if (matched && !found.has(matched)) {
        found.add(matched);
        findings.push({
          category,
          severity: info.severity,
          func: matched,
          offset: sym.offset,
          desc: `${info.desc}: ${matched}()`,
          binary: binaryPath,
        });
      }
    }
  }
  return findings;
}

/**
 * 获取所有危险函数名（用于其他模块查询）
 */
function getAllDangerFuncs() {
  return Object.values(DANGER_FUNCTIONS).flatMap((c) => c.funcs);
}

module.exports = { scan, DANGER_FUNCTIONS, getAllDangerFuncs };
