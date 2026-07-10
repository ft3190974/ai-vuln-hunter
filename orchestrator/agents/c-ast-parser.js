// agents/c-ast-parser.js — C/C++ 正则版 AST 解析器（零依赖）
//
// 不依赖 tree-sitter，用正则 + 大括号匹配提取 C/C++ 的结构信息：
//   - 函数定义（返回类型/函数名/参数/所在行/函数体）
//   - 函数调用（谁在哪个函数里调了谁）
//   - 资源操作（malloc/free/lock/unlock/fopen/fclose/new/delete）
//   - #include 关系（跨文件依赖）
//
// 局限：正则不如真 AST，处理复杂宏/模板/C++ 嵌套命名空间会出错。
// 但对函数级分析够用。装了 tree-sitter 可切换到 AST 版（c-ast-parser-treesitter.js）。

const fs = require("fs");
const path = require("path");

// 资源操作模式（acquire = 获取，release = 释放）
const RESOURCE_PATTERNS = {
  memory: {
    acquire: [/\b(malloc|calloc|realloc|alloca)\s*\(/g, /\b(new)\s+\w+/g],
    release: [/\b(free)\s*\(/g, /\b(delete)\s+\w+/g, /\b(delete)\s*\[\s*\]\s*\w+/g],
  },
  lock: {
    acquire: [/\b(pthread_mutex_lock|pthread_spin_lock|pthread_rwlock_wrlock|EnterCriticalSection)\s*\(/g],
    release: [/\b(pthread_mutex_unlock|pthread_spin_unlock|pthread_rwlock_unlock|LeaveCriticalSection)\s*\(/g],
  },
  file: {
    acquire: [/\b(fopen|open|fdopen|freopen)\s*\(/g],
    release: [/\b(fclose|close)\s*\(/g],
  },
};

// 危险函数（用于 danger-func-scanner 复用）
const DANGER_FUNCS = [
  "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf", "fscanf",
  "strncpy", "strncat", "snprintf", "vsnprintf",  // 有限版本（仍可能误用）
  "system", "popen", "execve", "execvp", "execl",
  "memcpy", "memmove", "memset",  // 长度可控时有风险
];

/**
 * 解析单个 C/C++ 源文件
 * @param {string} filePath
 * @param {string} content
 * @returns {{functions, calls, resources, includes}}
 */
function parseFile(filePath, content) {
  const lines = content.split("\n");
  const functions = [];
  const calls = [];
  const resources = [];
  const includes = [];

  // 1. 提取 #include
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*#\s*include\s*[<"]([^>"]+)[>"]/);
    if (m) includes.push({ file: m[1], line: i + 1 });
  }

  // 2. 提取函数定义（用大括号匹配找函数体边界）
  const funcDefs = findFunctionDefinitions(lines);
  for (const fd of funcDefs) {
    const body = lines.slice(fd.bodyStart, fd.bodyEnd + 1).join("\n");
    functions.push({
      name: fd.name,
      file: filePath,
      line: fd.line,
      signature: fd.signature,
      returnType: fd.returnType,
      params: fd.params,
      bodyStart: fd.bodyStart + 1, // 1-based
      bodyEnd: fd.bodyEnd + 1,
      body,
    });

    // 3. 在函数体内找调用
    const funcCalls = findCalls(body, fd.name);
    for (const c of funcCalls) {
      calls.push({
        caller: fd.name,
        callee: c.name,
        callerFile: filePath,
        line: fd.bodyStart + c.line, // 相对 bodyStart 的行号
        args: c.args,
      });
    }

    // 4. 在函数体内找资源操作
    const resOps = findResources(body, fd.bodyStart);
    for (const r of resOps) {
      resources.push({ ...r, function: fd.name, file: filePath });
    }
  }

  return { functions, calls, resources, includes };
}

/**
 * 找函数定义（正则 + 大括号匹配）
 * 简化策略：找形如 `ret_type name(params) {` 的行，然后用大括号匹配找函数体结束
 */
function findFunctionDefinitions(lines) {
  const defs = [];
  // C/C++ 函数定义正则：返回类型 + 函数名 + (参数) + {
  // 排除 control 语句（if/for/while/switch）
  const controlKw = new Set(["if", "for", "while", "switch", "return", "sizeof", "else"]);
  const funcRe = /^(\s*)(?:static\s+|inline\s+|extern\s+)*([\w\s\*:&<>]+?)\s+(\*?\s*\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:throw\s*\([^)]*\)\s*)?\{/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // 跳过预处理/注释行
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

    const m = line.match(funcRe);
    if (!m) continue;

    const name = m[3].replace(/[\*\s]/g, "");
    if (controlKw.has(name)) continue;
    if (!/^[a-zA-Z_]\w*$/.test(name)) continue;

    // 找函数体边界（大括号匹配，从 { 开始）
    const braceIdx = line.indexOf("{", line.indexOf(")"));
    if (braceIdx === -1) continue;
    const bodyEnd = findMatchingBrace(lines, i, braceIdx);
    if (bodyEnd === -1) continue;

    defs.push({
      name,
      line: i + 1,
      signature: `${m[2].trim()} ${name}(${m[4]})`,
      returnType: m[2].trim(),
      params: m[4].trim(),
      bodyStart: i, // { 所在行（0-based）
      bodyEnd,
    });
  }
  return defs;
}

/**
 * 从 startLine 的 startCol 开始，用大括号匹配找闭合 }
 * 返回闭合 } 所在的行号（0-based），找不到返回 -1
 */
function findMatchingBrace(lines, startLine, startCol) {
  let depth = 0;
  for (let i = startLine; i < lines.length; i++) {
    const start = i === startLine ? startCol : 0;
    for (let j = start; j < lines[i].length; j++) {
      const ch = lines[i][j];
      if (ch === "{") depth++;
      else if (ch === "}") {
        depth--;
        if (depth === 0) return i;
      }
    }
    // 限制函数体大小（避免匹配过远）
    if (i - startLine > 500) return -1;
  }
  return -1;
}

/**
 * 在函数体内找函数调用
 */
function findCalls(body, ownerFunc) {
  const calls = [];
  const lines = body.split("\n");
  // 简化：匹配 `ident(` 且 ident 不是控制关键字
  const callRe = /\b([a-zA-Z_]\w*)\s*\(/g;
  const controlKw = new Set(["if", "for", "while", "switch", "return", "sizeof", "else", "do", "catch"]);
  const seen = new Set();

  for (let i = 0; i < lines.length; i++) {
    let m;
    while ((m = callRe.exec(lines[i])) !== null) {
      const name = m[1];
      if (controlKw.has(name)) continue;
      if (name === ownerFunc) continue; // 递归调用暂记但这里跳过去重
      const key = name;
      if (seen.has(key)) continue;
      seen.add(key);
      calls.push({ name, line: i, args: "" });
    }
  }
  return calls;
}

/**
 * 在函数体内找资源操作
 * @param {string} body  函数体文本
 * @param {number} bodyStartLine  函数体起始行（0-based）
 */
function findResources(body, bodyStartLine) {
  const ops = [];
  const lines = body.split("\n");
  for (const [resType, { acquire, release }] of Object.entries(RESOURCE_PATTERNS)) {
    for (let i = 0; i < lines.length; i++) {
      // ★ 过滤注释行（// 或 /* */ 或行内注释部分）
      const lineContent = stripComment(lines[i]);
      if (!lineContent.trim()) continue;
      for (const re of acquire) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(lineContent)) !== null) {
          ops.push({ type: "acquire", resource: resType, func: m[1] || "new", line: bodyStartLine + i + 1, code: lines[i].trim() });
        }
      }
      for (const re of release) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(lineContent)) !== null) {
          ops.push({ type: "release", resource: resType, func: m[1] || "delete", line: bodyStartLine + i + 1, code: lines[i].trim() });
        }
      }
    }
  }
  return ops;
}

/**
 * 去除行内的注释部分（双斜杠 和 斜杠星 注释，简化版）
 */
function stripComment(line) {
  // 去 // 注释
  const slashIdx = line.indexOf("//");
  if (slashIdx !== -1) {
    // 检查是否在字符串内（简化：如果在 " 之后则保留）
    const beforeSlash = line.slice(0, slashIdx);
    const quoteCount = (beforeSlash.match(/"/g) || []).length;
    if (quoteCount % 2 === 0) return beforeSlash;
  }
  // 去 /* */ 行内注释（简化）
  return line.replace(/\/\*[^*]*\*\//g, "");
}

/**
 * 解析目录（递归找 .c/.h/.cpp/.cc/.hpp）
 */
function parseDirectory(dir, maxFiles = 100) {
  const result = { functions: [], calls: [], resources: [], includes: [] };
  const exts = new Set([".c", ".h", ".cpp", ".cc", ".hpp", ".cxx"]);
  let count = 0;
  const walk = (d) => {
    if (count >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (count >= maxFiles) return;
      if (["node_modules", ".git", "build", "target"].includes(e.name)) continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (exts.has(path.extname(e.name).toLowerCase())) {
        try {
          const content = fs.readFileSync(full, "utf-8");
          const r = parseFile(full, content);
          result.functions.push(...r.functions);
          result.calls.push(...r.calls);
          result.resources.push(...r.resources);
          result.includes.push(...r.includes);
          count++;
        } catch { /* 忽略 */ }
      }
    }
  };
  walk(dir);
  return result;
}

module.exports = { parseFile, parseDirectory, DANGER_FUNCS, RESOURCE_PATTERNS };
