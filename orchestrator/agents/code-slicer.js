// agents/code-slicer.js — 源代码切片器（不依赖 SAST）
//
// 直接读取源代码（文件/目录/字符串），按函数/方法切片，给 LLM 自主分析用。
// 这是 LLM 自主挖掘通道的入口——不需要任何工具先扫。
//
// 切片策略：
//   1. 按文件读源码
//   2. 用正则识别函数/方法边界（多语言通用：def/function/func/public/private 等）
//   3. 每个函数作为一个 slice，附文件名 + 行号 + 上下文
//
// 局限：基于正则的切片不如 AST 精确，但对 LLM 分析够用（LLM 能理解残缺代码）。
// 真实生产可换 tree-sitter，但为了零依赖先用正则。

const fs = require("fs");
const path = require("path");

// 各语言的函数定义正则
const FUNC_PATTERNS = {
  java: /^\s*(public|private|protected|static)?\s+\w+[<\w>,\s]*\s+(\w+)\s*\([^)]*\)\s*(\{|throws)/m,
  python: /^\s*(async\s+)?def\s+(\w+)\s*\(/m,
  javascript: /^\s*(async\s+)?(function\s+)?(\w+)\s*\([^)]*\)\s*\{/m,
  typescript: /^\s*(async\s+)?(public|private|protected)?\s*(static)?\s*(\w+)\s*\([^)]*\)\s*[:{]/m,
  go: /^\s*func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(/m,
  c: /^\s*[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{/m,
  cpp: /^\s*[\w\s\*:&<>]+\s+(\w+)\s*\([^)]*\)\s*[:{]/m,
  php: /^\s*(public|private|protected|static)?\s*function\s+(\w+)\s*\(/m,
  ruby: /^\s*def\s+(\w+)/m,
};

/**
 * 从字符串识别语言（按扩展名 + 内容特征）
 * 若用户已指定 language 直接用；否则按内容特征启发识别（多语言混合时按主语言）
 */
function detectLanguage(filePath, content) {
  const ext = path.extname(filePath).toLowerCase();
  const extMap = {
    ".java": "java", ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".php": "php", ".rb": "ruby",
  };
  if (extMap[ext]) return extMap[ext];

  // 无扩展名或 .txt：按内容特征识别
  const sample = (content || "").slice(0, 2000);
  if (/^\s*package\s+[\w.]+;/m.test(sample) || /public\s+(static\s+)?(class|void)\s/m.test(sample)) return "java";
  if (/^\s*(import|from)\s+\w/m.test(sample) && /def\s+\w+\s*\(/m.test(sample)) return "python";
  if (/^\s*package\s+\w+/m.test(sample) && /^func\s/m.test(sample)) return "go";
  if (/<\?php/.test(sample)) return "php";
  if (/^\s*def\s+\w+/m.test(sample)) return "python";
  if (/^\s*func\s+/m.test(sample)) return "go";
  if (/#include\s+[<"]/.test(sample)) return /class\s+\w+/.test(sample) ? "cpp" : "c";
  if (/function\s+\w+\s*\(/m.test(sample) || /const\s+\w+\s*=/.test(sample) || /=>\s* /.test(sample)) return "javascript";
  return "javascript"; // 兜底
}

/**
 * 按函数切片单个文件内容
 * @returns {Array<{functionName, code, startLine, endLine, language, file}>}
 */
function sliceFile(filePath, content) {
  const language = detectLanguage(filePath, content);
  const lines = content.split("\n");
  const slices = [];

  // 简化策略：找函数定义行，到下一个函数定义（或文件末尾）作为一个 slice
  const funcStarts = [];
  const pattern = FUNC_PATTERNS[language] || FUNC_PATTERNS.javascript;
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) {
      funcStarts.push(i);
    }
  }

  if (funcStarts.length === 0) {
    // 无函数定义：整个文件作为一个 slice（适合脚本类代码）
    if (content.trim().length > 0) {
      slices.push({
        functionName: "(top-level)",
        code: content,
        startLine: 1,
        endLine: lines.length,
        language,
        file: filePath,
      });
    }
    return slices;
  }

  for (let i = 0; i < funcStarts.length; i++) {
    const start = funcStarts[i];
    // 上下文：函数前 3 行（注释/注解）
    const ctxStart = Math.max(0, start - 3);
    // 结束：下一个函数前一行，或文件末尾
    const end = i + 1 < funcStarts.length ? funcStarts[i + 1] - 1 : lines.length - 1;
    // 函数名提取：取方法名捕获组（各语言 pattern 的命名组或第 2/3 捕获组）
    const match = lines[start].match(pattern);
    let funcName = `func_${i}`;
    if (match) {
      // 各 pattern 的捕获组结构不同，按优先级取：named > 倒数第 2 个非边界组 > 第 2 组
      // 简化：尝试常见位置（2/3），跳过纯边界字符
      for (const idx of [2, 3, 4, 1]) {
        const cand = match[idx];
        if (cand && /^[A-Za-z_]\w*$/.test(cand)) { funcName = cand; break; }
      }
    }

    const code = lines.slice(ctxStart, end + 1).join("\n");
    // 控制 slice 大小（超长函数截断，避免超出 LLM 上下文）
    const maxLines = 120;
    const trimmed = code.split("\n").slice(0, maxLines).join("\n");

    slices.push({
      functionName: funcName,
      code: trimmed,
      startLine: ctxStart + 1,
      endLine: end + 1,
      language,
      file: filePath,
    });
  }
  return slices;
}

/**
 * 切片入口：支持文件路径 / 目录 / 代码字符串
 * @param {object} input { path?, code?, language?, file?, maxFiles? }
 *   language 可选——不传则自动识别（多语言混合时每个文件独立识别）
 */
function sliceSource(input) {
  // 1. 直接传代码字符串
  if (input.code) {
    const file = input.file || "input.js";
    // 用户指定 language 则用，否则按内容识别
    const slices = sliceFile(file, input.code);
    if (input.language) {
      return slices.map((s) => ({ ...s, language: input.language }));
    }
    return slices;
  }

  // 2. 传文件路径
  if (input.path) {
    const resolved = path.resolve(input.path);
    if (!fs.existsSync(resolved)) {
      return [];
    }
    const stat = fs.statSync(resolved);
    if (stat.isFile()) {
      const content = fs.readFileSync(resolved, "utf-8");
      const slices = sliceFile(resolved, content);
      if (input.language) {
        return slices.map((s) => ({ ...s, language: input.language }));
      }
      return slices;
    }
    // 目录：递归找源码文件（每文件独立识别语言）
    if (stat.isDirectory()) {
      return walkDir(resolved, input.maxFiles || 50);
    }
  }
  return [];
}

function walkDir(dir, maxFiles) {
  // ★ 优先级排序：后端路由/控制器先分析，前端 JS 后分析
  const sourceExts = new Set([
    ".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".go",
    ".c", ".h", ".cpp", ".cc", ".hpp", ".php", ".rb",
  ]);
  const HIGH_PRIORITY_RE = /(app|main|server|views|routes|config|settings|__init__)\.(py|js|ts|java)$/i;
  const HIGH_PRIORITY_DIR = /controller|route|router|api|handler|middleware|service|model|view/i;
  const LOW_PRIORITY_DIR = /^(static|public|assets|templates|dist|build|frontend|client|node_modules)$/i;

  const highPriority = [], normalPriority = [], lowPriority = [];
  let fileCount = 0;

  const walk = (d, inLowDir) => {
    if (fileCount >= maxFiles * 3) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (fileCount >= maxFiles * 3) return;
      if (["node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__"].includes(entry.name)) continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) {
        const childLow = inLowDir || LOW_PRIORITY_DIR.test(entry.name);
        walk(full, childLow);
      } else if (sourceExts.has(path.extname(entry.name).toLowerCase())) {
        try {
          const content = fs.readFileSync(full, "utf-8");
          const fslices = sliceFile(full, content);
          fileCount++;
          const dirName = path.basename(path.dirname(full));
          if (HIGH_PRIORITY_RE.test(entry.name) || HIGH_PRIORITY_DIR.test(dirName) || HIGH_PRIORITY_DIR.test(full)) {
            highPriority.push(...fslices);
          } else if (inLowDir || /^(static|public|assets|templates|dist|build|frontend|client)$/i.test(dirName)) {
            lowPriority.push(...fslices);
          } else {
            normalPriority.push(...fslices);
          }
        } catch {}
      }
    }
  };
  walk(dir, false);
  // 合并：高优先级 > 普通 > 前端
  return [...highPriority, ...normalPriority, ...lowPriority].slice(0, maxFiles * 3);
}

module.exports = { sliceSource, sliceFile, detectLanguage };
