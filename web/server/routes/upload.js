// web/server/routes/upload.js — 文件上传路由
//
// POST /api/upload  上传源码包（.zip）或二进制文件
//   - .zip → 解压到临时目录，返回目录路径（sourceInput.path 用）
//   - .bin/.elf/.exe/.jar/.class → 保存文件，返回文件路径
//
// 返回 { path, type, filename, size }
//   type: "source_dir"（解压后的源码目录）/ "binary"（二进制文件）/ "jar"（Java 二进制）

const express = require("express");
const multer = require("multer");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");
const { pipeline } = require("stream/promises");
const unzipper = require("unzipper");

// ★ 用纯 ASCII 路径存上传文件（避免 Windows 中文用户名导致 PowerShell/tar 路径编码错乱）
// 优先用项目目录下的 tmp（纯 ASCII），兜底用 os.tmpdir()
function getAsciiTempDir() {
  // 尝试项目根目录的 tmp（路径纯 ASCII）
  const projectTmp = path.resolve(__dirname, "..", "..", "..", "tmp");
  try {
    fs.mkdirSync(projectTmp, { recursive: true });
    // 验证路径无中文（用 ascii 字符集检查）
    if (/^[\x20-\x7e]+$/.test(projectTmp)) return projectTmp;
  } catch {}
  // 兜底：C:\tmp（如果存在）
  const cTmp = "C:\\tmp";
  try {
    fs.mkdirSync(cTmp, { recursive: true });
    return cTmp;
  } catch {}
  return os.tmpdir();
}

const TMP_DIR = getAsciiTempDir();
const UPLOAD_DIR = path.join(TMP_DIR, "avh-uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`);
    },
  }),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const exts = [".zip", ".bin", ".elf", ".exe", ".so", ".dll", ".o", ".jar", ".class", ".img", ".fw", ".tar", ".gz",
      ".md", ".java", ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".c", ".h", ".cpp", ".cc", ".hpp", ".php", ".rb", ".rs", ".kt", ".swift", ".scala", ".lua", ".sh", ".json", ".yaml", ".yml", ".xml", ".txt", ".toml"];
    const ext = path.extname(file.originalname).toLowerCase();
    if (exts.includes(ext)) cb(null, true);
    else cb(new Error(`不支持的文件类型: ${ext}（支持 zip/tar/bin/elf/exe/jar/class）`));
  },
});

function uploadRoutes() {
  const router = express.Router();

  router.post("/upload", upload.single("file"), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "未上传文件" });
      }
      const originalName = req.file.originalname;
      const ext = path.extname(originalName).toLowerCase();
      const tmpPath = req.file.path;

      // .zip → 解压（纯 JS unzipper，不依赖 PowerShell/tar，避免编码问题）
      if (ext === ".zip") {
        const extractDir = path.join(TMP_DIR, `avh_src_${Date.now()}`);
        fs.mkdirSync(extractDir, { recursive: true });
        let extracted = false;
        try {
          // 用 unzipper.Extract（自动等待所有文件写入完成）
          await pipeline(
            fs.createReadStream(tmpPath),
            unzipper.Extract({ path: extractDir })
          );
          extracted = true;
        } catch (e) {
          console.log("[upload] unzipper 失败:", e.message?.slice(0, 100));
        }
        if (!extracted) throw new Error("解压失败");
        // 清理上传的临时文件
        try { fs.unlinkSync(tmpPath); } catch {}

        // 检查解压后是否多了一层目录
        const entries = fs.readdirSync(extractDir);
        let finalPath = extractDir;
        if (entries.length === 1) {
          const onlyPath = path.join(extractDir, entries[0]);
          if (fs.statSync(onlyPath).isDirectory()) {
            finalPath = onlyPath;
          }
        }

        const sourceCount = countSourceFiles(finalPath);
        return res.json({
          path: finalPath,
          type: "source_dir",
          filename: originalName,
          sourceFiles: sourceCount,
        });
      }

      // .tar/.gz → 解压
      if (ext === ".tar" || ext === ".gz") {
        const extractDir = path.join(TMP_DIR, `avh_src_${Date.now()}`);
        fs.mkdirSync(extractDir, { recursive: true });
        execSync(`tar -xf "${tmpPath}" -C "${extractDir}"`, { stdio: "pipe", timeout: 30000 });
        try { fs.unlinkSync(tmpPath); } catch {}
        const sourceCount = countSourceFiles(extractDir);
        return res.json({
          path: extractDir,
          type: "source_dir",
          filename: originalName,
          sourceFiles: sourceCount,
        });
      }

      // .jar/.class
      if (ext === ".jar" || ext === ".class") {
        const dest = path.join(TMP_DIR, `avh_${Date.now()}_${originalName}`);
        fs.renameSync(tmpPath, dest);
        return res.json({
          path: dest,
          type: "jar",
          filename: originalName,
          size: req.file.size,
        });
      }

      // 源码/Skill 文件（.md/.java/.py/.js 等）→ 作为源码处理
      const sourceExts = [".md", ".java", ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".c", ".h", ".cpp", ".cc", ".hpp", ".php", ".rb", ".rs", ".kt", ".swift", ".scala", ".lua", ".sh", ".json", ".yaml", ".yml", ".xml", ".txt", ".toml"];
      if (sourceExts.includes(ext)) {
        const dest = path.join(TMP_DIR, `avh_${Date.now()}_${originalName}`);
        fs.renameSync(tmpPath, dest);
        return res.json({
          path: dest,
          type: "source_file",
          filename: originalName,
          size: req.file.size,
        });
      }

      // 二进制文件（.bin/.elf/.exe 等）
      const dest = path.join(TMP_DIR, `avh_${Date.now()}_${originalName}`);
      fs.renameSync(tmpPath, dest);
      return res.json({
        path: dest,
        type: "binary",
        filename: originalName,
        size: req.file.size,
      });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  });

  return router;
}

/** 统计目录下的源码文件数 */
function countSourceFiles(dir) {
  const exts = new Set([".java", ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".c", ".h", ".cpp", ".cc", ".hpp", ".php", ".rb"]);
  let count = 0;
  const walk = (d) => {
    try {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (["node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__"].includes(e.name)) continue;
        const full = path.join(d, e.name);
        if (e.isDirectory()) walk(full);
        else if (exts.has(path.extname(e.name).toLowerCase())) count++;
      }
    } catch {}
  };
  walk(dir);
  return count;
}

module.exports = uploadRoutes;
