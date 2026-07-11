// agents/dependency-scanner.js — 依赖扫描器（已知漏洞匹配 / SCA）
//
// 扫描项目中的依赖文件，提取依赖名 + 版本，与漏洞库匹配已知 CVE。
// 这是"已知漏洞"的主要发现路径（和 LLM 自主挖掘互补）。
//
// 支持的依赖文件：
//   Java:    pom.xml（Maven）/ build.gradle（Gradle）
//   Node.js: package.json / package-lock.json
//   Python:  requirements.txt / Pipfile
//   Go:      go.mod
//   Rust:    Cargo.toml
//   PHP:     composer.json

const fs = require("fs");
const path = require("path");

/**
 * 扫描目录或文件，提取所有依赖
 * @param {string} targetPath  目录或文件路径
 * @returns {{packages: Array, files: Array}}
 */
function scanDependencies(targetPath) {
  const packages = [];
  const files = [];

  if (fs.existsSync(targetPath)) {
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      walkDir(targetPath, packages, files, 0);
    } else if (stat.isFile()) {
      const result = parseDependencyFile(targetPath);
      if (result) {
        packages.push(...result.packages);
        files.push({ file: targetPath, ecosystem: result.ecosystem, count: result.packages.length });
      }
    }
  }

  return { packages, files };
}

function walkDir(dir, packages, files, depth) {
  if (depth > 5) return;
  // 跳过这些目录
  const skipDirs = new Set(["node_modules", ".git", "dist", "build", "target", "vendor", "__pycache__", ".idea", ".vscode"]);

  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  for (const entry of entries) {
    if (skipDirs.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkDir(full, packages, files, depth + 1);
    } else {
      const result = parseDependencyFile(full);
      if (result && result.packages.length > 0) {
        packages.push(...result.packages);
        files.push({ file: full, ecosystem: result.ecosystem, count: result.packages.length });
      }
    }
  }
}

/**
 * 解析单个依赖文件
 */
function parseDependencyFile(filePath) {
  const basename = path.basename(filePath).toLowerCase();
  const content = safeRead(filePath);
  if (!content) return null;

  // Maven pom.xml
  if (basename === "pom.xml") {
    return parseMavenPom(content, filePath);
  }
  // Gradle
  if (basename.includes("build.gradle")) {
    return parseGradle(content, filePath);
  }
  // Node.js package.json
  if (basename === "package.json" || basename === "package-lock.json") {
    return parsePackageJson(content, filePath);
  }
  // Python requirements.txt
  if (basename === "requirements.txt" || basename === "pipfile") {
    return parseRequirements(content, filePath);
  }
  // Go go.mod
  if (basename === "go.mod") {
    return parseGoMod(content, filePath);
  }
  // Rust Cargo.toml
  if (basename === "cargo.toml") {
    return parseCargo(content, filePath);
  }
  // PHP composer.json
  if (basename === "composer.json" || basename === "composer.lock") {
    return parseComposer(content, filePath);
  }
  return null;
}

function safeRead(filePath) {
  try { return fs.readFileSync(filePath, "utf-8"); } catch { return null; }
}

// ── Maven pom.xml ──
function parseMavenPom(content, file) {
  const packages = [];
  // 提取 <groupId>:<artifactId> + <version>
  const depRe = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]+)<\/version>)?/g;
  let m;
  while ((m = depRe.exec(content)) !== null) {
    packages.push({
      name: `${m[1].trim()}:${m[2].trim()}`,
      version: m[3]?.trim() || "unknown",
      ecosystem: "maven",
      file,
    });
  }
  // Maven properties（${xxx.version}）也提取出来
  return { packages, ecosystem: "maven" };
}

// ── Gradle build.gradle ──
function parseGradle(content, file) {
  const packages = [];
  const re = /(?:implementation|api|compile|runtimeOnly|testImplementation)['"]([^'":\s]+):([^'":\s]+):([^'":\s]+)['"]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    packages.push({ name: `${m[1]}:${m[2]}`, version: m[3], ecosystem: "maven", file });
  }
  return { packages, ecosystem: "maven" };
}

// ── Node.js package.json ──
function parsePackageJson(content, file) {
  let pkg;
  try { pkg = JSON.parse(content); } catch { return null; }
  const packages = [];
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  for (const [name, version] of Object.entries(deps)) {
    packages.push({ name, version: version.replace(/[\^~>=<]/g, ""), ecosystem: "npm", file });
  }
  return { packages, ecosystem: "npm" };
}

// ── Python requirements.txt ──
function parseRequirements(content, file) {
  const packages = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const m = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*[=~<>!]+\s*([\d.]+)/);
    if (m) {
      packages.push({ name: m[1].toLowerCase(), version: m[2], ecosystem: "pypi", file });
    } else {
      // 只有包名没有版本
      const m2 = trimmed.match(/^([a-zA-Z0-9_.-]+)$/);
      if (m2) packages.push({ name: m2[1].toLowerCase(), version: "unknown", ecosystem: "pypi", file });
    }
  }
  return { packages, ecosystem: "pypi" };
}

// ── Go go.mod ──
function parseGoMod(content, file) {
  const packages = [];
  const re = /^\s*(?:require\s+)?([^\s]+)\s+(v[\d.]+)/gm;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (m[1] === "module" || m[1] === "go") continue;
    packages.push({ name: m[1], version: m[2], ecosystem: "go", file });
  }
  return { packages, ecosystem: "go" };
}

// ── Rust Cargo.toml ──
function parseCargo(content, file) {
  const packages = [];
  const re = /^([a-zA-Z0-9_-]+)\s*=\s*["']([\d.]+)["']/gm;
  let m;
  // 简化：匹配 name = "version" 在 [dependencies] 之后
  const depSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
  const text = depSection ? depSection[1] : content;
  while ((m = re.exec(text)) !== null) {
    packages.push({ name: m[1], version: m[2], ecosystem: "cargo", file });
  }
  return { packages, ecosystem: "cargo" };
}

// ── PHP composer.json ──
function parseComposer(content, file) {
  let pkg;
  try { pkg = JSON.parse(content); } catch { return null; }
  const packages = [];
  const deps = pkg.require || {};
  for (const [name, version] of Object.entries(deps)) {
    if (name.startsWith("php") || name.startsWith("ext-")) continue;
    packages.push({ name, version: String(version).replace(/[\^~>=<]/g, ""), ecosystem: "composer", file });
  }
  return { packages, ecosystem: "composer" };
}

module.exports = { scanDependencies };
