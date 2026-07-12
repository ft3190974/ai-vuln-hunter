// agents/git-clone.js — Git 仓库拉取（clone 到临时目录）
//
// 输入 Git URL，clone 到临时目录后返回路径。
// 用于"开源模型项目"扫描：用户输入 Git 地址 → 自动 clone → 扫描。

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

let _tmpCounter = 0;

/**
 * Clone 一个 Git 仓库到临时目录
 * @param {string} gitUrl  https://github.com/xxx/yyy.git 或 git@github.com:xxx/yyy.git
 * @param {number} depth    clone 深度（默认 1 = 只拉最新，省带宽）
 * @returns {{path, repoName}}
 */
function cloneRepo(gitUrl, depth = 1) {
  // 从 URL 提取仓库名
  const repoName = gitUrl
    .replace(/\.git$/, "")
    .replace(/^.*\//, "")
    .replace(/^.*:/, "");

  const tmpDir = path.join(os.tmpdir(), `avh_repo_${Date.now()}_${_tmpCounter++}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  try {
    execSync(`git clone --depth ${depth} "${gitUrl}" "${tmpDir}"`, {
      stdio: "pipe",
      timeout: 120000, // 2 分钟超时
    });
    return { path: tmpDir, repoName };
  } catch (e) {
    // 清理
    try { fs.rmSync(tmpDir, { recursive: true }); } catch {}
    throw new Error(`Git clone 失败: ${e.message?.slice(0, 150) || "未知错误"}`);
  }
}

module.exports = { cloneRepo };
