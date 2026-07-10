// agents/ghidra-adapter.js — Ghidra Headless 反编译适配器（可选）
//
// 调用 Ghidra 的 analyzeHeadless 批量反编译二进制为伪 C 代码。
// 没装 Ghidra 时返回空（binary-hunter 会跳过函数级分析，只做确定性扫描）。
//
// 环境变量：
//   GHIDRA_HOME    Ghidra 安装目录（含 support/analyzeHeadless）
//
// Ghidra 安装：https://ghidra-sre.org/

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

let _ghidraAvailable = null;

function isGhidraAvailable() {
  if (_ghidraAvailable !== null) return _ghidraAvailable;
  const home = process.env.GHIDRA_HOME;
  if (!home) { _ghidraAvailable = false; return false; }
  // Windows: analyzeHeadless.bat; Linux/Mac: analyzeHeadless
  const script = path.join(home, "support", process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless");
  _ghidraAvailable = fs.existsSync(script);
  return _ghidraAvailable;
}

/**
 * 用 Ghidra Headless 反编译
 * @param {string} binaryPath
 * @returns {{functions: Array<{name, code}>, decompiled: boolean, tool: string}}
 */
function decompileWithGhidra(binaryPath) {
  if (!isGhidraAvailable()) {
    return { functions: [], decompiled: false, tool: "none" };
  }

  const home = process.env.GHIDRA_HOME;
  const script = path.join(home, "support", process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless");
  const tmpProject = path.join(os.tmpdir(), `ghidra_proj_${Date.now()}`);
  const tmpOutput = path.join(os.tmpdir(), `ghidra_out_${Date.now()}`);
  fs.mkdirSync(tmpOutput, { recursive: true });

  // Ghidra 后处理脚本（导出反编译结果到文件）
  const postScript = path.join(tmpOutput, "DecompileAll.java");
  fs.writeFileSync(postScript, `
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class DecompileAll extends GhidraScript {
  @Override public void run() throws Exception {
    String outDir = "${tmpOutput.replace(/\\/g, "/")}";
    DecompInterface decomp = new DecompInterface();
    decomp.openProgram(currentProgram);
    FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
    while (funcs.hasNext()) {
      Function f = funcs.next();
      DecompileResults res = decomp.decompileFunction(f, 30, monitor);
      if (res.decompileCompleted()) {
        String name = f.getName();
        PrintWriter pw = new PrintWriter(outDir + "/" + name + ".c");
        pw.println(res.getDecompiledFunction().getC());
        pw.close();
      }
    }
    decomp.dispose();
  }
}
`);

  try {
    console.log(`[ghidra-adapter] 反编译: ${binaryPath}`);
    execFileSync(script, [
      tmpProject, "TmpProj",
      "-import", binaryPath,
      "-postScript", "DecompileAll.java",
      "-scriptPath", tmpOutput,
      "-deleteProject",
    ], { stdio: "pipe", timeout: 120000 });

    // 收集反编译结果
    const functions = [];
    for (const file of fs.readdirSync(tmpOutput)) {
      if (file.endsWith(".c") && file !== "DecompileAll.java") {
        const name = file.replace(/\.c$/, "");
        const code = fs.readFileSync(path.join(tmpOutput, file), "utf-8");
        functions.push({ name, code });
      }
    }
    return { functions, decompiled: true, tool: "ghidra" };
  } catch (e) {
    console.warn(`[ghidra-adapter] 反编译失败: ${e.message}`);
    return { functions: [], decompiled: false, tool: "error" };
  } finally {
    try { fs.rmSync(tmpProject, { recursive: true }); } catch {}
    try { fs.rmSync(tmpOutput, { recursive: true }); } catch {}
  }
}

module.exports = { decompileWithGhidra, isGhidraAvailable };
