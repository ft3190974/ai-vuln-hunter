// agents/java-decompiler.js — Java 二进制反编译适配器
//
// 把 .jar/.class 反编译成 .java 源码，复用现有 code-slicer + llm-hunter 流程。
//
// 工具优先级：
//   1. CFR（java -jar cfr.jar）—— 最准确，需要 Java 运行时
//   2. mock —— 无 Java 时返回构造的示例反编译代码（让流程能跑通）
//
// 环境变量：
//   JAVA_BIN     java 可执行路径（默认 java）
//   CFR_JAR      cfr.jar 路径（必须下载 CFR）
//
// CFR 下载：https://github.com/leibnitz27/cfr/releases

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

let _javaAvailable = null;

/**
 * 检测 Java 是否可用（缓存结果）
 */
function isJavaAvailable() {
  if (_javaAvailable !== null) return _javaAvailable;
  try {
    execFileSync(process.env.JAVA_BIN || "java", ["-version"], {
      stdio: "pipe", timeout: 5000,
    });
    _javaAvailable = true;
  } catch {
    // java -version 输出到 stderr，exit code 0 也算成功
    _javaAvailable = false;
  }
  return _javaAvailable;
}

/**
 * 检测 CFR 是否配置
 */
function isCfrConfigured() {
  return !!process.env.CFR_JAR && fs.existsSync(process.env.CFR_JAR);
}

/**
 * 反编译入口
 * @param {string} inputPath  .jar 或 .class 路径
 * @returns {{files: Array<{file, content}>, decompiled: boolean, tool: string}}
 */
function decompile(inputPath) {
  // 优先用 CFR（需文件存在）
  if (isJavaAvailable() && isCfrConfigured()) {
    if (!fs.existsSync(inputPath)) {
      throw new Error(`文件不存在: ${inputPath}`);
    }
    return decompileWithCfr(inputPath);
  }

  // 降级：mock 反编译（不要求文件存在——用于测试和演示）
  console.log("[java-decompiler] Java 或 CFR 不可用，使用 mock 反编译（返回构造的示例代码）");
  console.log("  配置真实反编译：安装 JRE + 下载 cfr.jar + 设置 CFR_JAR 环境变量");
  return mockDecompile(inputPath);
}

/**
 * 用 CFR 反编译
 */
function decompileWithCfr(inputPath) {
  const tmpDir = path.join(os.tmpdir(), `cfr_decompile_${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  const cfrJar = process.env.CFR_JAR;
  const javaBin = process.env.JAVA_BIN || "java";

  console.log(`[java-decompiler] 使用 CFR 反编译: ${inputPath} → ${tmpDir}`);
  execFileSync(javaBin, [
    "-jar", cfrJar,
    inputPath,
    "--outputdir", tmpDir,
    "--silent", "true",
  ], { stdio: "pipe", timeout: 60000 });

  // 收集反编译出的 .java 文件
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".java")) {
        files.push({ file: entry.name, content: fs.readFileSync(full, "utf-8") });
      }
    }
  };
  walk(tmpDir);

  // 清理临时目录
  try { fs.rmSync(tmpDir, { recursive: true }); } catch {}

  return { files, decompiled: true, tool: "cfr" };
}

/**
 * Mock 反编译（无 Java 时，返回构造的示例反编译代码）
 * 让流程能端到端跑通，验证"反编译 → 分析"链路
 */
function mockDecompile(inputPath) {
  const ext = path.extname(inputPath).toLowerCase();
  const baseName = path.basename(inputPath, ext);

  // 构造一个典型 Java 反序列化漏洞的反编译示例
  const mockFiles = [
    {
      file: "ObjectInputHandler.java",
      content: `import java.io.*;

public class ObjectInputHandler {
    // 模拟反编译：反序列化用户输入（典型 Java 反序列化漏洞）
    public Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();  // 反序列化漏洞
    }

    // SQL 注入
    public User login(String username) throws Exception {
        String sql = "SELECT * FROM users WHERE name='" + username + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next() ? new User(rs) : null;
    }
}`,
    },
    {
      file: "ConfigServlet.java",
      content: `import javax.servlet.*;
import javax.servlet.http.*;

public class ConfigServlet extends HttpServlet {
    // 越权
    public void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String id = req.getParameter("id");
        User u = userRepo.findById(Long.parseLong(id));  // IDOR
    }

    // 命令执行
    public String execCommand(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);  // 命令注入
        return new String(p.getInputStream().readAllBytes());
    }
}`,
    },
  ];

  return { files: mockFiles, decompiled: false, tool: "mock" };
}

module.exports = { decompile, isJavaAvailable, isCfrConfigured };
