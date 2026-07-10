// sandbox/index.js — 沙箱工厂
//
// 按 config.verify.mode 返回对应实现。上层只调 getSandbox()，不感知具体实现。
//
// mode 取值：
//   mock    使用 MockSandbox（零依赖，本地即跑）
//   docker  使用 DockerSandbox（需本机 Docker，自动探测，不可用则降级 mock）
//   auto    优先 docker，不可用降级 mock（默认）

const config = require("../config");
const { MockSandbox } = require("./mock-sandbox");
const { DockerSandbox } = require("./docker-adapter");

let cached = null;
let cachedMode = null;

async function getSandbox() {
  const want = config.verify.mode;
  if (cached && cachedMode === want) return cached;

  if (want === "mock") {
    cached = new MockSandbox();
    cachedMode = "mock";
    return cached;
  }

  // docker 或 auto：尝试 docker，不可用降级
  const docker = new DockerSandbox();
  const ok = await docker.available();
  if (ok) {
    cached = docker;
    cachedMode = "docker";
  } else {
    // 降级
    cached = new MockSandbox();
    cachedMode = "mock-fallback";
  }
  return cached;
}

/** 同步获取当前模式（不触发 docker 探测） */
function currentMode() {
  return cachedMode || config.verify.mode;
}

function reset() {
  cached = null;
  cachedMode = null;
}

module.exports = { getSandbox, currentMode, reset };
