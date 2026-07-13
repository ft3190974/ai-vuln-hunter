#!/bin/bash
# deploy.sh — Ubuntu 一键部署脚本
#
# 用法（在 Ubuntu 服务器上执行）：
#   curl -sL https://raw.githubusercontent.com/ft3190974/ai-vuln-hunter/main/deploy.sh | bash
#
# 或手动 clone 后执行：
#   git clone https://github.com/ft3190974/ai-vuln-hunter.git
#   cd ai-vuln-hunter
#   chmod +x deploy.sh
#   ./deploy.sh
#
# 部署完成后：
#   服务地址：http://服务器IP:3000
#   日志查看：pm2 logs ai-vuln-hunter
#   重启服务：pm2 restart ai-vuln-hunter
#   停止服务：pm2 stop ai-vuln-hunter

set -e

echo "================================================"
echo "  AI 漏洞挖掘应用 · Ubuntu 一键部署"
echo "================================================"

# ── 0. 检查环境 ──
echo ""
echo "[0/6] 检查环境..."

if ! command -v node &> /dev/null; then
  echo "  安装 Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

if ! command -v python3 &> /dev/null; then
  echo "  安装 Python 3..."
  sudo apt-get install -y python3 python3-pip
fi

if ! command -v git &> /dev/null; then
  echo "  安装 git..."
  sudo apt-get install -y git
fi

NODE_VERSION=$(node -v | cut -dv -f2 | cut -d. -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
  echo "  ❌ Node.js 版本过低（$(node -v)），需要 18+。请升级：curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs"
  exit 1
fi

echo "  ✓ Node.js $(node -v)"
echo "  ✓ Python $(python3 --version 2>&1)"
echo "  ✓ git $(git --version 2>&1)"

# ── 1. 克隆/更新代码 ──
echo ""
echo "[1/6] 获取代码..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -d "$SCRIPT_DIR/.git" ]; then
  echo "  已在项目目录，拉取最新代码..."
  cd "$SCRIPT_DIR"
  git fetch origin main
  git reset --hard origin/main
  echo "  ✓ 代码已更新到最新版"
else
  echo "  克隆项目..."
  git clone https://github.com/ft3190974/ai-vuln-hunter.git /opt/ai-vuln-hunter || true
  cd /opt/ai-vuln-hunter
fi
APP_DIR="$(pwd)"
echo "  ✓ 项目目录: $APP_DIR"

# ── 2. 安装 Python 依赖（schema 校验用）──
echo ""
echo "[2/6] 安装 Python 依赖..."
pip3 install jsonschema referencing 2>/dev/null || pip3 install --user jsonschema referencing 2>/dev/null || true
echo "  ✓ Python 依赖就绪"

# ── 3. 构建前端 ──
echo ""
echo "[3/6] 构建前端..."
cd web/frontend
npm install --silent 2>&1 | tail -1
npm run build 2>&1 | tail -3
cd ../..
echo "  ✓ 前端构建完成"

# ── 4. 安装后端依赖 ──
echo ""
echo "[4/6] 安装后端依赖..."
cd web/server
npm install --silent 2>&1 | tail -1
cd ../..
# orchestrator 也需要依赖（MCP SDK）
cd orchestrator
npm install --silent 2>&1 | tail -1 || true
cd ..
# mcp-server 需要依赖（ajv 校验 + MCP SDK）
cd mcp-server
npm install --silent 2>&1 | tail -1 || true
cd ..
echo "  ✓ 后端依赖就绪"

# ── 5. 安装 PM2（进程管理，保证服务不中断）──
echo ""
echo "[5/6] 配置进程管理..."
if ! command -v pm2 &> /dev/null; then
  echo "  安装 PM2..."
  sudo npm install -g pm2
fi

# 停止旧进程（如果有）
pm2 delete ai-vuln-hunter 2>/dev/null || true

# 启动服务
cd web/server
pm2 start app.js --name ai-vuln-hunter --env production
pm2 save
cd ../..

# 设置开机自启
pm2 startup 2>/dev/null || true

echo "  ✓ 服务已启动（PM2 管理）"

# ── 6. 完成 ──
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo ""
echo "================================================"
echo "  ✅ 部署完成！"
echo "================================================"
echo ""
echo "  访问地址:  http://$SERVER_IP:3000"
echo "  健康检查:  http://$SERVER_IP:3000/api/health"
echo ""
echo "  常用命令:"
echo "    查看日志:   pm2 logs ai-vuln-hunter"
echo "    重启服务:   pm2 restart ai-vuln-hunter"
echo "    停止服务:   pm2 stop ai-vuln-hunter"
echo "    状态查看:   pm2 status"
echo ""
echo "  防火墙（如果需要开放端口）:"
echo "    sudo ufw allow 3000/tcp"
echo ""
echo "  可选配置（在启动前设置环境变量）:"
echo "    export LLM_MODE=glm && export GLM_API_KEY=你的key  # 启用真实 GLM"
echo "    export AUTH_ENABLED=1 && export JWT_SECRET=你的密钥  # 启用认证"
echo ""
echo "  LLM 配置（推荐在 Web 界面 /settings 配置，支持两种协议）:"
echo "    • GLM Coding Plan (glm-5.2):"
echo "        provider = glm"
echo "        baseUrl  = https://open.bigmodel.cn/api/anthropic"
echo "        model    = glm-5.2  (走 Anthropic 协议)"
echo "    • GLM 按量付费 (glm-4-flash/glm-4-plus):"
echo "        provider = glm"
echo "        baseUrl  = https://open.bigmodel.cn/api/paas/v4"
echo "        model    = glm-4-flash  (走 OpenAI 协议)"
echo "    系统按 baseUrl 自动选择协议，无需手动指定。"
echo ""
