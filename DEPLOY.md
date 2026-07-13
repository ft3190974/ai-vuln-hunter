# 部署指南

## 方式 A：一键脚本部署（推荐）

在 Ubuntu 服务器上执行：

```bash
# 方式 1：直接下载执行（无需先 clone）
curl -sL https://raw.githubusercontent.com/ft3190974/ai-vuln-hunter/main/deploy.sh | bash

# 方式 2：先 clone 再执行
git clone https://github.com/ft3190974/ai-vuln-hunter.git
cd ai-vuln-hunter
chmod +x deploy.sh
./deploy.sh
```

部署完成后，访问 `http://服务器IP:3000`。

### 脚本做了什么
1. 检查/安装 Node.js 20 + Python 3 + git
2. 克隆（或更新）代码
3. 安装 Python 依赖（jsonschema）
4. 构建前端（npm run build）
5. 安装后端依赖
6. 确保 `data/` 目录存在 + 迁移旧版错位数据 + 初始化 settings.json
7. 用 PM2 启动服务（进程管理 + 开机自启）

### 服务管理

```bash
pm2 logs ai-vuln-hunter      # 查看日志
pm2 restart ai-vuln-hunter   # 重启
pm2 stop ai-vuln-hunter      # 停止
pm2 status                    # 状态
```

---

## 方式 B：Docker 部署

```bash
git clone https://github.com/ft3190974/ai-vuln-hunter.git
cd ai-vuln-hunter/web
docker compose up -d
# 访问 http://服务器IP:3000
```

含数据库版（Postgres + Neo4j）：
```bash
DB_MODE=postgres+neo4j docker compose --profile db up -d
```

---

## 方式 C：Nginx 反向代理（80 端口 + 域名）

默认服务跑在 3000 端口。如果想让同事通过 80 端口或域名访问：

```bash
sudo apt install nginx
sudo cp nginx.conf /etc/nginx/sites-available/ai-vuln-hunter
# 编辑 server_name 改成你的域名
sudo ln -s /etc/nginx/sites-available/ai-vuln-hunter /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

启用 HTTPS：
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## 可选配置

### LLM 配置（推荐用 Web 界面）

部署后访问 `http://服务器IP:3000/settings`，添加 LLM 配置。系统按 `baseUrl` 自动选择协议：

| 场景 | baseUrl | 模型 | 协议 |
|---|---|---|---|
| **GLM Coding Plan** | `https://open.bigmodel.cn/api/anthropic` | `glm-5.2` | Anthropic Messages |
| **GLM 按量付费** | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash` / `glm-4-plus` | OpenAI Chat |

也可用环境变量（启动前设置）：

```bash
# 启用真实 GLM（按量付费 API）
export LLM_MODE=glm
export GLM_API_KEY=你的智谱API Key

# 启用 JWT 认证
export AUTH_ENABLED=1
export JWT_SECRET=你的密钥

# 启用持久化（需先装 Postgres + Neo4j）
export DB_MODE=postgres+neo4j
export DATABASE_URL=postgres://user:pass@localhost:5432/ai_vuln_hunter
export NEO4J_URL=bolt://localhost:7687
```

用环境变量启动 PM2：
```bash
LLM_MODE=glm GLM_API_KEY=xxx pm2 start web/server/app.js --name ai-vuln-hunter
pm2 save
```

---

## 更新代码

```bash
cd /path/to/ai-vuln-hunter
git pull origin main
# 重新执行部署脚本（会自动构建前端、迁移数据、重启服务）
./deploy.sh
# 或手动：
# cd web/frontend && npm run build && cd ../..
# pm2 restart ai-vuln-hunter
```

升级后如果态势总览数据与实际任务不符（旧版 bug 遗留），去「任务管理」页点「🧹 清理残留数据」按钮即可同步。

---

## 防火墙

```bash
sudo ufw allow 3000/tcp     # 开放 3000 端口
sudo ufw allow 80/tcp       # 开放 80 端口（Nginx）
sudo ufw allow 443/tcp      # 开放 443 端口（HTTPS）
sudo ufw status
```

---

## 常见问题

**Q: 同事访问不了？**
- 检查防火墙：`sudo ufw status`，确保 3000 端口开放
- 检查云服务器安全组：在阿里云/腾讯云控制台开放 3000 端口
- 检查服务状态：`pm2 status`

**Q: 页面能打开但扫描没结果？**
- 默认用 Mock LLM（不需要 API key），扫描结果有限
- 启用真实 GLM 效果更好：去 `/settings` 页面配置，或在启动前 `export LLM_MODE=glm && export GLM_API_KEY=xxx`

**Q: 删除任务后态势总览数据没变？**
- 旧版有此问题（finding 的 scanId 未持久化）。升级到最新版后，去「任务管理」页点「🧹 清理残留数据」按钮即可清掉历史残留并同步态势数据。

**Q: GLM Coding Plan 的 glm-5.2 连不通？**
- Coding Plan 的 glm-5.2 走 Anthropic 协议，baseUrl 必须填 `https://open.bigmodel.cn/api/anthropic`（不是 paas/v4）。系统会按 baseUrl 自动选协议。
- 注意：Coding Plan 套餐额度只在官方支持的编程工具中可用，自建应用建议用按量付费 API（paas/v4 + glm-4-flash）。

**Q: 内存/磁盘不够？**
- 最低配置：1 核 CPU + 1GB 内存 + 5GB 磁盘
- 推荐：2 核 + 2GB 内存（跑 GLM 分析时更流畅）
