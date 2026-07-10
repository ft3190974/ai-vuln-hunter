# web/ — HTTP 服务 + React 前端（M + N + O 升级版）

> 本轮升级：N（存储工厂接入）/ O（JWT 完整认证 + 前端登录页）

## 1. 新增：JWT 认证（O）

### 后端（web/server/auth/）
| 文件 | 职责 |
|---|---|
| `auth/jwt.js` | 签发/验证 access(15min) + refresh(7d) token |
| `auth/users.js` | 用户存储（bcrypt 哈希，首个用户自动 admin） |
| `auth/middleware.js` | 认证中间件（带 token 解析真实用户；无 token 按 AUTH_ENABLED 决定放行/拒绝） |
| `routes/auth.js` | POST /register /login /refresh，GET /me |

### 认证 API
```
POST /api/auth/register  { username, password }  → 201 { user, accessToken, refreshToken }
POST /api/auth/login     { username, password }  → 200 { user, accessToken, refreshToken }
POST /api/auth/refresh   { refreshToken }        → 200 { accessToken, refreshToken }
GET  /api/auth/me        (Bearer token)          → 200 { user }
```

### 两种模式（向后兼容）
```bash
# 默认：免认证（AUTH_ENABLED 未设或 0）—— 现有测试不破坏
node app.js

# 强制认证
AUTH_ENABLED=1 JWT_SECRET=your-secret node app.js
# → 无 token 访问 /api/findings 返回 401
# → /api/health 和 /api/auth/* 仍免认证
```

关键设计：**默认模式下，带了有效 token 仍解析注入真实用户**（/me 等接口在两种模式下都正确）。

### 前端
- `pages/LoginPage.jsx`：登录/注册表单（切换模式）
- `api.js`：token 自动注入 Authorization 头 + 401 自动清 token 跳登录
- `App.jsx`：启动时探 health.authEnabled，启用且未登录则跳 /login；侧边栏显示用户名+登出按钮

## 2. N：存储工厂接入

`app.js` 的 `createApp()` 现在 async，启动时按 `DB_MODE` 创建存储实例注入 engine：
```js
const stores = await createStores(process.env.DB_MODE || "memory");
engine = new OrchestratorEngine({ stores });
```
默认内存（零依赖），DB 不可用自动降级。

## 3. 测试
```bash
cd web/server
node test-api.js     # 32/32（12 端点 + JWT 注册/登录/刷新/me）
node test-auth.js    # 8/8（AUTH_ENABLED=1 强制认证模式）
```

## 4. 环境变量（新增）
| 变量 | 默认 | 说明 |
|---|---|---|
| `AUTH_ENABLED` | 0 | 1=强制认证，0=免认证（向后兼容） |
| `JWT_SECRET` | （临时） | JWT 签名密钥，未设生成临时（仅开发） |
| `DB_MODE` | memory | memory / postgres+neo4j |
