# 极简短链接服务

本项目同时支持 EdgeOne Makers、Cloudflare Pages 和 Cloudflare Worker，包含短链生成、人工审核、目标地址编辑、链接管理、访问统计、自动清理、前台密码、微信与 QQ 引导、OTP、公告和备案信息管理。

## 平台目录

- `edge-functions/`：EdgeOne Makers Edge Functions
- `functions/`：Cloudflare Pages Functions
- `public/`：Cloudflare Pages 输出目录
- `worker.js`：Cloudflare Worker 入口

现有平台入口路径保持不变。`index.js`、动态 Catch-all 路由和 `_routes.json` 均保留。

## 后台页面

后台已经改为独立多页面结构：

- `/{后台路径}/basic`
- `/{后台路径}/links`
- `/{后台路径}/audit`
- `/{后台路径}/announcement`
- `/{后台路径}/filing`

访问原后台根路径会跳转到 `/{后台路径}/basic`。每个菜单返回独立完整 HTML，只读取和处理本页面的数据。链接管理的已通过列表支持编辑目标地址，保存后短码不变。

## EdgeOne Makers 部署

1. 导入仓库。
2. 使用以下构建配置：
   - 框架预设：`Other`
   - 根目录：`./`
   - 输出目录：`./`
   - 构建命令：留空
   - 安装命令：由 `edgeone.json` 固定为 `npm install`
   - Node.js：由 `edgeone.json` 固定为 `20.18.0`
3. 不创建也不绑定 KV。系统只使用名为 `duanlianjie` 的 Makers Blob，并对后台和短链数据执行强一致读取。
4. 首次访问站点，根据页面提示初始化后台路径、账号和密码。

EdgeOne Makers 使用 `@edgeone/pages-blob`，依赖版本已经锁定在 `package-lock.json`。名为 `duanlianjie` 的 Blob Store 在首次调用时自动创建，并在 Makers Functions 内自动鉴权，不需要配置 API Token。

## Cloudflare Pages 部署

1. 在 Workers & Pages 中创建 Pages 项目并连接仓库。
2. 使用以下构建配置：
   - 框架预设：无
   - 根目录：`./`
   - 构建命令：留空；控制台要求必填时使用 `exit 0`
   - 构建输出目录：`public`
3. 创建并绑定 Workers KV，变量名必须为 `duanlianjie`。
4. 生产环境和预览环境需要分别检查绑定。
5. 重新部署后首次访问站点完成初始化。

## Cloudflare Worker 部署

将 `worker.js` 作为 ES Module Worker 部署，并绑定 D1：

- D1 数据库名称：`duanlianjie`
- Worker 绑定变量名：`DB`

初始化 SQL：

```sql
CREATE TABLE IF NOT EXISTS system_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS links (
  short TEXT PRIMARY KEY,
  long_url TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  approved_at INTEGER,
  visits INTEGER NOT NULL DEFAULT 0,
  last_visited_at INTEGER NOT NULL,
  is_permanent INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_links_status ON links(status);
CREATE INDEX IF NOT EXISTS idx_links_created_at ON links(created_at);
CREATE INDEX IF NOT EXISTS idx_links_last_visited_at ON links(last_visited_at);

CREATE TABLE IF NOT EXISTS sessions (
  type TEXT NOT NULL,
  token TEXT NOT NULL,
  expire INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (type, token)
);

CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
```

## 可选自动清理

EdgeOne Makers 和 Cloudflare Pages 可以配置 `CLEANUP_TOKEN`，通过 `POST /api/internal/pending-cleanup` 触发待审核数据清理。Cloudflare Worker 的计划任务还可以配置：

- `EDGEONE_CLEANUP_URL`
- `PAGES_CLEANUP_URL`
- `CLEANUP_TOKEN`

## 缓存策略

动态 HTML、JSON、登录和操作响应均返回 `Cache-Control: no-store`。EdgeOne Makers 数据通过 Blob 强一致读取，避免旧 KV 边缘缓存导致后台需要重复刷新。
