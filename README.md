# 极简短链接生成源码

本系统基于 EdgeOne Pages / Cloudflare Pages + KV Storage 搭建，无需服务器和数据库，开箱即用。

🔗 **演示地址：** [https://i.l42.cn](https://i.l42.cn)

🌐 **博主博客：** [https://www.l42.cn](https://www.l42.cn)

🎬 **部署视频：** [点击观看部署视频](https://www.bilibili.com/video/BV1cpX9BQEAx/?share_source=copy_web&vd_source=8e545f5a82280a573a313547eae8ee24)

## 功能说明

- 防封与防抓取：自动识别微信、QQ 等内置浏览器环境，动态渲染防封引导遮罩，隐藏真实跳转信息。
- 智能自动清理：支持按天数自动清理长期未访问短链，并可为重要链接设置免清理。
- OTP 二次验证：后台支持 TOTP 动态验证码。
- 人工审核流：可开启生成审核，新提交短链进入待审核队列。
- 数据与链路管理：支持自定义短链、跳转统计、单条或批量删除、公告板管理。

## 目录说明

- `edge-functions/`：EdgeOne Pages 使用
- `functions/`：Cloudflare Pages 使用
- `public/`：Cloudflare Pages 静态输出目录

## EdgeOne Pages 部署

1. 导入 Git 仓库。
2. 使用自动识别到的构建配置即可；如果没有自动带出，可直接使用：
   - 框架预设：按控制台自动识别，或保持默认，如果没有自动识别选择'Other"
   - 根目录：`./`
   - 输出目录：`./`
   - 构建命令：留空
   - 安装命令：留空
3. 绑定 KV，变量名必须是 `duanlianjie`。
4. 部署完成后首次访问站点，按页面提示初始化后台路径、管理员账号和密码。

## Cloudflare Pages 部署

1. 进入 Workers & Pages，选择 Pages，连接 Git 仓库。
2. 构建设置按下面填写：
   - 框架预设：`无`
   - 构建命令：留空；如果控制台要求必填，填写 `exit 0`
   - 构建输出目录：`public`
   - 根目录：留空或 `./`
3. 在项目设置中绑定 KV，变量名必须是 `duanlianjie`。
4. 部署完成后首次访问站点，按页面提示初始化后台路径、管理员账号和密码。

## 说明

- 这份仓库已经同时包含 EdgeOne Pages 和 Cloudflare Pages 所需目录。
- EdgeOne Pages 读取 `edge-functions/`。
- Cloudflare Pages 读取根目录 `functions/`，静态输出目录使用 `public/`。
- 两个平台功能、页面、后台界面保持一致。