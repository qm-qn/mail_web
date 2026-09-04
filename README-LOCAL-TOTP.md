# 验证码中心

GitHub Pages 前端现在直接连接 Google Apps Script，同时显示：

- TOTP 一次性验证码；
- Gmail 邮箱验证码。

正常使用不再需要启动本机 Node 服务，也不再需要 localtunnel。

## 在线链路

```text
GitHub Pages → Google Apps Script
```

前端已经配置以下 Apps Script：

- `rubesubban@gmail.com`：合并版 Gmail + TOTP 接口；
- `bubber7789121@gmail.com`：合并版 Gmail + TOTP 接口。

页面加载后会自动获取 TOTP，并可在验证码卡片中切换账号；邮箱验证码在输入 Gmail 地址并点击“查询邮箱码”后，通过 `verify → check` 流程查询，最长轮询一分钟。

## 本地查看页面

静态页面可以使用任意 HTTP 静态服务器预览，例如：

```bash
cd /home/yu_ziyang/Mail_web
python3 -m http.server 8080
```

然后打开：

```text
http://127.0.0.1:8080/
```

本地查看同样会直接访问 Apps Script，不需要运行 `npm start`。

## Apps Script 配置

合并版代码位于 [code.gs](./code.gs)，支持：

- `GET`：服务和配置状态；
- `POST {"action":"code"}`：生成 TOTP；
- `POST {"action":"verify","secret":"..."}`：验证邮箱并返回服务器时间；
- `POST {"action":"check",...}`：查询 Gmail 验证码。

脚本属性：

- `GMAIL_SHARED_SECRET`
- `TOTP_SECRET`
- `TOTP_LABEL`
- `TOTP_PERIOD`，默认 `30`
- `TOTP_DIGITS`，默认 `6`

更新 Apps Script 代码后，需要在“管理部署”中选择新版本并更新部署。

## 可选 Node 备用服务

[server.js](./server.js) 仍保留为备用代理，提供 `/health`、`/totp` 和 `/email/code`，但不参与 GitHub Pages 的正常运行。

如需备用代理：

```bash
GMAIL_SHARED_SECRET='<与 Apps Script 相同的值>' PORT=3000 npm start
```

## 验证

```bash
npm test
```

测试使用 RFC 6238 SHA-1 标准向量检查 Node 备用实现。
