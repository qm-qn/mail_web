# 本机 TOTP 后端（单账号）

## 1) 启动服务

```bash
cd /home/yu_ziyang/Mail_web

TOTP_SECRET='<你的 Base32 秘钥>' \
TOTP_LABEL='chatgpt' \
TOTP_PERIOD=30 \
TOTP_DIGITS=6 \
PORT=3000 \
npm start
```

环境变量可选：
- `TOTP_PERIOD`：默认 30
- `TOTP_DIGITS`：默认 6
- `TOTP_LABEL`：展示名称
- `HOST`：默认 `0.0.0.0`
- `PORT`：默认 `3000`
- `ALLOW_ORIGIN`：CORS 白名单，默认 `*`

## 2) 本地自检

```bash
curl http://127.0.0.1:3000/health
curl -X POST http://127.0.0.1:3000/totp \
  -H 'Content-Type: application/json' \
  -d '{"action":"code"}'
```

返回示例：

```json
{ "ok": true, "code": "123456", "expires_at": 1725356400000, "account": "chatgpt", "period": 30, "digits": 6 }
```

## 3) 前端如何接上

`index.html` 中默认后端地址是：

- `http://127.0.0.1:3000/totp`

### 关键说明（你的报错原因）

GitHub Pages 页面是 HTTPS，浏览器会禁止它直接请求 `http://...` 接口。
因此在页面里**只能填 https 链接**，否则会持续显示“当前页面为 HTTPS，后端不能是 http”。

你应该填的是：

`https://你的域名或隧道域名/totp`

### 本地内网测试（非 HTTPS 页面）

如果你不是在 GitHub Pages 打开（例如在本机直接打开 `index.html`），填：

- `http://127.0.0.1:3000/totp`

### GitHub Pages 需要的 HTTPS 解决方式（推荐）

#### A. 先用临时 HTTPS 隧道（最快）

```bash
cd /home/yu_ziyang/Mail_web
npx localtunnel --port 3000
```

终端会输出形如 `https://xxxx.loca.lt` 的地址。

在页面里填：

- `https://xxxx.loca.lt/totp`

#### B. 生产推荐（固定 HTTPS 域名）

给你的 Linux 映射一个域名并做 HTTPS 反代（Nginx/Caddy/Cloudflare），例如：

- `https://totp.your-domain.com/totp`

也可以直接在浏览器地址中带 `api` 覆盖：

```
https://qm-qn.github.io/mail_web/?api=https://totp.your-domain.com/totp
```

第一次使用后，页面会把地址缓存在 `localStorage`（`TOTP_API`）。
