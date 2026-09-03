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

你可以直接改成你的 Linux 外网地址/HTTPS 地址，比如：

```js
const FALLBACK_APP_URL = 'https://totp.your-domain.com/totp';
```

也可以在浏览器地址中带 `?api=` 参数临时覆盖：

```
https://qm-qn.github.io/mail_web/?api=http://192.168.1.8:3000/totp
```

第一次使用后，页面会把地址缓存在 `localStorage`（`TOTP_API`）。
