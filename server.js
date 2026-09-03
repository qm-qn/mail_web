#!/usr/bin/env node
import http from 'node:http';
import { createHmac } from 'node:crypto';

function toPositiveInt(v, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) return fallback;
  return n;
}

const CONFIG = {
  secret: String(process.env.TOTP_SECRET || '').trim(),
  period: toPositiveInt(process.env.TOTP_PERIOD || 30, 30),
  digits: (() => {
    const d = toPositiveInt(process.env.TOTP_DIGITS || 6, 6);
    return Math.min(10, Math.max(6, d));
  })(),
  label: process.env.TOTP_LABEL || 'TOTP',
  host: process.env.HOST || '0.0.0.0',
  port: toPositiveInt(process.env.PORT || 3000, 3000),
  allowOrigin: process.env.ALLOW_ORIGIN || '*' // 先按你的要求放宽，先能跑
};

if (!CONFIG.secret || CONFIG.secret.length < 8) {
  throw new Error('TOTP_SECRET missing or too short');
}

function writeJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', CONFIG.allowOrigin);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.end(body);
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input || '').toUpperCase().replace(/=+/g, '').replace(/\s+/g, '');
  let bits = '';
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function hashDigest(key, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter), 0);
  return createHmac('sha1', key).update(msg).digest();
}

function hotp(key, counter, digits = 6) {
  const h = hashDigest(key, counter);
  const offset = h[h.length - 1] & 0x0f;
  const binary =
    ((h[offset] & 0x7f) << 24) |
    ((h[offset + 1] & 0xff) << 16) |
    ((h[offset + 2] & 0xff) << 8) |
    (h[offset + 3] & 0xff);

  const mod = 10 ** digits;
  return String(binary % mod).padStart(digits, '0');
}

function totp(secret, period = 30, digits = 6) {
  const key = base32Decode(secret);
  const nowSec = Math.floor(Date.now() / 1000);
  const counter = Math.floor(nowSec / period);
  const code = hotp(key, counter, digits);
  return {
    code,
    period,
    digits,
    expires_at: (counter + 1) * period * 1000,
    server_time: nowSec * 1000
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const pathname = url.pathname.replace(/\/+$/, '');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    res.setHeader('Access-Control-Allow-Origin', CONFIG.allowOrigin);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    return res.end('');
  }

  if (pathname === '/health') {
    return writeJson(res, 200, {
      ok: true,
      service: 'totp-server',
      period: CONFIG.period,
      digits: CONFIG.digits,
      label: CONFIG.label
    });
  }

  if (pathname !== '/totp') {
    return writeJson(res, 404, { ok: false, error: 'not found' });
  }

  if (req.method !== 'POST') {
    return writeJson(res, 405, { ok: false, error: 'method not allowed' });
  }

  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 2048) {
      writeJson(res, 413, { ok: false, error: 'payload too large' });
      req.destroy();
    }
  });

  req.on('end', () => {
    try {
      const payload = body ? JSON.parse(body) : {};
      if (payload && String(payload.action || '').toLowerCase() !== 'code') {
        return writeJson(res, 400, { ok: false, error: 'invalid action' });
      }

      const result = totp(CONFIG.secret, CONFIG.period, CONFIG.digits);
      return writeJson(res, 200, {
        ok: true,
        code: result.code,
        expires_at: result.expires_at,
        account: CONFIG.label,
        period: result.period,
        digits: result.digits,
        server_time: result.server_time
      });
    } catch (err) {
      if (err instanceof SyntaxError) {
        return writeJson(res, 400, { ok: false, error: 'invalid json' });
      }
      return writeJson(res, 500, { ok: false, error: 'server error' });
    }
  });
});

server.listen(CONFIG.port, CONFIG.host, () => {
  console.log(`TOTP server running at http://${CONFIG.host}:${CONFIG.port}/totp`);
  console.log(`Period=${CONFIG.period}, Digits=${CONFIG.digits}, Label=${CONFIG.label}`);
});
