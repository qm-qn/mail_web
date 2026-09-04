#!/usr/bin/env node
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { totp } from './totp.js';

const ROOT_DIR = dirname(fileURLToPath(import.meta.url));
const DEFAULT_EMAIL_ENDPOINTS = {
  'rubesubban@gmail.com': 'https://script.google.com/macros/s/AKfycbx7i4fZ34bzRT42XiXvO2vq4v8snfHwAtcSH0H-LUZPEUsmWF7TP7fxa9Ckmz80Qlw/exec',
  'bubber7789121@gmail.com': 'https://script.google.com/macros/s/AKfycbwLIlFuVHOXcqqMFlYS-yv--POhNibNBqTJgVFXjLWdbuUJ8TPc1xczFlyKzr_62nQL/exec'
};
const DEFAULT_TOTP_APPS_SCRIPT_URL = DEFAULT_EMAIL_ENDPOINTS['rubesubban@gmail.com'];

function positiveInt(value, fallback, min = 1, max = Number.MAX_SAFE_INTEGER) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) return fallback;
  return number;
}

function parseEmailEndpoints(raw) {
  if (!raw) return DEFAULT_EMAIL_ENDPOINTS;
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error();
    return Object.fromEntries(
      Object.entries(parsed)
        .map(([email, url]) => [String(email).trim().toLowerCase(), String(url).trim()])
        .filter(([email, url]) => email && /^https:\/\//i.test(url))
    );
  } catch {
    throw new Error('EMAIL_APPS_SCRIPT_MAP must be a JSON object of email-to-HTTPS-URL entries');
  }
}

const CONFIG = {
  secret: String(process.env.TOTP_SECRET || '').trim(),
  period: positiveInt(process.env.TOTP_PERIOD, 30),
  digits: positiveInt(process.env.TOTP_DIGITS, 6, 6, 10),
  label: process.env.TOTP_LABEL || 'TOTP',
  host: process.env.HOST || '0.0.0.0',
  port: positiveInt(process.env.PORT, 3000, 1, 65535),
  allowOrigin: process.env.ALLOW_ORIGIN || '*',
  gmailSecret: String(process.env.GMAIL_SHARED_SECRET || '').trim(),
  emailEndpoints: parseEmailEndpoints(process.env.EMAIL_APPS_SCRIPT_MAP),
  totpAppsScriptUrl: String(process.env.TOTP_APPS_SCRIPT_URL || DEFAULT_TOTP_APPS_SCRIPT_URL).trim(),
  totpAppsScriptSecret: String(process.env.TOTP_APPS_SCRIPT_SECRET || '').trim(),
  upstreamTimeoutMs: positiveInt(process.env.UPSTREAM_TIMEOUT_MS, 30000, 1000, 120000)
};

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', CONFIG.allowOrigin);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Vary', 'Origin');
}

function writeJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  setCors(res);
  res.end(JSON.stringify(payload));
}

async function readJson(req) {
  return await new Promise((resolve, reject) => {
    let body = '';
    let settled = false;
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      if (settled) return;
      body += chunk;
      if (body.length > 4096) {
        settled = true;
        reject(Object.assign(new Error('payload too large'), { status: 413 }));
      }
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(Object.assign(new Error('invalid json'), { status: 400 }));
      }
    });
    req.on('error', (error) => {
      if (!settled) reject(error);
    });
  });
}

async function callAppsScript(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    body: JSON.stringify(payload),
    redirect: 'follow',
    signal: AbortSignal.timeout(CONFIG.upstreamTimeoutMs)
  });
  if (!response.ok) throw new Error(`Apps Script HTTP ${response.status}`);
  const result = await response.json();
  if (!result || typeof result !== 'object') throw new Error('Apps Script returned invalid JSON');
  return result;
}

async function getEmailCode(email, windowSec) {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const endpoint = CONFIG.emailEndpoints[normalizedEmail];
  if (!endpoint) return { status: 404, body: { ok: false, error: '没有此邮箱' } };
  if (!CONFIG.gmailSecret) {
    return { status: 503, body: { ok: false, error: '后端未配置 GMAIL_SHARED_SECRET' } };
  }

  const verified = await callAppsScript(endpoint, {
    action: 'verify',
    secret: CONFIG.gmailSecret
  });
  if (!verified.ok || !verified.since_epoch) {
    return { status: 502, body: { ok: false, error: verified.error || '邮箱接口验证失败' } };
  }

  const checked = await callAppsScript(endpoint, {
    action: 'check',
    since_epoch: verified.since_epoch,
    window_sec: windowSec,
    secret: CONFIG.gmailSecret
  });
  if (!checked.ok) {
    return { status: 502, body: { ok: false, error: checked.error || '邮箱接口查询失败' } };
  }
  return { status: 200, body: checked };
}

async function getTotpCode() {
  if (CONFIG.secret) {
    return { ok: true, ...totp(CONFIG.secret, { period: CONFIG.period, digits: CONFIG.digits }), account: CONFIG.label };
  }
  if (!CONFIG.totpAppsScriptUrl) {
    throw Object.assign(new Error('后端未配置 TOTP_SECRET 或 TOTP_APPS_SCRIPT_URL'), { status: 503 });
  }

  const payload = { action: 'code' };
  if (CONFIG.totpAppsScriptSecret) payload.secret = CONFIG.totpAppsScriptSecret;
  const result = await callAppsScript(CONFIG.totpAppsScriptUrl, payload);
  if (!result.ok) throw Object.assign(new Error(result.error || 'TOTP Apps Script 请求失败'), { status: 502 });

  const expiresAt = Number(result.expires_at || 0);
  const serverTime = Number(result.server_time || result.generated_at || Date.now());
  return {
    ...result,
    expires_at: expiresAt && expiresAt < 1e12 ? expiresAt * 1000 : expiresAt,
    server_time: serverTime && serverTime < 1e12 ? serverTime * 1000 : serverTime
  };
}

async function serveStatic(pathname, res) {
  const files = {
    '/': ['index.html', 'text/html; charset=utf-8'],
    '/index.html': ['index.html', 'text/html; charset=utf-8'],
    '/style.css': ['style.css', 'text/css; charset=utf-8']
  };
  const target = files[pathname];
  if (!target) return false;
  const content = await readFile(join(ROOT_DIR, target[0]));
  res.statusCode = 200;
  res.setHeader('Content-Type', target[1]);
  res.setHeader('Cache-Control', 'no-cache');
  res.end(content);
  return true;
}

export function createServer() {
  return http.createServer(async (req, res) => {
    const requestUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = requestUrl.pathname.replace(/\/+$/, '') || '/';

    try {
      if (req.method === 'OPTIONS') {
        res.statusCode = 204;
        setCors(res);
        return res.end();
      }

      if (req.method === 'GET' && pathname === '/health') {
        return writeJson(res, 200, {
          ok: true,
          service: 'verification-code-server',
          totp_configured: Boolean(CONFIG.secret || CONFIG.totpAppsScriptUrl),
          totp_source: CONFIG.secret ? 'local' : 'apps-script',
          email_configured: Boolean(CONFIG.gmailSecret),
          email_accounts: Object.keys(CONFIG.emailEndpoints),
          period: CONFIG.period,
          digits: CONFIG.digits,
          label: CONFIG.label
        });
      }

      if (req.method === 'GET' && await serveStatic(pathname, res)) return;

      if (req.method !== 'POST') {
        return writeJson(res, 404, { ok: false, error: 'not found' });
      }

      const payload = await readJson(req);

      if (pathname === '/totp') {
        if (String(payload.action || '').toLowerCase() !== 'code') {
          return writeJson(res, 400, { ok: false, error: 'invalid action' });
        }
        return writeJson(res, 200, await getTotpCode());
      }

      if (pathname === '/email/code') {
        const windowSec = positiveInt(payload.window_sec, 120, 30, 600);
        const result = await getEmailCode(payload.email, windowSec);
        return writeJson(res, result.status, result.body);
      }

      return writeJson(res, 404, { ok: false, error: 'not found' });
    } catch (error) {
      const isTimeout = error && (error.name === 'TimeoutError' || error.name === 'AbortError');
      const status = error && error.status ? error.status : (isTimeout ? 504 : 500);
      const message = isTimeout ? '上游邮箱接口超时' : (error && error.message) || 'server error';
      return writeJson(res, status, { ok: false, error: message });
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  createServer().listen(CONFIG.port, CONFIG.host, () => {
    console.log(`Verification code server: http://${CONFIG.host}:${CONFIG.port}`);
    console.log(`TOTP=${CONFIG.secret ? 'local' : (CONFIG.totpAppsScriptUrl ? 'apps-script' : 'missing')}, Gmail=${CONFIG.gmailSecret ? 'configured' : 'missing'}`);
  });
}
