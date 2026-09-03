/**
 * 极简单账号 TOTP 接口（GitHub Pages -> Apps Script）
 * 前端固定请求 POST JSON: { action: "code" }
 */

const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;

function doPost(e) {
  const payload = parseJson_(e);
  if (!payload || String(payload.action || '').toLowerCase() !== 'code') {
    return jsonOut_({ ok: false, error: 'invalid action' }, 400);
  }

  const props = PropertiesService.getScriptProperties();
  const secret = String(props.getProperty('TOTP_SECRET') || '').trim();
  if (!secret) {
    return jsonOut_({ ok: false, error: 'TOTP_SECRET not set' }, 500);
  }

  const period = parseInt(props.getProperty('TOTP_PERIOD') || DEFAULT_PERIOD, 10);
  const digits = parseInt(props.getProperty('TOTP_DIGITS') || DEFAULT_DIGITS, 10);
  const label = props.getProperty('TOTP_LABEL') || '';

  const periodSec = isFinite(period) && period > 0 ? period : DEFAULT_PERIOD;
  const digitCount = isFinite(digits) && digits >= 6 && digits <= 10 ? digits : DEFAULT_DIGITS;

  const nowSec = Math.floor(Date.now() / 1000);
  const counter = Math.floor(nowSec / periodSec);
  const code = generateTotp_(secret, counter, periodSec, digitCount);
  const expiresAt = (counter + 1) * periodSec * 1000;

  return jsonOut_({
    ok: true,
    code: code,
    expires_at: expiresAt,
    account: label,
    period: periodSec,
    digits: digitCount,
    server_time: nowSec * 1000
  }, 200);
}

function doGet(e) {
  return jsonOut_({ ok: true, service: 'totp-web', note: 'POST { action: "code" }' }, 200);
}

function generateTotp_(base32Secret, counter, digits) {
  const keyBytes = base32Decode_(base32Secret);
  const counterBytes = [];
  for (let i = 7; i >= 0; i--) {
    counterBytes.push((counter >>> (i * 8)) & 0xff);
  }

  const hmac = Utilities.computeHmacSha1Signature(counterBytes, keyBytes);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const mod = Math.pow(10, digits);
  const code = ('000000000' + (binary % mod)).slice(-digits);

  return code;
}

function base32Decode_(input) {
  const map = {
    A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7,
    I: 8, J: 9, K: 10, L: 11, M: 12, N: 13, O: 14, P: 15,
    Q: 16, R: 17, S: 18, T: 19, U: 20, V: 21, W: 22, X: 23,
    Y: 24, Z: 25, '2': 26, '3': 27, '4': 28, '5': 29, '6': 30, '7': 31
  };

  const raw = String(input || '').toUpperCase().replace(/=+/g, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];

  for (let i = 0; i < raw.length; i++) {
    const c = map[raw[i]];
    if (c === undefined) {
      continue;
    }
    value = (value << 5) | c;
    bits += 5;
    while (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Utilities.newBlob(String.fromCharCode.apply(null, out)).getBytes();
}

function parseJson_(e) {
  if (!e || !e.postData || !e.postData.contents) {
    return {};
  }
  try {
    return JSON.parse(e.postData.contents);
  } catch (_) {
    return {};
  }
}

function jsonOut_(obj, code) {
  const out = ContentService.createTextOutput(JSON.stringify(obj));
  out.setMimeType(ContentService.MimeType.JSON);
  return out;
}
