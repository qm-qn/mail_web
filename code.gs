/**
 * Gmail 邮箱验证码 + TOTP 兼容后端。
 *
 * Script Properties:
 * - GMAIL_SHARED_SECRET：Node 后端代理邮箱查询时使用
 * - TOTP_SECRET：Base32 TOTP 密钥（可选，仅用于 action=code）
 * - TOTP_LABEL / TOTP_PERIOD / TOTP_DIGITS：可选
 */

const TARGET_FROM = ['otp@tm1.openai.com', 'noreply@tm.openai.com'];
const SUBJECT_PREFIXES = [
  'Your OpenAI code is',
  'Your authentication code',
  'Your temporary ChatGPT login code',
  '你的 ChatGPT 代码为'
];
const WINDOW_SEC_DEFAULT = 120;
const GMAIL_COARSE_RANGE = 'newer_than:10m';
const SEARCH_LIMIT = 20;
const DEFAULT_PERIOD = 30;
const DEFAULT_DIGITS = 6;

function doPost(e) {
  try {
    const payload = parseJson_(e);
    const action = String(payload.action || '').toLowerCase();

    if (action === 'code' || action === 'totp') {
      return jsonOut_(createTotpPayload_());
    }

    if (action === 'verify') {
      assertGmailSecret_(payload);
      return jsonOut_({ ok: true, since_epoch: Math.floor(Date.now() / 1000) });
    }

    if (action === 'check') {
      assertGmailSecret_(payload);
      const sinceEpoch = Number(payload.since_epoch || 0);
      if (!sinceEpoch || !isFinite(sinceEpoch)) {
        return jsonOut_({ ok: false, error: 'since_epoch is required' });
      }
      const requestedWindow = Number(payload.window_sec || WINDOW_SEC_DEFAULT);
      const windowSec = isFinite(requestedWindow)
        ? Math.min(600, Math.max(30, Math.floor(requestedWindow)))
        : WINDOW_SEC_DEFAULT;
      return jsonOut_(findCodeInWindow_(sinceEpoch, windowSec));
    }

    return jsonOut_({ ok: false, error: 'invalid action' });
  } catch (error) {
    return jsonOut_({ ok: false, error: String(error && error.message || error) });
  }
}

function doGet() {
  const props = PropertiesService.getScriptProperties();
  return jsonOut_({
    ok: true,
    service: 'gmail-and-totp',
    gmail_configured: Boolean(props.getProperty('GMAIL_SHARED_SECRET')),
    totp_configured: Boolean(props.getProperty('TOTP_SECRET'))
  });
}

function createTotpPayload_() {
  const props = PropertiesService.getScriptProperties();
  const secret = String(props.getProperty('TOTP_SECRET') || '').trim();
  if (!secret) return { ok: false, error: 'TOTP_SECRET not set' };

  const period = boundedInt_(props.getProperty('TOTP_PERIOD'), DEFAULT_PERIOD, 1, 3600);
  const digits = boundedInt_(props.getProperty('TOTP_DIGITS'), DEFAULT_DIGITS, 6, 10);
  const nowMs = Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  const counter = Math.floor(nowSec / period);

  return {
    ok: true,
    code: generateTotp_(secret, counter, digits),
    expires_at: (counter + 1) * period * 1000,
    account: props.getProperty('TOTP_LABEL') || 'TOTP',
    period: period,
    digits: digits,
    server_time: nowMs
  };
}

function generateTotp_(base32Secret, counter, digits) {
  const keyBytes = base32Decode_(base32Secret);
  const counterBytes = new Array(8).fill(0);
  let remaining = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }

  const signedCounter = counterBytes.map(toSignedByte_);
  const digest = Utilities.computeHmacSignature(
    Utilities.MacAlgorithm.HMAC_SHA_1,
    signedCounter,
    keyBytes
  );
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(binary % Math.pow(10, digits)).padStart(digits, '0');
}

function base32Decode_(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const raw = String(input || '').toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  if (!raw) throw new Error('TOTP secret is empty');

  let bits = 0;
  let value = 0;
  const output = [];
  for (let i = 0; i < raw.length; i++) {
    const index = alphabet.indexOf(raw[i]);
    if (index < 0) throw new Error('TOTP secret is not valid Base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
      value = bits ? value & ((1 << bits) - 1) : 0;
    }
  }
  if (!output.length) throw new Error('TOTP secret is too short');
  return output.map(toSignedByte_);
}

function toSignedByte_(value) {
  return value > 127 ? value - 256 : value;
}

function findCodeInWindow_(sinceEpoch, windowSec) {
  const startSec = sinceEpoch - windowSec;
  const endSec = sinceEpoch + windowSec;
  const fromPart = TARGET_FROM.length
    ? '(' + TARGET_FROM.map(function (address) {
        return 'from:"' + address.replace(/"/g, '\\"') + '"';
      }).join(' OR ') + ')'
    : '';
  const query = [GMAIL_COARSE_RANGE, fromPart].filter(Boolean).join(' ').trim();
  const threads = GmailApp.search(query || GMAIL_COARSE_RANGE, 0, SEARCH_LIMIT);
  let best = null;

  threads.forEach(function (thread) {
    thread.getMessages().forEach(function (message) {
      const receivedAt = Math.floor(message.getDate().getTime() / 1000);
      if (receivedAt < startSec || receivedAt > endSec) return;
      if (TARGET_FROM.length && !emailInList_(message.getFrom(), TARGET_FROM)) return;

      const subject = message.getSubject() || '';
      if (!hasAnyPrefix_(subject, SUBJECT_PREFIXES)) return;
      const code = extractCode_(subject, message.getPlainBody() || '', message.getBody() || '');
      if (!code) return;

      if (!best || receivedAt > best.received_at) {
        best = {
          id: message.getId(),
          subject: subject,
          received_at: receivedAt,
          extracted: code
        };
      }
    });
  });

  return best ? { ok: true, found: true, payload: best } : { ok: true, found: false };
}

function extractCode_(subject, plainBody, htmlBody) {
  const subjectCode = lastSixDigitsFromSubject_(subject);
  if (subjectCode) return subjectCode;

  const plainText = String(plainBody || '').replace(/\r/g, '');
  const htmlText = htmlToVisibleText_(htmlBody);
  return sixDigitsNearKeyword_(plainText) ||
    sixDigitsNearKeyword_(htmlText) ||
    firstStandaloneSixDigits_(plainText) ||
    firstStandaloneSixDigits_(htmlText);
}

function sixDigitsNearKeyword_(text) {
  const match = String(text || '').match(
    /(authentication code|verification code|login code|log-in code|your code|验证码|动态码|一次性密码|OTP)[^0-9]{0,80}([0-9]{6})/i
  );
  return match ? match[2] : null;
}

function firstStandaloneSixDigits_(text) {
  const match = String(text || '').match(/(^|[^0-9])([0-9]{6})(?![0-9])/);
  return match ? match[2] : null;
}

function lastSixDigitsFromSubject_(subject) {
  const digits = String(subject || '').replace(/\D+/g, '');
  return digits.length >= 6 ? digits.slice(-6) : null;
}

function htmlToVisibleText_(html) {
  return String(html || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function emailInList_(fromField, list) {
  const value = String(fromField || '').toLowerCase();
  return list.some(function (address) {
    const expected = String(address || '').toLowerCase();
    return value === expected || value.includes('<' + expected + '>');
  });
}

function hasAnyPrefix_(subject, prefixes) {
  const value = String(subject || '').trim().toLowerCase();
  return prefixes.some(function (prefix) {
    return value.startsWith(String(prefix || '').trim().toLowerCase());
  });
}

function assertGmailSecret_(payload) {
  const expected = PropertiesService.getScriptProperties().getProperty('GMAIL_SHARED_SECRET');
  if (!expected) throw new Error('GMAIL_SHARED_SECRET not set');
  if (!payload || payload.secret !== expected) throw new Error('Unauthorized');
}

function boundedInt_(value, fallback, min, max) {
  const number = Number(value);
  return isFinite(number) && Math.floor(number) === number && number >= min && number <= max
    ? number
    : fallback;
}

function parseJson_(e) {
  if (!e || !e.postData || !e.postData.contents) return {};
  try {
    return JSON.parse(e.postData.contents);
  } catch (_) {
    throw new Error('Invalid JSON payload');
  }
}

function jsonOut_(payload) {
  return ContentService.createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}

/** 在 Apps Script 编辑器中运行，验证 RFC 6238 SHA-1 标准向量。 */
function testTotpRfc6238_() {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const actual = generateTotp_(secret, Math.floor(59 / 30), 8);
  if (actual !== '94287082') throw new Error('TOTP test failed: ' + actual);
  return 'TOTP test passed';
}
