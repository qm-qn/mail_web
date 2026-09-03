import { createHmac } from 'node:crypto';

export function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input || '').toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  if (!clean) throw new Error('TOTP secret is empty');

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const ch of clean) {
    const index = alphabet.indexOf(ch);
    if (index < 0) throw new Error('TOTP secret is not valid Base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
      value = bits ? value & ((1 << bits) - 1) : 0;
    }
  }

  if (!bytes.length) throw new Error('TOTP secret is too short');
  return Buffer.from(bytes);
}

export function hotp(key, counter, digits = 6) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter), 0);
  const digest = createHmac('sha1', key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  return String(binary % (10 ** digits)).padStart(digits, '0');
}

export function totp(secret, { period = 30, digits = 6, nowMs = Date.now() } = {}) {
  const nowSec = Math.floor(nowMs / 1000);
  const counter = Math.floor(nowSec / period);
  return {
    code: hotp(base32Decode(secret), counter, digits),
    period,
    digits,
    expires_at: (counter + 1) * period * 1000,
    server_time: nowMs
  };
}
