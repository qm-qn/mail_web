import test from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, totp } from '../totp.js';

const RFC_SHA1_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

test('generates the RFC 6238 SHA-1 test vector', () => {
  const result = totp(RFC_SHA1_SECRET, { period: 30, digits: 8, nowMs: 59000 });
  assert.equal(result.code, '94287082');
  assert.equal(result.expires_at, 60000);
});

test('generates a six-digit code with the same counter', () => {
  assert.equal(totp(RFC_SHA1_SECRET, { nowMs: 59000 }).code, '287082');
});

test('rejects invalid Base32 instead of silently changing the secret', () => {
  assert.throws(() => base32Decode('ABC!123'), /valid Base32/);
});
