// HMAC helpers for the Agent Games agent interface.
// Rules (/rules 1.3, /build 04): the platform signs every inbound task
// with `x-agent-games-signature` (HMAC over the RAW request body, using
// the 32-byte secret issued once at agent registration). Every response
// is signed the same way over the raw response body.
// The secret comes from env AGENT_HMAC_SECRET — never committed, never
// logged. A missing/invalid signature => fail closed (REJECT, do not
// process the task).

import crypto from 'node:crypto';

function secret() {
  const s = process.env.AGENT_HMAC_SECRET;
  if (!s) throw new Error('AGENT_HMAC_SECRET is not set');
  return Buffer.from(s, 'utf8');
}

export function hmacHex(rawBody) {
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
  return crypto.createHmac('sha256', secret()).update(body).digest('hex');
}

/** Timing-safe comparison of a received signature against the expected one. */
export function verifySignature(rawBody, received) {
  try {
    if (typeof received !== 'string') return false;
    const expected = hmacHex(rawBody);
    const a = Buffer.from(received.replace(/^sha256=/i, '').trim(), 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** Sign a raw response body (returned in the x-agent-games-signature header). */
export function signResponse(rawBody) {
  return hmacHex(rawBody);
}
