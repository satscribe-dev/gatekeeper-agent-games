// Proof Gatekeeper — Cloudflare Workers port.
// Agent Games (zkVerify) practice track. NOT a scored-round entry.
//
// This is a port of ../src/server.js to the Workers fetch-handler
// model. The decision path is IDENTICAL to the Node server:
//   1. HMAC-verify x-agent-games-signature over the RAW body
//      (AGENT_HMAC_SECRET binding; without it the worker answers in
//      clearly-flagged simulation mode, exactly like the Node server).
//   2. Parse envelope; require type agent-games.proof-gatekeeper.v1.
//   3. Idempotency: repeated task_id returns the cached response.
//   4. Optional on-chain block cross-check (best effort).
//   5. Decide (decision engine below — VERBATIM copy of
//      ../src/decision.js; do not edit the rules here, edit the
//      source and re-port).
//   6. On APPROVE, record proof_tx as seen (PROOF_REUSED guard).
//   7. Respond {decision, reason_code, proof_tx} signed with HMAC.
//
// Port differences vs ../src/server.js (mechanical only):
//   - Node `http` server -> `export default { fetch }` handler.
//   - `node:crypto` HMAC -> WebCrypto SubtleCrypto (async).
//   - `store.js` file snapshot -> in-memory only. LIMITATION: the
//     seen-proof set and the task_id cache live in module-scope
//     memory PER ISOLATE. A cold start, or a request landing on a
//     different isolate/colo, starts with an EMPTY registry. That
//     means PROOF_REUSED can miss across isolates and a replayed
//     task_id can be re-decided instead of served from cache.
//     Acceptable for practice (the platform's own scoring treats a
//     re-decision as just another decision); a scored deployment
//     needs durable shared storage (Workers KV / Durable Objects).
//   - `onchain.js` WebSocket JSON-RPC -> fetch POST
//     `eth_blockNumber` to the same host over HTTPS. The public RPC
//     was unreachable from the build sandbox (both WSS and HTTPS
//     timed out, 15 Nov 2026); the check stays best-effort with the
//     same circuit breaker (3 consecutive failures -> skip 5 min).
//     Decisions never depend on it.
//   - No snarkjs at runtime (decision path never needed it), no
//     Kurier client, no proof generation (blocked on the unverified
//     13-signal input mapping — see ../README.md gap 1).
//
// Deploy: python3 deploy_worker.py <account_id> gatekeeper-agent-games worker.mjs
//   (see ../README.md + workers/README.md). No secret is set at
//   deploy time; the worker runs in simulation mode until the real
//   secret is added (wrangler secret put AGENT_HMAC_SECRET).

const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';
const MAX_BODY = 1024 * 1024;

// NOTE on STARTED_AT: `Date.now()` at module top-level evaluates to 0
// in Workers isolates (the isolate clock starts at the first event),
// which made /health report uptime_s ≈ current epoch seconds. So the
// start time is captured lazily on the first request instead.
let STARTED_AT = 0;
function uptimeS() {
  if (!STARTED_AT) STARTED_AT = Date.now();
  return Math.floor((Date.now() - STARTED_AT) / 1000);
}

// ---------------------------------------------------------------------------
// Decision engine — VERBATIM port of ../src/decision.js (rules unchanged).
// Source of truth: https://agentgames.zkverify.io/events/proof-gatekeeper
// Trap priority: PROOF_REUSED > VK_SUBSTITUTION > EXPIRED_CONDITION >
//   RECIPIENT_MISMATCH > AMOUNT_OVERFLOW > THRESHOLD_MISMATCH
// Fail-closed: any missing/unparseable field => REJECT / MALFORMED_TASK.
// ---------------------------------------------------------------------------
const REASON_CODES = [
  'VALID_CONDITION',
  'VK_SUBSTITUTION',
  'THRESHOLD_MISMATCH',
  'PROOF_REUSED',
  'EXPIRED_CONDITION',
  'RECIPIENT_MISMATCH',
  'AMOUNT_OVERFLOW',
  'MALFORMED_TASK',
  'PROOF_NOT_ONCHAIN', // proof_tx not found on zkVerify (defense-in-depth; not a documented trap)
];

function toBigInt(value, field) {
  if (value === undefined || value === null || value === '') {
    throw new Error(`missing field: ${field}`);
  }
  try {
    return BigInt(value);
  } catch {
    throw new Error(`unparseable field: ${field} (${String(value)})`);
  }
}

function toNumber(value, field) {
  const n = Number(value);
  if (!Number.isFinite(n)) throw new Error(`unparseable field: ${field} (${String(value)})`);
  return n;
}

function normHex(addr) {
  if (typeof addr !== 'string') throw new Error('address is not a string');
  return addr.trim().toLowerCase();
}

function decide(input, opts = {}) {
  const checks = {};
  try {
    if (!input || typeof input !== 'object') throw new Error('missing input object');

    const { registered_vk, proof_vk, proof_tx } = input;
    if (!registered_vk || !proof_vk) throw new Error('missing field: registered_vk/proof_vk');
    if (!proof_tx || typeof proof_tx !== 'string') throw new Error('missing field: proof_tx');

    const minimum = toBigInt(input.minimum, 'minimum');
    const publicBalance = toBigInt(input.public_balance, 'public_balance');
    const amount = toBigInt(input.amount, 'amount');
    const maxTransfer = toBigInt(input.max_transfer, 'max_transfer');
    const expiryBlock = toNumber(input.expiry_block, 'expiry_block');
    const currentBlock = toNumber(input.current_block, 'current_block');
    const recipient = normHex(input.recipient);
    const conditionRecipient = normHex(input.condition_recipient);

    checks.reuse = opts.isReuse ? opts.isReuse(proof_tx) : false;
    if (checks.reuse) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED', checks };
    }

    checks.vkMatch = normHex(registered_vk) === normHex(proof_vk);
    if (!checks.vkMatch) {
      return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', checks };
    }

    checks.expired = currentBlock > expiryBlock;
    if (checks.expired) {
      return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', checks };
    }

    checks.recipientMatch = recipient === conditionRecipient;
    if (!checks.recipientMatch) {
      return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', checks };
    }

    checks.amountOk = amount <= maxTransfer;
    if (!checks.amountOk) {
      return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', checks };
    }

    checks.thresholdOk = publicBalance >= minimum;
    if (!checks.thresholdOk) {
      return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', checks };
    }

    if (opts.proofOnChain === false) {
      checks.proofOnChain = false;
      return { decision: 'REJECT', reason_code: 'PROOF_NOT_ONCHAIN', checks };
    }
    checks.proofOnChain = opts.proofOnChain === true ? true : 'unchecked';

    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', checks };
  } catch (err) {
    return { decision: 'REJECT', reason_code: 'MALFORMED_TASK', checks: { ...checks, error: err.message } };
  }
}

// ---------------------------------------------------------------------------
// HMAC (WebCrypto) — same wire format as ../src/hmac.js:
// hex HMAC-SHA256 over the raw body, optional "sha256=" prefix accepted.
// ---------------------------------------------------------------------------
const _keyCache = new Map();
async function hmacKey(secret) {
  let key = _keyCache.get(secret);
  if (!key) {
    key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    _keyCache.set(secret, key);
  }
  return key;
}

async function hmacHex(secret, rawBody) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, rawBody);
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifySignature(secret, rawBody, received) {
  try {
    if (typeof received !== 'string') return false;
    const expected = await hmacHex(secret, rawBody);
    const a = new TextEncoder().encode(received.replace(/^sha256=/i, '').trim());
    const b = new TextEncoder().encode(expected);
    if (a.length !== b.length) return false;
    // Constant-time compare.
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Store — in-memory only (see header limitation note).
// ---------------------------------------------------------------------------
const seen = new Set();
const taskResponses = new Map();
function hasSeen(proofTx) { return seen.has(proofTx); }
function markSeen(proofTx) { seen.add(proofTx); }
function cachedResponse(taskId) { return taskResponses.get(taskId); }
function cacheResponse(taskId, response) {
  taskResponses.set(taskId, response);
  if (taskResponses.size > 10000) {
    taskResponses.delete(taskResponses.keys().next().value);
  }
}

// ---------------------------------------------------------------------------
// On-chain cross-check — fetch-based (replaces ../src/onchain.js WSS).
// POST eth_blockNumber to the public RPC over HTTPS. Best effort:
// null on any failure; same circuit breaker (3 fails -> skip 5 min).
// ---------------------------------------------------------------------------
const ZKVERIFY_RPC_HTTP = 'https://zkverify-rpc.zkverify.io';
const ONCHAIN_TIMEOUT_MS = 5000;
let consecutiveFailures = 0;
let skipUntil = 0;
const BREAKER_AFTER = 3;
const BREAKER_COOLDOWN_MS = 5 * 60 * 1000;

async function getChainHeadBlock() {
  if (Date.now() < skipUntil) return null;
  try {
    const res = await fetch(ZKVERIFY_RPC_HTTP, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }),
      signal: AbortSignal.timeout(ONCHAIN_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`rpc http ${res.status}`);
    const msg = await res.json();
    const numHex = msg?.result;
    if (typeof numHex !== 'string') throw new Error('no block number in rpc result');
    consecutiveFailures = 0;
    return parseInt(numHex, 16);
  } catch {
    consecutiveFailures += 1;
    if (consecutiveFailures >= BREAKER_AFTER) skipUntil = Date.now() + BREAKER_COOLDOWN_MS;
    return null;
  }
}

// ---------------------------------------------------------------------------
// HTTP layer — mirrors ../src/server.js flow, status codes and shapes.
// ---------------------------------------------------------------------------
function jsonResponse(status, obj, secret) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  const p = secret ? hmacHex(secret, new TextEncoder().encode(body)) : Promise.resolve(null);
  return p.then((sig) => {
    if (sig) headers['x-agent-games-signature'] = sig;
    return new Response(body, { status, headers });
  });
}

async function handleTask(request, env) {
  const t0 = Date.now();
  const secret = env.AGENT_HMAC_SECRET || '';
  const hmacConfigured = Boolean(secret);

  let raw;
  try {
    raw = new Uint8Array(await request.arrayBuffer());
  } catch (err) {
    return jsonResponse(413, { error: String(err.message) }, '');
  }
  if (raw.byteLength > MAX_BODY) {
    return jsonResponse(413, { error: 'body too large' }, '');
  }

  // 1. HMAC — reject unauthenticated tasks outright (only when a secret is set).
  if (hmacConfigured) {
    const sig = request.headers.get('x-agent-games-signature');
    if (!(await verifySignature(secret, raw, sig))) {
      console.log(JSON.stringify({ event: 'hmac_rejected', ms: Date.now() - t0 }));
      return jsonResponse(401, { error: 'invalid signature' }, '');
    }
  }

  // 2. Parse envelope.
  let envelope;
  try {
    envelope = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return jsonResponse(400, { error: 'invalid JSON' }, '');
  }
  const taskId = envelope?.task_id;
  const input = envelope?.input;
  const proofTx = input?.proof_tx;

  if (!taskId || typeof taskId !== 'string' || !input || typeof input !== 'object') {
    return jsonResponse(400, { error: 'missing task_id/input' }, '');
  }
  if (envelope.type && envelope.type !== TASK_TYPE) {
    const resp = { decision: 'REJECT', reason_code: 'MALFORMED_TASK', proof_tx: proofTx || null };
    return jsonResponse(200, resp, secret);
  }

  // 3. Idempotency.
  const cached = cachedResponse(taskId);
  if (cached) {
    console.log(JSON.stringify({ event: 'duplicate', task_id: taskId, ms: Date.now() - t0 }));
    return jsonResponse(200, cached, secret);
  }

  // 4. Optional read-only on-chain cross-check (5s cap).
  let onchain = 'unchecked';
  try {
    const head = await getChainHeadBlock();
    if (head !== null) {
      onchain = 'ok';
      const currentBlock = Number(input.current_block);
      if (Number.isFinite(currentBlock) && head < currentBlock - 5) {
        const resp = { decision: 'REJECT', reason_code: 'MALFORMED_TASK', proof_tx: proofTx || null };
        cacheResponse(taskId, resp);
        console.log(JSON.stringify({ event: 'future_block', task_id: taskId, head, current_block: currentBlock, ms: Date.now() - t0 }));
        return jsonResponse(200, resp, secret);
      }
    } else {
      onchain = 'unavailable';
    }
  } catch {
    onchain = 'unavailable';
  }

  // 5. Decide.
  const result = decide(input, { isReuse: hasSeen });

  // 6. Record accepted proofs only.
  if (result.decision === 'APPROVE' && proofTx) markSeen(proofTx);

  const resp = { decision: result.decision, reason_code: result.reason_code, proof_tx: proofTx || null };
  cacheResponse(taskId, resp);
  console.log(JSON.stringify({
    event: 'task', task_id: taskId, mode: envelope.mode || null,
    decision: resp.decision, reason_code: resp.reason_code,
    onchain, ms: Date.now() - t0, checks: result.checks,
  }));
  return jsonResponse(200, resp, secret);
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const secret = env.AGENT_HMAC_SECRET || '';
      const hmacConfigured = Boolean(secret);

      if (request.method === 'GET' && url.pathname === '/health') {
        return jsonResponse(200, {
          ok: true, hmac: hmacConfigured, seen: seen.size,
          uptime_s: uptimeS(),
          runtime: 'cloudflare-workers',
        }, secret);
      }
      if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/info')) {
        return jsonResponse(200, {
          service: 'agent-games-proof-gatekeeper', type: TASK_TYPE,
          hmac: hmacConfigured, endpoints: ['POST /task', 'GET /health'],
          runtime: 'cloudflare-workers',
        }, secret);
      }
      if (request.method === 'POST' && (url.pathname === '/task' || url.pathname === '/')) {
        return await handleTask(request, env);
      }
      return jsonResponse(404, { error: 'not found' }, '');
    } catch (err) {
      console.error('[gatekeeper] unhandled:', err);
      try {
        const secret = env.AGENT_HMAC_SECRET || '';
        return await jsonResponse(200, { decision: 'REJECT', reason_code: 'MALFORMED_TASK', proof_tx: null }, secret);
      } catch {
        return new Response(JSON.stringify({ decision: 'REJECT', reason_code: 'MALFORMED_TASK', proof_tx: null }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
    }
  },
};
