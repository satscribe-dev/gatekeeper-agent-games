// Proof Gatekeeper — agent endpoint (Node.js, zero dependencies).
//  - POST /task (also POST /) — signed arena task envelope
//  - GET  /health             — {ok, seen, uptime_s}
//  - GET  /                   — service info
//
// Flow per task (all inside the 60s hard deadline; typical cost is
// milliseconds — the only network call is the optional read-only
// on-chain cross-check, capped at 5s):
//   1. Verify HMAC x-agent-games-signature over the RAW body (if
//      AGENT_HMAC_SECRET is set; without it the server refuses to
//      claim authentication — it still answers, clearly flagged as
//      unauthenticated, so local simulation works).
//   2. Parse envelope; require type agent-games.proof-gatekeeper.v1.
//   3. Idempotency: a repeated task_id returns the cached response.
//   4. Optional on-chain block cross-check (best effort).
//   5. Decide (decision.js — all 7 documented traps + malformed).
//   6. On APPROVE, record proof_tx as seen (PROOF_REUSED guard).
//   7. Respond {decision, reason_code, proof_tx} signed with
//      x-agent-games-signature over the raw response body.
//
// Fail-closed everywhere: any doubt => REJECT, never APPROVE.
// Rejecting a valid task costs -3; approving a trap costs -6.

import http from 'node:http';
import { decide } from './decision.js';
import { verifySignature, signResponse } from './hmac.js';
import { loadFromDisk, hasSeen, markSeen, seenCount, cachedResponse, cacheResponse } from './store.js';
import { getChainHeadBlock } from './onchain.js';

const PORT = Number(process.env.PORT || 8788);
const TASK_TYPE = 'agent-games.proof-gatekeeper.v1';
const MAX_BODY = 1024 * 1024;
const STARTED_AT = Date.now();

const hmacConfigured = Boolean(process.env.AGENT_HMAC_SECRET);
loadFromDisk();
console.log(`[gatekeeper] starting on :${PORT} — hmac ${hmacConfigured ? 'configured' : 'NOT SET (simulation mode)'}, seen=${seenCount()}`);

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let tooBig = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { tooBig = true; return; }
      chunks.push(c);
    });
    req.on('end', () => (tooBig ? reject(new Error('body too large')) : resolve(Buffer.concat(chunks))));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj, sign = true) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (sign && hmacConfigured) {
    try { headers['x-agent-games-signature'] = signResponse(body); } catch { /* unsigned */ }
  }
  res.writeHead(status, headers);
  res.end(body);
}

async function handleTask(req, res) {
  const t0 = Date.now();
  let raw;
  try {
    raw = await readRawBody(req);
  } catch (err) {
    return sendJson(res, 413, { error: String(err.message) }, false);
  }

  // 1. HMAC — reject unauthenticated tasks outright.
  if (hmacConfigured) {
    const sig = req.headers['x-agent-games-signature'];
    if (!verifySignature(raw, sig)) {
      console.log(JSON.stringify({ event: 'hmac_rejected', ms: Date.now() - t0 }));
      return sendJson(res, 401, { error: 'invalid signature' }, false);
    }
  }

  // 2. Parse envelope.
  let env;
  try {
    env = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, 400, { error: 'invalid JSON' }, false);
  }
  const taskId = env?.task_id;
  const input = env?.input;
  const proofTx = input?.proof_tx;

  if (!taskId || typeof taskId !== 'string' || !input || typeof input !== 'object') {
    return sendJson(res, 400, { error: 'missing task_id/input' }, false);
  }
  if (env.type && env.type !== TASK_TYPE) {
    const resp = { decision: 'REJECT', reason_code: 'MALFORMED_TASK', proof_tx: proofTx || null };
    return sendJson(res, 200, resp);
  }

  // 3. Idempotency.
  const cached = cachedResponse(taskId);
  if (cached) {
    console.log(JSON.stringify({ event: 'duplicate', task_id: taskId, ms: Date.now() - t0 }));
    return sendJson(res, 200, cached);
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
        return sendJson(res, 200, resp);
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
    event: 'task', task_id: taskId, mode: env.mode || null,
    decision: resp.decision, reason_code: resp.reason_code,
    onchain, ms: Date.now() - t0, checks: result.checks,
  }));
  return sendJson(res, 200, resp);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, { ok: true, hmac: hmacConfigured, seen: seenCount(), uptime_s: Math.floor((Date.now() - STARTED_AT) / 1000) });
    }
    if (req.method === 'GET' && (req.url === '/' || req.url === '/info')) {
      return sendJson(res, 200, { service: 'agent-games-proof-gatekeeper', type: TASK_TYPE, hmac: hmacConfigured, endpoints: ['POST /task', 'GET /health'] });
    }
    if (req.method === 'POST' && (req.url === '/task' || req.url === '/')) {
      return await handleTask(req, res);
    }
    return sendJson(res, 404, { error: 'not found' }, false);
  } catch (err) {
    console.error('[gatekeeper] unhandled:', err);
    // Fail closed even on internal error: a signed REJECT is better
    // than a dropped connection (timeout = -2 and no decision at all).
    try {
      return sendJson(res, 200, { decision: 'REJECT', reason_code: 'MALFORMED_TASK', proof_tx: null });
    } catch { /* socket gone */ }
  }
});

server.listen(PORT, () => console.log(`[gatekeeper] listening on :${PORT}`));
