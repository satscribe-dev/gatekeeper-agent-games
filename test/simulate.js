// Local simulation of a Gatekeeper practice round: 1 valid task + all
// 7 documented trap varieties, posted over HTTP to a fresh server
// instance (spawned here with a throwaway HMAC secret).
// Asserts: correct decision + reason_code for every trap, HMAC
// signature on every response, duplicate task_id idempotency, reuse
// across two tasks, and p95 latency far below the 60s deadline.
// The on-chain cross-check is best-effort: in this sandbox the public
// RPC may be unreachable — the test only requires that the decision is
// still correct (local field checks decide all 7 documented traps).
//
// Usage: node test/simulate.js   (exit 0 = all checks pass)

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { decide } from '../src/decision.js';
import { loadVk, verifyProofLocal } from '../src/proof.js';

const SECRET = 'test-secret-do-not-use-in-production';
const PORT = 18788;
const BASE = `http://127.0.0.1:${PORT}`;
const VK = '0x7d3a11111111111111111111111111111111111111111111111111111111f291';
const OTHER_VK = '0xa4c11111111111111111111111111111111111111111111111111111111b8ff';
const RECIPIENT = '0xDe4200000000000000000000000000000000009f01';
const OTHER_RECIPIENT = '0xAb0000000000000000000000000000000000000001';

function task(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: overrides.task_id || `gk_sim_${Math.random().toString(36).slice(2, 8)}`,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: '500',
      max_transfer: '1000',
      proof_tx: overrides.proof_tx || `0x${crypto.randomBytes(16).toString('hex')}`,
      ...inputOverrides,
    },
    ...overrides,
  };
}

const CASES = [
  { name: 'VALID_CONDITION', make: () => task(), expect: ['APPROVE', 'VALID_CONDITION'] },
  { name: 'VK_SUBSTITUTION', make: () => task({}, { proof_vk: OTHER_VK }), expect: ['REJECT', 'VK_SUBSTITUTION'] },
  { name: 'THRESHOLD_MISMATCH', make: () => task({}, { public_balance: '999' }), expect: ['REJECT', 'THRESHOLD_MISMATCH'] },
  { name: 'EXPIRED_CONDITION', make: () => task({}, { current_block: 19842202 }), expect: ['REJECT', 'EXPIRED_CONDITION'] },
  { name: 'RECIPIENT_MISMATCH', make: () => task({}, { recipient: OTHER_RECIPIENT }), expect: ['REJECT', 'RECIPIENT_MISMATCH'] },
  { name: 'AMOUNT_OVERFLOW', make: () => task({}, { amount: '1001' }), expect: ['REJECT', 'AMOUNT_OVERFLOW'] },
  { name: 'MALFORMED_TASK', make: () => task({}, { minimum: undefined, public_balance: undefined }), expect: ['REJECT', 'MALFORMED_TASK'] },
];

async function post(path, body, sign = true) {
  const raw = JSON.stringify(body);
  const headers = { 'content-type': 'application/json' };
  if (sign) {
    headers['x-agent-games-signature'] = crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
  }
  const t0 = Date.now();
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers, body: raw });
  const ms = Date.now() - t0;
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, ms, json, sig: res.headers.get('x-agent-games-signature'), rawOut: text };
}

function verifyRespSig(rawOut, sig) {
  if (!sig) return false;
  const expect = crypto.createHmac('sha256', SECRET).update(rawOut).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect));
}

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
}

async function main() {
  // 0. Unit-test the pure decision engine first (no HTTP).
  const unit = decide(
    { registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460', expiry_block: 10, current_block: 9, recipient: RECIPIENT, condition_recipient: RECIPIENT, amount: '500', max_transfer: '1000', proof_tx: '0xabc' },
    { isReuse: () => false },
  );
  check('unit decide() VALID', unit.decision === 'APPROVE' && unit.reason_code === 'VALID_CONDITION', JSON.stringify(unit));

  // Proof module: vk exports from the downloaded zkey (nPublic must be 13,
  // matching the header parse). Positive proof verification is NOT
  // asserted here — it needs the circuit input mapping (see proof.js);
  // the negative control (garbage proof must NOT verify) is asserted.
  const vk = await loadVk();
  check('vk exports, nPublic=13, groth16/bn128', vk.nPublic === 13 && vk.protocol === 'groth16' && vk.curve === 'bn128', `nPublic=${vk.nPublic}`);
  const garbageProof = { pi_a: ['1', '2', '1'], pi_b: [['1', '2'], ['3', '4'], ['1', '1']], pi_c: ['5', '6', '1'], protocol: 'groth16', curve: 'bn128' };
  let garbageVerifies = null;
  try { garbageVerifies = await verifyProofLocal(garbageProof, Array(13).fill('0')); } catch (e) { garbageVerifies = `error: ${e.message}`; }
  check('garbage proof does NOT verify', garbageVerifies === false, `got=${garbageVerifies}`);

  const server = spawn('node', ['src/server.js'], {
    cwd: new URL('..', import.meta.url).pathname,
    env: { ...process.env, PORT: String(PORT), AGENT_HMAC_SECRET: SECRET, ONCHAIN_TIMEOUT_MS: '2000' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  server.stdout.on('data', (d) => { serverLog += d.toString(); });
  server.stderr.on('data', (d) => { serverLog += d.toString(); });

  try {
    // Wait for the health endpoint.
    let up = false;
    for (let i = 0; i < 30; i++) {
      try {
        const r = await fetch(`${BASE}/health`);
        if (r.ok) { up = true; break; }
      } catch { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 300));
    }
    check('server boots + /health', up);
    if (!up) { console.log(serverLog); process.exit(1); }

    const latencies = [];
    let reuseTx = null;

    for (const c of CASES) {
      const t = c.make();
      const r = await post('/task', t);
      latencies.push(r.ms);
      const ok = r.status === 200 && r.json?.decision === c.expect[0] && r.json?.reason_code === c.expect[1] && r.json?.proof_tx === t.input.proof_tx;
      check(`HTTP ${c.name} -> ${c.expect.join('/')}`, ok, `status=${r.status} got=${r.json?.decision}/${r.json?.reason_code} ms=${r.ms}`);
      check(`HTTP ${c.name} response is HMAC-signed`, verifyRespSig(r.rawOut, r.sig));
      if (c.name === 'VALID_CONDITION') reuseTx = t.input.proof_tx;
    }

    // PROOF_REUSED: same proof_tx in a fresh task (already accepted once).
    const reused = task({ task_id: 'gk_sim_reuse_1', proof_tx: reuseTx });
    const rr = await post('/task', reused);
    latencies.push(rr.ms);
    check('HTTP PROOF_REUSED -> REJECT/PROOF_REUSED', rr.status === 200 && rr.json?.decision === 'REJECT' && rr.json?.reason_code === 'PROOF_REUSED', `got=${rr.json?.decision}/${rr.json?.reason_code}`);

    // Idempotency: replay the first valid task_id — must return the cached APPROVE.
    const first = CASES[0].make();
    const firstTaskId = first.task_id;
    const r1 = await post('/task', first);
    const r2 = await post('/task', first);
    check('idempotency: same task_id twice -> identical response', JSON.stringify(r1.json) === JSON.stringify(r2.json) && r1.json?.decision === 'APPROVE', `first=${r1.json?.decision} second=${r2.json?.decision}`);

    // HMAC: unsigned + wrong-signature requests must be rejected, not processed.
    const noSig = await post('/task', task(), false);
    check('unsigned request -> 401', noSig.status === 401, `status=${noSig.status}`);
    const badSig = await post('/task', task());
    // tamper: sign with a different secret by re-signing manually
    const rawBad = JSON.stringify(task());
    const badRes = await fetch(`${BASE}/task`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': crypto.createHmac('sha256', 'wrong-secret').update(rawBad).digest('hex') },
      body: rawBad,
    });
    check('wrong-signature request -> 401', badRes.status === 401, `status=${badRes.status}`);

    // Malformed JSON + missing fields.
    const malformed = await fetch(`${BASE}/task`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': crypto.createHmac('sha256', SECRET).update('{not json').digest('hex') },
      body: '{not json',
    });
    check('invalid JSON -> 400', malformed.status === 400, `status=${malformed.status}`);

    latencies.sort((a, b) => a - b);
    const p95 = latencies[Math.floor(latencies.length * 0.95)] ?? latencies.at(-1);
    check('latency p95 << 60s deadline', p95 < 5000, `p95=${p95}ms max=${latencies.at(-1)}ms n=${latencies.length}`);
  } finally {
    server.kill('SIGTERM');
  }

  console.log(failures === 0 ? '\nALL SIMULATION CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('simulate crashed:', e); process.exit(1); });
