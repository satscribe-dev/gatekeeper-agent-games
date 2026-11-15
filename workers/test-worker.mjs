// Local test for the Workers port: drives worker.mjs's fetch handler
// directly (Node 24 has WebCrypto + fetch + Request/Response globals),
// with the same cases as ../test/simulate.js, plus a cross-check of
// every result against the Node decision engine (../src/decision.js)
// to prove the ported decide() is behaviorally identical.
// No network deployment needed. Exit 0 = all checks pass.
//
// Usage: node test-worker.mjs
//   (uses a throwaway secret, 'test-secret-do-not-use-in-production')

import crypto from 'node:crypto';
import worker from './worker.mjs';
import { decide as nodeDecide } from '../src/decision.js';

const SECRET = 'test-secret-do-not-use-in-production';
const VK = '0x7d3a11111111111111111111111111111111111111111111111111111111f291';
const OTHER_VK = '0xa4c11111111111111111111111111111111111111111111111111111111b8ff';
const RECIPIENT = '0xDe4200000000000000000000000000000000009f01';
const OTHER_RECIPIENT = '0xAb0000000000000000000000000000000000000001';

function task(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: overrides.task_id || `gk_wk_${Math.random().toString(36).slice(2, 8)}`,
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

const BASE = 'https://gatekeeper-agent-games.local';

async function call(path, body, { sign = true, secret = SECRET, env = { AGENT_HMAC_SECRET: SECRET }, method = 'POST' } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  const headers = { 'content-type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  const res = await worker.fetch(new Request(`${BASE}${path}`, { method, headers, body: method === 'GET' ? undefined : raw }), env, {});
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* leave null */ }
  return { status: res.status, json, sig: res.headers.get('x-agent-games-signature'), rawOut: text };
}

function verifyRespSig(rawOut, sig, secret = SECRET) {
  if (!sig) return false;
  const expect = crypto.createHmac('sha256', secret).update(rawOut).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect)); } catch { return false; }
}

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures++;
}

async function main() {
  // 0. Health + root in both modes.
  const h1 = await worker.fetch(new Request(`${BASE}/health`), { AGENT_HMAC_SECRET: SECRET }, {});
  const h1j = await h1.json();
  check('GET /health (secret set)', h1.status === 200 && h1j.ok === true && h1j.hmac === true && h1j.runtime === 'cloudflare-workers', JSON.stringify(h1j));
  const h0 = await worker.fetch(new Request(`${BASE}/health`), {}, {});
  const h0j = await h0.json();
  check('GET /health (no secret = simulation)', h0.status === 200 && h0j.ok === true && h0j.hmac === false, JSON.stringify(h0j));
  const root = await worker.fetch(new Request(`${BASE}/`), {}, {});
  const rootJ = await root.json();
  check('GET / service info', root.status === 200 && rootJ.service === 'agent-games-proof-gatekeeper', JSON.stringify(rootJ));
  const nf = await worker.fetch(new Request(`${BASE}/nope`), {}, {});
  check('GET /nope -> 404', nf.status === 404);

  // 1. The 7 cases over HTTP, signed, vs Node decide() equivalence.
  let reuseTx = null;
  for (const c of CASES) {
    const t = c.make();
    const r = await call('/task', t);
    const node = nodeDecide(t.input, { isReuse: () => false });
    const ok = r.status === 200 && r.json?.decision === c.expect[0] && r.json?.reason_code === c.expect[1]
      && r.json?.proof_tx === t.input.proof_tx
      && node.decision === c.expect[0] && node.reason_code === c.expect[1];
    check(`HTTP ${c.name} -> ${c.expect.join('/')} (matches Node decide)`, ok, `status=${r.status} got=${r.json?.decision}/${r.json?.reason_code}`);
    check(`HTTP ${c.name} response is HMAC-signed`, verifyRespSig(r.rawOut, r.sig));
    if (c.name === 'VALID_CONDITION') reuseTx = t.input.proof_tx;
  }

  // 2. PROOF_REUSED: same proof_tx in a fresh task.
  const reused = task({ task_id: 'gk_wk_reuse_1', proof_tx: reuseTx });
  const rr = await call('/task', reused);
  check('HTTP PROOF_REUSED -> REJECT/PROOF_REUSED', rr.status === 200 && rr.json?.decision === 'REJECT' && rr.json?.reason_code === 'PROOF_REUSED', `got=${rr.json?.decision}/${rr.json?.reason_code}`);

  // 3. Idempotency: same task_id twice -> identical response.
  const first = task();
  const r1 = await call('/task', first);
  const r2 = await call('/task', first);
  check('idempotency: same task_id twice -> identical response', JSON.stringify(r1.json) === JSON.stringify(r2.json) && r1.json?.decision === 'APPROVE', `first=${r1.json?.decision} second=${r2.json?.decision}`);

  // 4. HMAC enforcement.
  const noSig = await call('/task', task(), { sign: false });
  check('unsigned request -> 401', noSig.status === 401, `status=${noSig.status}`);
  const badSig = await call('/task', task(), { secret: 'wrong-secret' });
  check('wrong-signature request -> 401', badSig.status === 401, `status=${badSig.status}`);
  const prefixed = await call('/task', task(), { sign: false });
  // sign with "sha256=" prefix format
  const rawP = JSON.stringify(task());
  const sigP = 'sha256=' + crypto.createHmac('sha256', SECRET).update(rawP).digest('hex');
  const rp = await worker.fetch(new Request(`${BASE}/task`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sigP }, body: rawP }), { AGENT_HMAC_SECRET: SECRET }, {});
  check('"sha256=" prefixed signature accepted', rp.status === 200, `status=${rp.status}`);

  // 5. Malformed JSON + missing fields.
  const malformed = await call('/task', '{not json');
  check('invalid JSON -> 400', malformed.status === 400, `status=${malformed.status}`);
  const noInput = await call('/task', { type: 'agent-games.proof-gatekeeper.v1', task_id: 'x' });
  check('missing input -> 400', noInput.status === 400, `status=${noInput.status}`);
  const wrongType = await call('/task', { type: 'something.else', task_id: 'gk_wk_wrongtype', input: task().input });
  check('wrong envelope type -> REJECT/MALFORMED_TASK', wrongType.status === 200 && wrongType.json?.decision === 'REJECT' && wrongType.json?.reason_code === 'MALFORMED_TASK', `got=${wrongType.json?.decision}/${wrongType.json?.reason_code}`);

  // 6. Simulation mode (no secret): unsigned task is PROCESSED and response unsigned.
  const simTask = task();
  const sim = await call('/task', simTask, { sign: false, env: {} });
  check('simulation mode: unsigned task processed', sim.status === 200 && sim.json?.decision === 'APPROVE' && sim.json?.reason_code === 'VALID_CONDITION', `status=${sim.status} got=${sim.json?.decision}/${sim.json?.reason_code}`);
  check('simulation mode: response unsigned', sim.sig === null, `sig=${sim.sig}`);

  // 7. Extra decide() equivalence vectors (worker HTTP vs Node decide).
  const vectors = [
    [{ registered_vk: VK, proof_vk: VK, minimum: '0', public_balance: '0', expiry_block: 5, current_block: 5, recipient: RECIPIENT, condition_recipient: RECIPIENT.toLowerCase(), amount: '0', max_transfer: '0', proof_tx: '0xeq1' }, ['APPROVE', 'VALID_CONDITION']],
    [{ registered_vk: VK, proof_vk: VK, minimum: '100', public_balance: '100', expiry_block: 5, current_block: 6, recipient: RECIPIENT, condition_recipient: RECIPIENT, amount: '1', max_transfer: '1', proof_tx: '0xeq2' }, ['REJECT', 'EXPIRED_CONDITION']],
    [{ registered_vk: VK, proof_vk: VK, minimum: '100', public_balance: '50', expiry_block: 5, current_block: 5, recipient: RECIPIENT, condition_recipient: RECIPIENT, amount: 'x', max_transfer: '1', proof_tx: '0xeq3' }, ['REJECT', 'MALFORMED_TASK']],
    [{ registered_vk: VK, proof_vk: VK, minimum: '100', public_balance: '50', expiry_block: 5, current_block: 5, recipient: 'NOT_AN_ADDRESS', condition_recipient: RECIPIENT, amount: '1', max_transfer: '1', proof_tx: '0xeq4' }, ['REJECT', 'RECIPIENT_MISMATCH']],
  ];
  for (const [input, expect] of vectors) {
    const t = { type: 'agent-games.proof-gatekeeper.v1', task_id: `gk_wk_vec_${Math.random().toString(36).slice(2, 8)}`, mode: 'practice', input };
    const r = await call('/task', t);
    const node = nodeDecide(input, { isReuse: () => false });
    check(`equivalence ${expect.join('/')}`, r.json?.decision === expect[0] && r.json?.reason_code === expect[1] && node.decision === expect[0] && node.reason_code === expect[1], `worker=${r.json?.decision}/${r.json?.reason_code} node=${node.decision}/${node.reason_code}`);
  }

  console.log(failures === 0 ? '\nALL WORKER CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('test-worker crashed:', e); process.exit(1); });
