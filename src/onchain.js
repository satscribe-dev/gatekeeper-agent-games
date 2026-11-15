// Read-only on-chain cross-check (FREE — no seed, no funds, no key).
// Uses the public zkVerify mainnet RPC (docs.zkverify.io:
// wss://zkverify-rpc.zkverify.io) over a raw WebSocket JSON-RPC call.
// Best-effort by design: if the RPC is unreachable/slow, the caller
// proceeds on local field checks and records `onchain: 'unavailable'`.
// A FAILED RPC must never turn a valid task into a forfeit — the
// documented traps are all field-level, and local checks decide them.
// What this check CAN catch: a task claiming a block height in the
// future (chain head below the task's current_block) — evidence of a
// stale/forged envelope.

const RPC_URL = process.env.ZKVERIFY_RPC_URL || 'wss://zkverify-rpc.zkverify.io';
const TIMEOUT_MS = Number(process.env.ONCHAIN_TIMEOUT_MS || 5000);

// Circuit breaker: if the public RPC is unreachable, every task would
// pay the full timeout for nothing. After 3 consecutive failures the
// check is skipped for 5 minutes (decisions still run on local field
// checks, which decide all 7 documented trap varieties).
let consecutiveFailures = 0;
let skipUntil = 0;
const BREAKER_AFTER = 3;
const BREAKER_COOLDOWN_MS = 5 * 60 * 1000;

/** Current zkVerify mainnet block height, or null if unavailable. */
export function getChainHeadBlock() {
  if (Date.now() < skipUntil) return Promise.resolve(null);
  return new Promise((resolve) => {
    let done = false;
    let ws;
    const finish = (value) => {
      if (done) return;
      done = true;
      try { ws && ws.close(); } catch { /* ignore */ }
      if (value === null) {
        consecutiveFailures += 1;
        if (consecutiveFailures >= BREAKER_AFTER) skipUntil = Date.now() + BREAKER_COOLDOWN_MS;
      } else {
        consecutiveFailures = 0;
      }
      resolve(value);
    };
    const timer = setTimeout(() => finish(null), TIMEOUT_MS);
    try {
      ws = new WebSocket(RPC_URL);
    } catch {
      clearTimeout(timer);
      consecutiveFailures += 1;
      if (consecutiveFailures >= BREAKER_AFTER) skipUntil = Date.now() + BREAKER_COOLDOWN_MS;
      return resolve(null);
    }
    ws.onopen = () => {
      ws.send(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'chain_getHeader', params: [] }));
    };
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        const numHex = msg?.result?.number;
        if (typeof numHex === 'string') {
          clearTimeout(timer);
          finish(parseInt(numHex, 16));
        } else {
          clearTimeout(timer);
          finish(null);
        }
      } catch {
        clearTimeout(timer);
        finish(null);
      }
    };
    ws.onerror = () => { clearTimeout(timer); finish(null); };
    ws.onclose = () => { clearTimeout(timer); finish(null); };
  });
}
