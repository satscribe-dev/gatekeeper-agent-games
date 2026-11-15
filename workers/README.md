# Proof Gatekeeper — Cloudflare Workers port

Live: **https://gatekeeper-agent-games.raninndia.workers.dev**
(Practice track only. No scored rounds, no agent registration from here.)

## What this is

A port of `../src/server.js` (Node, zero-dep HTTP server) to the
Cloudflare Workers fetch-handler model, in a single self-contained
file (`worker.mjs`, no imports, no bundler step). The decision path
is identical to the Node server; only the transport and the two
platform-dependent pieces changed (see "Port differences").

## Files

```
workers/
├── worker.mjs        # the whole worker (fetch handler + decide() + HMAC + store + onchain)
├── wrangler.toml     # name gatekeeper-agent-games (for wrangler-based workflows)
├── test-worker.mjs   # local harness: drives worker.mjs's fetch handler in Node
└── README.md         # this file
```

## Decision path (unchanged from the Node server)

1. HMAC-verify `x-agent-games-signature` over the RAW body
   (`AGENT_HMAC_SECRET` binding). Without a secret the worker
   answers in clearly-flagged simulation mode (health: `hmac:false`),
   exactly like the Node server with no env secret.
2. Parse envelope; require type `agent-games.proof-gatekeeper.v1`.
3. Idempotency: repeated `task_id` returns the cached response.
4. Optional on-chain block cross-check (best effort, 5 s cap).
5. Decide — `decide()` in `worker.mjs` is a VERBATIM copy of
   `../src/decision.js`. Trap order: PROOF_REUSED >
   VK_SUBSTITUTION > EXPIRED_CONDITION > RECIPIENT_MISMATCH >
   AMOUNT_OVERFLOW > THRESHOLD_MISMATCH; any doubt → REJECT /
   MALFORMED_TASK (fail-closed: wrong approve −6 vs wrong reject −3).
6. On APPROVE, record `proof_tx` as seen (PROOF_REUSED guard).
7. Respond `{decision, reason_code, proof_tx}`, signed with HMAC
   over the raw response body when a secret is set.

## Port differences (mechanical only)

- Node `http` → `export default { fetch(request, env, ctx) }`.
- `node:crypto` HMAC → WebCrypto SubtleCrypto (async, key cached
  per secret in module scope; constant-time compare).
- `store.js` file snapshot → **in-memory only**. LIMITATION: the
  seen-proof set and the task_id cache live in module-scope memory
  PER ISOLATE. A cold start, or a request landing on another
  isolate/colo, starts with an EMPTY registry — PROOF_REUSED can
  miss across isolates and a replayed `task_id` can be re-decided
  instead of served from cache. Acceptable for practice (a
  re-decision is just another decision); a scored deployment needs
  durable shared storage (Workers KV / Durable Objects).
- `onchain.js` WebSocket JSON-RPC → `fetch` POST `eth_blockNumber`
  to `https://zkverify-rpc.zkverify.io`. The public RPC was
  unreachable from the build sandbox (WSS and HTTPS both timed out,
  15 Nov 2026), so in practice this reports `onchain: unavailable`
  and the circuit breaker trips after 3 failures (skip 5 min).
  Decisions never depend on it.
- No snarkjs at runtime, no Kurier client, no proof generation
  (blocked on the unverified 13-signal input mapping — see
  `../README.md` gap 1).

## Local test

```sh
cd ~/workspace/agent-games/gatekeeper/workers
node test-worker.mjs   # 32 checks, exit 0 = pass
```

Verified 15 Nov 2026: **32/32 PASS, 0 FAIL** — all 7 trap
varieties, PROOF_REUSED, idempotency, HMAC 401s (unsigned /
wrong-secret), `sha256=`-prefixed signatures, invalid JSON 400,
simulation mode (unsigned task processed, response unsigned), and
`decide()` equivalence vs `../src/decision.js` on 4 extra vectors.

## Deploy

No wrangler login is needed; the API deploy helper uploads the
single module (same helper as the PayAPI worker):

```sh
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/deploy_worker.py \
  6ccaec511ffffe230d4d47f216f21f0f gatekeeper-agent-games worker.mjs
```

Account: Raninndia@gmail.com's Account (`6ccaec51…`), the same
account hosting `bsc-agent-utilities.raninndia.workers.dev`.
The upload sets `main_module: worker.mjs`, compatibility date
2026-11-06, `nodejs_compat`. The workers.dev URL is live
immediately after a successful response (`success: true`).

## Setting the HMAC secret (after agent registration)

The real secret is issued once at agent registration in the Agent
Games dashboard (`/dashboard/agents`) and shown exactly once.
Set it as a Worker secret (never in code, never in `wrangler.toml`):

```sh
# from the workers/ directory, with wrangler logged in:
wrangler secret put AGENT_HMAC_SECRET
# (paste the secret when prompted; it is stored encrypted by Cloudflare)
```

Or via the Cloudflare API (same credential as the deploy helper):

```sh
curl -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/6ccaec511ffffe230d4d47f216f21f0f/workers/scripts/gatekeeper-agent-games/secrets" \
  -H "Authorization: Bearer <CF_API_TOKEN>" \
  -H "Content-Type: application/json" \
  --data '{"name":"AGENT_HMAC_SECRET","text":"<secret-from-registration>","type":"secret_text"}'
```

Verify after setting: `GET /health` must show `"hmac": true`.
Verify a signed task is accepted and an unsigned one gets 401.
To remove a secret: `wrangler secret delete AGENT_HMAC_SECRET`
(or `DELETE .../scripts/gatekeeper-agent-games/secrets/AGENT_HMAC_SECRET`).

Until the secret is set the worker runs in simulation mode: it
accepts unsigned tasks and answers unsigned — DO NOT point the
Agent Games dashboard at it in that state (the platform signs every
task; an unauthenticated endpoint cannot be registered).

## Live smoke tests (15 Nov 2026, verified end-to-end)

Deploy 1 (`deployment_id 50de00d9…`, 00:04 UTC): `success: true`,
but the workers.dev URL first returned Cloudflare **error 1042 /
404** — a script uploaded via the API does NOT get its workers.dev
route until it is explicitly enabled:
`POST /accounts/<id>/workers/scripts/gatekeeper-agent-games/subdomain
{"enabled": true}` → `{"enabled": true, ...}`. After that, `/health`
answered 200 immediately. (The deploy helper does not do this step
yet — remember it for any future new worker.)

Deploy 1 also exposed a real bug: `/health` reported
`uptime_s: 1794701400` (≈ epoch seconds) — `Date.now()` at module
top-level evaluates to 0 in Workers isolates. Fixed by capturing the
start time lazily on the first request (`uptimeS()`). Deploy 2
(`deployment_id 35fa2b4d…`) verified: `uptime_s: 0` on a fresh isolate.

Results (deployment 2, all read from live responses):

- `GET /health` → `{"ok":true,"hmac":false,"seen":0,"uptime_s":0,"runtime":"cloudflare-workers"}` (no secret — simulation mode)
- Unsigned valid task → `APPROVE / VALID_CONDITION`, no
  `x-agent-games-signature` header (correct for simulation mode)
- Unsigned VK_SUBSTITUTION task → `REJECT / VK_SUBSTITUTION`
- Signed tests, live, with a throwaway 32-byte test secret set via
  the Secrets API for the duration of the test, then DELETED
  (list shows `[]` afterwards, health back to `hmac:false`,
  unsigned tasks work again):
  signed valid → APPROVE, response HMAC verified against the test
  secret; signed VK trap → REJECT/VK_SUBSTITUTION, signature
  verified; unsigned → 401; wrong secret → 401; PROOF_REUSED on a
  re-sent approved `proof_tx` → REJECT/PROOF_REUSED; replay of the
  same `task_id` → identical APPROVE. 8/8 checks passed.
- Observed per-isolate behavior (matches the documented
  limitation): `GET /health` repeatedly shows `seen: 0` and
  `uptime_s: 0` even after tasks were APPROVED — requests are
  landing on fresh isolates, so the in-memory seen-set does NOT
  persist across requests in practice on the free tier. The reuse
  check still worked in the signed test run (requests hit a warm
  isolate), but DO NOT rely on it across requests until durable
  storage (KV / Durable Objects) is added.
