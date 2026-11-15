# Proof Gatekeeper — Agent Games (zkVerify)

Scaffold + practice harness for the **Proof Gatekeeper** arena track.
Scope: build + validate locally only. **No scored rounds** (needs GitHub
linked + a user decision; not done here).

## What the agent does

Receives a signed task envelope (`POST /task`), verifies the HMAC,
decides `APPROVE` / `REJECT` with a `reason_code`, and signs its
response — all inside the 60s deadline (typical: <10 ms once the
on-chain check is warm; ~2s worst case when the public RPC is down).

Decision rules (from `/events/proof-gatekeeper`, read 15 Nov 2026):

| Check (in order) | Fail → | Notes |
|---|---|---|
| proof_tx already accepted before | `PROOF_REUSED` | recorded only on APPROVE |
| `proof_vk != registered_vk` | `VK_SUBSTITUTION` | valid proof, wrong key |
| `current_block > expiry_block` | `EXPIRED_CONDITION` | |
| `recipient != condition_recipient` | `RECIPIENT_MISMATCH` | case-insensitive |
| `amount > max_transfer` | `AMOUNT_OVERFLOW` | BigInt math (no float) |
| `public_balance < minimum` | `THRESHOLD_MISMATCH` | |
| all pass | `APPROVE` / `VALID_CONDITION` | |
| missing/unparseable field | `MALFORMED_TASK` | fail-closed |

Scoring asymmetry is respected: wrong approve −6 vs wrong reject −3,
so on any doubt the agent REJECTS. Responses are
`{decision, reason_code, proof_tx}` (the event page's exact shape —
no proof field in the response).

## Cost — the important part

| Path | Cost | Status |
|---|---|---|
| Decision engine + local field checks | **$0** | implemented |
| Local Groth16 verify (`snarkjs`, exported vk) | **$0** | implemented (`verifyProofLocal`) |
| Read-only on-chain cross-check (public mainnet RPC `wss://zkverify-rpc.zkverify.io`, no key/seed/funds) | **$0** | implemented, best-effort + circuit breaker |
| Kurier mainnet API key | **unknown — no public price; request-gated from Horizen Labs** | NOT requested; client code is env-gated (`KURIER_API_KEY`, `KURIER_API_URL`) |
| zkVerifyJS write path (submit proof on-chain) | real VFY for fees (VFY ~$0.0046, 14 Nov 2026; per-proof fee unpublished; a third-party relay quotes a ~$0.01/proof floor) + a funded account/seed | NOT done — real money + seed handling, out of scope here |

Bottom line: **the agent can play the full decision game for $0.**
On-chain submission is only needed if the platform is later shown to
require a per-task proof submission from the agent (see open gaps).

## Files

```
gatekeeper/
├── circuits/
│   ├── gatekeeper.wasm        # 1,755,820 B, from agentgames.zkverify.io/circuits/
│   ├── gatekeeper_final.zkey  # 309,750 B, same source
│   └── gatekeeper_vk.json     # exported vk (groth16/bn128, nPublic=13)
├── src/
│   ├── decision.js  # pure decision engine (all 7 traps + malformed)
│   ├── hmac.js      # x-agent-games-signature verify/sign (SHA-256 HMAC)
│   ├── store.js     # seen proof_tx registry + task_id idempotency cache
│   ├── onchain.js   # read-only chain-head check (WS JSON-RPC + breaker)
│   ├── proof.js     # local verify + Kurier client (opt-in) + proof gen (BLOCKED, see below)
│   └── server.js    # Node http server, zero dependencies
├── test/simulate.js # local practice round: valid + 7 traps + HMAC + idempotency
├── Dockerfile       # node:24-alpine for VPS deploy
└── .env.example
```

## Validation (local, 15 Nov 2026)

`node test/simulate.js` — **24/24 PASS**:

- All 7 trap varieties → correct `REJECT` + `reason_code`
- Valid condition → `APPROVE` / `VALID_CONDITION`
- `PROOF_REUSED` across two tasks sharing one `proof_tx`
- Duplicate `task_id` → identical cached response
- Unsigned / wrong-signature requests → 401, never processed
- Invalid JSON → 400; malformed fields → signed `REJECT`
- Garbage Groth16 proof → `verify` returns `false`
- Latency p95 ≈ 1.9s (first tasks pay the 2s RPC timeout; after the
  circuit breaker trips, 4–61 ms) — far under the 60s deadline

## Open gaps (do NOT guess — each needs a verified source)

1. **Circuit input mapping (13 public signals).** The zkey header says
   `nPublic = 13`, `nVars = 647`, `domainSize = 1024` (verified from
   the binary + exported vk). The circuit source is not published, so
   the names/order of those 13 public signals are UNVERIFIED.
   `generateDecisionProof()` throws `INPUT_MAPPING_UNKNOWN` until the
   mapping is obtained (it lives in the `/build` starter prompt or a
   dashboard practice example — readable only from a logged-in
   session). The decision engine does not depend on this.
2. **Does the platform require the agent to submit a fresh Groth16
   proof per approved task?** `/build` says "generate proofs locally
   … and include the proof in your response", but the event page's
   response shape is `{decision, reason_code, proof_tx}` with no proof
   field, and the reliability bonus is about the TASK's proof verifying
   against the registered key. If a per-task submission is required,
   it goes through Kurier (key not yet requested) or a funded VFY
   account (real money). Resolve from a real practice task payload.
3. **vkHash cross-check.** Platform says the gatekeeper vkHash is
   `0x6b79c601…ad77b0` (`/api/circuit-info`). Artifacts were fetched
   from the platform's own URLs, so provenance is the platform
   itself. A byte-level cross-check needs the platform's vk-hashing
   scheme (or one Kurier `register-vk` round-trip, which returns the
   vk hash) — not done yet.
4. **On-chain RPC reachability.** From this sandbox the public RPC
   was unreachable (every check hit the timeout; breaker tripped).
   From a deploy host it may work — verify after deploy.

## Practice mode — BLOCKED (needs the user)

Registering an agent (required before any practice dispatch) needs
GitHub linked — Settings → Eligibility says GitHub is "Required to
enable VFY & Gatekeeper and to submit agents", and the event's entry
requirements demand an authenticated prize-eligibility identity +
signed preflight + ≥1 practice task. The user links GitHub from their
phone (Dashboard → avatar → Account settings → Accounts → GitHub
Connect → Authorize; account **satscribe-dev**). After that:

1. Deploy (see below), register the endpoint in
   `/dashboard/agents`, complete the signed preflight.
2. Start practice (`/dashboard/practice`, 10 dispatches/hour, no
   leaderboard effect) and compare each dispatch against the local
   simulator's expected decision; keep the first real task payload as
   a regression fixture (it also resolves gaps 1–2).
3. Only then consider scored rounds (Round 03 opens 15 Nov 17:30 WIB;
   Rounds 01–02 are gone — this is practice/portfolio, not a top-3 run).

## Deploy options (cheapest first)

1. **User's VPS (Cloady)** — `Dockerfile` included (`node:24-alpine`,
   `npm ci`, `node src/server.js`, port 8788). Needs a public HTTPS
   front (domain + TLS — Caddy/nginx) and the `AGENT_HMAC_SECRET`
   env from agent registration. No new account, no new credentials.
2. **Cloudflare Workers** (existing `raninndia` account) — **DONE 15 Nov
   2026, live at https://gatekeeper-agent-games.raninndia.workers.dev**
   — see `workers/` (`worker.mjs` + `test-worker.mjs` 32/32 PASS local,
   8/8 live signed checks PASS with a throwaway secret, since deleted;
   unsigned smoke tests PASS in simulation mode). Port notes: HTTP
   layer rewritten as a fetch handler, on-chain check is fetch-based
   `eth_blockNumber` (best-effort; public RPC unreachable from the
   sandbox), store is in-memory per isolate (PROOF_REUSED/idempotency
   do not survive cold starts — observed live: `seen` resets to 0
   between requests). Deploy gotcha: a script uploaded via the API
   does NOT get a workers.dev route until
   `POST .../workers/scripts/<name>/subdomain {"enabled": true}`.
   No secret is set yet — registration + `wrangler secret put
   AGENT_HMAC_SECRET` still to come (see `workers/README.md`).
3. **Nowhere** — without a public HTTPS endpoint the agent cannot be
   registered at all. Local validation is complete; deployment waits
   for the GitHub link + a host decision.

## Run locally

```sh
cd ~/workspace/agent-games/gatekeeper
npm install            # snarkjs only (decision path has no deps)
AGENT_HMAC_SECRET=<secret-from-registration> PORT=8788 node src/server.js
# smoke test:
curl -s localhost:8788/health
npm run simulate       # 24-check local practice round
```

Env vars: `PORT` (default 8788), `AGENT_HMAC_SECRET` (required for
real use), `ONCHAIN_TIMEOUT_MS` (default 5000),
`KURIER_API_KEY` / `KURIER_API_URL` (opt-in proof submission only),
`ZKVERIFY_RPC_URL` (default public mainnet RPC), `SEEN_FILE`
(seen-proof snapshot path).
