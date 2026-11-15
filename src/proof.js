// Proof handling: local verification (FREE) + Kurier submission
// (OPT-IN, gated by env) + decision-proof generation (BLOCKED on an
// unverified input mapping — see below).
//
// COST VERDICT (checked 15 Nov 2026, sources: docs.zkverify.io
// quickstart + /build + /events/proof-gatekeeper):
//  - Local Groth16 verify with snarkjs + the exported vk: $0.
//  - Read-only on-chain confirmation (zkVerifyJS read-only session
//    over the public mainnet RPC wss://zkverify-rpc.zkverify.io):
//    $0, no seed phrase, no funds.
//  - Kurier mainnet API key: request-gated from Horizen Labs, NO
//    public price found anywhere. Do NOT assume free.
//  - zkVerifyJS WRITE path (submit a proof on-chain): needs a funded
//    mainnet account holding real VFY (VFY ~$0.0046, 14 Nov 2026).
//    Per-proof fee is not published; a third-party relay quotes a
//    ~$0.01/proof floor. Real money + a seed phrase => NOT done here.
//
// INPUT MAPPING GAP (honest blocker, do not guess):
//  The gatekeeper circuit has nPublic = 13 (read from the zkey header
//  15 Nov 2026; nVars = 647, domainSize = 1024). The circuit source is
//  not published, so the NAMES and ORDER of those 13 public signals
//  are UNVERIFIED. Generating a decision proof the platform would
//  accept requires that mapping (it lives in the /build starter
//  prompt / dashboard practice example, readable only from a logged-in
//  session). generateDecisionProof() therefore throws INPUT_MAPPING
//  _UNKNOWN until the mapping is supplied. The decision engine does
//  NOT depend on this: the event page's response shape is
//  {decision, reason_code, proof_tx} with no proof field, and the
//  reliability bonus is about the TASK's proof verifying against the
//  registered key — which the agent checks read-only, for free.

import { groth16, zKey } from 'snarkjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const ZKEY = path.join(DIR, '..', 'circuits', 'gatekeeper_final.zkey');
const WASM = path.join(DIR, '..', 'circuits', 'gatekeeper.wasm');

let vkPromise = null;

/** Export the verification key from the downloaded zkey (in-memory). */
export function loadVk() {
  if (!vkPromise) {
    vkPromise = zKey.exportVerificationKey(ZKEY).catch((err) => {
      vkPromise = null;
      throw new Error(`vk export failed: ${err.message}`);
    });
  }
  return vkPromise;
}

/**
 * Verify a Groth16 proof locally against the gatekeeper vk.
 * Only usable when the caller actually has proof bytes + public
 * signals. The arena task payload carries only `proof_tx` (a
 * reference), so this is used for self-tests / future payloads that
 * embed the proof, NOT for the live task flow (there the proof is
 * confirmed read-only on-chain instead).
 */
export async function verifyProofLocal(proof, publicSignals) {
  const vk = await loadVk();
  return groth16.verify(vk, publicSignals, proof);
}

/**
 * Generate a Groth16 decision proof with the gatekeeper circuit.
 * @param {object} inputSignals - circuit input signals, keyed by name
 * @throws {Error} INPUT_MAPPING_UNKNOWN until the 13-public-signal
 *   mapping (names + order) is verified from the starter prompt or a
 *   practice example payload.
 */
export async function generateDecisionProof(inputSignals) {
  if (!inputSignals || !inputSignals.__mappingVerified) {
    throw new Error(
      'INPUT_MAPPING_UNKNOWN: the gatekeeper circuit has 13 public signals ' +
      'but their names/order are not published. Do not guess them. ' +
      'Obtain the mapping from the /build starter prompt or a dashboard ' +
      'practice example, then wire it into src/input-map.js.',
    );
  }
  const { proof, publicSignals } = await groth16.fullProve(inputSignals, WASM, ZKEY);
  return { proof, publicSignals };
}

// ---- Kurier (opt-in; only active when KURIER_API_KEY is set) ----
// Testnet base is documented (docs.zkverify.io): https://api-testnet.kurier.xyz/api/v1
// Mainnet base URL is NOT verified — never guess it; set KURIER_API_URL
// explicitly when a mainnet key is issued.

function kurierBase() {
  const url = (process.env.KURIER_API_URL || 'https://api-testnet.kurier.xyz/api/v1').replace(/\/$/, '');
  const key = process.env.KURIER_API_KEY;
  if (!key) throw new Error('KURIER_API_KEY is not set — Kurier submission is disabled');
  return { url, key };
}

export async function kurierRegisterVk() {
  const { url, key } = kurierBase();
  const vk = await loadVk();
  const res = await fetch(`${url}/register-vk/${key}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ proofType: 'groth16', proofOptions: { library: 'snarkjs', curve: 'bn128' }, vk }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`kurier register-vk failed: HTTP ${res.status} ${JSON.stringify(data).slice(0, 300)}`);
  return data; // expected: { vkHash, ... } — confirm it equals the registered gatekeeper vkHash
}

export async function kurierSubmitProof({ proof, publicSignals, vkHash, chainId = 0 }) {
  const { url, key } = kurierBase();
  const res = await fetch(`${url}/submit-proof/${key}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      proofType: 'groth16',
      vkRegistered: true,
      chainId,
      proofData: { proof, publicSignals, vk: vkHash },
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`kurier submit-proof failed: HTTP ${res.status} ${JSON.stringify(data).slice(0, 300)}`);
  return data; // expected: { jobId, ... }
}

export async function kurierJobStatus(jobId, { tries = 20, delayMs = 3000 } = {}) {
  const { url, key } = kurierBase();
  for (let i = 0; i < tries; i++) {
    const res = await fetch(`${url}/job-status/${key}/${jobId}`);
    const data = await res.json().catch(() => ({}));
    if (data.status === 'Finalized') return data;
    if (data.status === 'Failed' || !res.ok) return data;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return { status: 'Timeout', jobId };
}
