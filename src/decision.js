// Proof Gatekeeper — decision engine (pure, no I/O).
// Source of truth: https://agentgames.zkverify.io/events/proof-gatekeeper
// Sample task payload fields (input.*):
//   registered_vk, proof_vk, minimum, public_balance,
//   expiry_block, current_block, recipient, condition_recipient,
//   amount, max_transfer, proof_tx
// Response: { decision: "APPROVE"|"REJECT", reason_code, proof_tx }
//
// Trap priority (each platform task carries exactly one trap, so order
// only matters if a task is malformed on several fields at once):
//   PROOF_REUSED > VK_SUBSTITUTION > EXPIRED_CONDITION >
//   RECIPIENT_MISMATCH > AMOUNT_OVERFLOW > THRESHOLD_MISMATCH
// Fail-closed: any missing/unparseable field => REJECT with reason
// MALFORMED_TASK (never APPROVE on uncertainty: wrong approve -6
// costs more than wrong reject -3).

export const REASON_CODES = [
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

/**
 * Decide a gatekeeper task.
 * @param {object} input - the task's `input` object
 * @param {object} opts
 * @param {(proofTx: string) => boolean} opts.isReuse - true if proof_tx seen before
 * @param {boolean} [opts.proofOnChain] - result of on-chain confirmation; undefined = not checked
 * @returns {{decision: 'APPROVE'|'REJECT', reason_code: string, checks: object}}
 */
export function decide(input, opts = {}) {
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

    // 1. Reuse — a proof reference already accepted in a previous task.
    checks.reuse = opts.isReuse ? opts.isReuse(proof_tx) : false;
    if (checks.reuse) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED', checks };
    }

    // 2. VK substitution — proof valid under a different key than the condition's.
    checks.vkMatch = normHex(registered_vk) === normHex(proof_vk);
    if (!checks.vkMatch) {
      return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', checks };
    }

    // 3. Expiry — condition's block-height window has passed.
    checks.expired = currentBlock > expiryBlock;
    if (checks.expired) {
      return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', checks };
    }

    // 4. Recipient — payment would go to the wrong party.
    checks.recipientMatch = recipient === conditionRecipient;
    if (!checks.recipientMatch) {
      return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', checks };
    }

    // 5. Amount — requested payment exceeds the single-transfer cap.
    checks.amountOk = amount <= maxTransfer;
    if (!checks.amountOk) {
      return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', checks };
    }

    // 6. Threshold — public balance below the condition's minimum.
    checks.thresholdOk = publicBalance >= minimum;
    if (!checks.thresholdOk) {
      return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', checks };
    }

    // 7. On-chain confirmation (when available). A task whose proof_tx
    //    cannot be found on zkVerify is not a documented trap variety,
    //    but approving a proof that does not exist would be approving
    //    nothing — fail closed.
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
