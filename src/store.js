// Seen-proof registry (PROOF_REUSED detection).
// The trap text says a proof reference counts as reused once it was
// "already accepted in a previous task" — so a proof_tx is recorded
// ONLY when a task using it is APPROVED. A rejected task does not
// burn its proof reference.
// In-memory Map is the source of truth; a JSON snapshot on disk is a
// best-effort convenience (a restart resets the registry — acceptable
// for a practice scaffold; a scored deployment should back this with
// durable storage shared across instances).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DATA_FILE = process.env.SEEN_FILE
  || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'data', 'seen.json');

const seen = new Set();
const taskResponses = new Map(); // task_id -> response (idempotency)

export function loadFromDisk() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) for (const tx of arr) if (typeof tx === 'string') seen.add(tx);
  } catch {
    // No snapshot yet, or unreadable — start empty. Not fatal.
  }
  return seen.size;
}

export function saveToDisk() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify([...seen], null, 2));
    return true;
  } catch (err) {
    console.warn('[store] snapshot write failed (continuing in-memory):', err.message);
    return false;
  }
}

export function hasSeen(proofTx) {
  return seen.has(proofTx);
}

export function markSeen(proofTx) {
  seen.add(proofTx);
  saveToDisk();
}

export function seenCount() {
  return seen.size;
}

export function cachedResponse(taskId) {
  return taskResponses.get(taskId);
}

export function cacheResponse(taskId, response) {
  taskResponses.set(taskId, response);
  if (taskResponses.size > 10000) {
    const first = taskResponses.keys().next().value;
    taskResponses.delete(first);
  }
}
