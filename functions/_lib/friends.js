/**
 * Friendship + encrypted-history helpers.
 *
 * The two users in a pair are always stored in "canonical" order so A->B and B->A
 * resolve to the same key. All message content that touches KV is AES-256-GCM
 * encrypted with a per-pair symmetric key, so a KV dump is unreadable.
 *
 * KV keys (binding: WORM_HOLE)
 * ─────────────────────────────────────────────────────────────────────────────
 *  friend:<A>:<B>   (A < B)  ->  JSON { status:"pending"|"friend", by, at }
 *  pairkey:<A>:<B>  (A < B)  ->  JSON { k }   (k = base64url 32-byte AES key)
 *  hist:<A>:<B>     (A < B)  ->  JSON array [{ id, from, c (base64url GCM blob), at, n }]
 *     where c = { v:1, iv, ct, tag } base64url, one record per message (capped)
 *
 * Live P2P is NOT in KV: the real-time path is a WebRTC DataChannel between the
 * two logged-in devices (DTLS-encrypted). The AES here is what makes the *persisted*
 * history safe at rest and recoverable on a new device. See "Known limits" in README.
 */

export const HISTORY_CAP = 200;          // last N messages kept per pair in KV
export const HISTORY_TTL = 60 * 60 * 24 * 365 * 10; // keep history long-term; KV TTL is a hint

/**
 * Maintain a per-user index of the peers they have a relation with (friend or
 * pending), so list endpoints don't have to scan KV.
 *   idx:<uid> -> JSON array of peer uids
 * Adds each of `a` and `b` to the other's index (idempotent).
 */
export async function indexPair(kv, a, b) {
  const jobs = [[a, b], [b, a]]; // [owner, peer]
  for (const [owner, p] of jobs) {
    const key = `idx:${owner}`;
    const arr = (await kv.get(key, 'json')) || [];
    if (!arr.includes(p)) arr.push(p);
    await kv.put(key, JSON.stringify(arr));
  }
}

/* ── canonical pair ordering ───────────────────────────────────── */

/** [low, high] so that both callers build the identical key. */
export function pair(a, b) {
  const x = String(a), y = String(b);
  return x < y ? [x, y] : [y, x];
}
export const friendKey = (a, b) => `friend:${pair(a, b).join(':')}`;
export const pairKey = (a, b) => `pairkey:${pair(a, b).join(':')}`;
export const histKey = (a, b) => `hist:${pair(a, b).join(':')}`;

/* ── crypto ────────────────────────────────────────────────────── */

const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

/** Generate the pair's 32-byte AES-256 key, base64url-encoded. */
export function genPairKey() {
  return b64u(crypto.getRandomValues(new Uint8Array(32)));
}

async function importKey(k) {
  return crypto.subtle.importKey('raw', fromB64u(k), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * Encrypt a message for the pair. Returns a base64url blob whose decoded bytes are:
 *   [ 12-byte IV ][ ciphertext+tag ]
 * The 12-byte IV is prepended so a single base64u string is self-describing.
 */
export async function encryptMsg(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyObj = await importKey(key);
  const aad = new TextEncoder().encode('wh-msg');
  const ctTag = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, keyObj, new TextEncoder().encode(text)));
  const out = new Uint8Array(12 + ctTag.length);
  out.set(iv, 0);
  out.set(ctTag, 12);
  return b64u(out);
}

/** Decrypt a blob produced by encryptMsg. Throws on tamper (GCM auth fails). */
export async function decryptMsg(key, blob) {
  const raw = fromB64u(blob);
  const iv = raw.subarray(0, 12);
  const ctTag = raw.subarray(12);
  const keyObj = await importKey(key);
  const aad = new TextEncoder().encode('wh-msg');
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, keyObj, ctTag);
  return new TextDecoder().decode(pt);
}

/**
 * Persist one message to the pair's history. Keeps only the newest HISTORY_CAP
 * entries, de-duplicates by id, and marks each record with its sender (`from`).
 * `kv` = the WORM_HOLE binding.
 */
export async function pushHistory(kv, a, b, msg) {
  const key = histKey(a, b);
  const arr = (await kv.get(key, 'json')) || [];
  if (!arr.some(x => x.id === msg.id)) arr.push(msg);
  // newest last; cap from the front
  while (arr.length > HISTORY_CAP) arr.shift();
  await kv.put(key, JSON.stringify(arr), { expirationTtl: HISTORY_TTL });
  return arr;
}

/**
 * Read a pair's history and decrypt it for the given me/peer pair.
 * Returns [{ id, from, text, at, n, unreadable? }] oldest->newest.
 * Records the caller can't decrypt (e.g. pair key rotated / corrupted) are
 * kept with unreadable:true rather than dropped, so the UI can show a placeholder.
 */
export async function readHistory(kv, meId, peerId) {
  const keyB64 = await kv.get(pairKey(meId, peerId));
  const arr = (await kv.get(histKey(meId, peerId), 'json')) || [];
  const out = [];
  for (const m of arr) {
    let text;
    try { text = keyB64 ? await decryptMsg(keyB64, m.c) : null; } catch { text = null; }
    out.push({ id: m.id, from: m.from, at: m.at, n: m.n, text, unreadable: text === null });
  }
  return out;
}
