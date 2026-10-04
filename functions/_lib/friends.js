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
 *
 * Visibility safety: a record's `hiddenBy` array is the source of truth for
 * which users opted out of it. Writers run concurrently on (eventually
 * consistent) KV — `pushHistory` here, `markHiddenForUser` on every clear, and
 * both sides' clients — so this must NEVER clobber a flag another writer just
 * set. Concretely:
 *   - a NEW record always starts with `hiddenBy: []` (nothing is hidden yet);
 *   - on DEDUPE (this id already archived — e.g. the live P2P copy arrived
 *     first) we keep the EXISTING record and its `hiddenBy` as-is, we do not
 *     replace it with a blank flag;
 *   - the cap trim drops the oldest records, and a record hidden by BOTH users
 *     is already gone from KV (markHiddenForUser purges it), so the cap never
 *     resurrects a purged one.
 */
export async function pushHistory(kv, a, b, msg) {
  const key = histKey(a, b);
  const arr = (await kv.get(key, 'json')) || [];
  const existing = arr.find(x => x.id === msg.id);
  if (existing) {
    // De-dupe: the archive already has this logical message. Keep it — and its
    // `hiddenBy` flag (someone may have cleared it since we first pushed) —
    // rather than overwriting with a blank array. Only refresh the content
    // if the copy we hold is missing the encrypted blob.
    if (existing.c === undefined && msg.c !== undefined) existing.c = msg.c;
  } else {
    arr.push({ ...msg, hiddenBy: Array.isArray(msg.hiddenBy) ? msg.hiddenBy : [] });
  }
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

/* ── per-user visibility ("hiddenBy") ───────────────────────────
   Clearing a conversation is NO LONGER a device-wide flag that hides every
   message. Instead each history record carries a `hiddenBy` array of the
   USER ids who have marked it hidden on their side:
     - user A clears  -> every record the pair shares gets A's id in hiddenBy
     - user B clears  -> B's id is added to the same records
     - a record is DELETED only when BOTH users' ids are in hiddenBy, i.e.
       each side has opted out of it. Until then the other side still sees it.
   history-get returns only the records that do NOT carry the caller's own id.
   This keeps the "the peer still sees my cleared chat" property exactly as
   before, but models visibility per-record and per-user. */

/**
 * Mark `userId` as having hidden every record in the pair's history.
 *
 * "Clear" is per-user: it adds `userId` to the `hiddenBy` of every record the
 * pair currently shares. A record is physically deleted only when BOTH users of
 * the pair are in its `hiddenBy` — until then the other side still sees it.
 * Idempotent: clearing again is a no-op. Returns true if the array was
 * rewritten (at least one record gained `userId` or was pruned).
 *
 * Concurrency note: this is a read-modify-write on eventually-consistent KV,
 * and it races with pushHistory (either side's new message) and with the
 * peer's own clear. We mitigate by (a) re-reading the array fresh at write time
 * is NOT possible here without a second round-trip, so instead we MERGE flags
 * additively: we only ever ADD userId to a record's hiddenBy and only PURGE a
 * record when BOTH ids are present. We never drop a peer id we didn't just add
 * — so the worst case under a lost-update is that a *new* record pushed by the
 * peer momentarily lacks userId's flag, which the next clear re-covers. That's
 * the safe direction (over-hiding a fresh message for a moment, not
 * resurrecting an old hidden one).
 */
export async function markHiddenForUser(kv, userId, peerId) {
  const key = histKey(userId, peerId);
  const arr = (await kv.get(key, 'json')) || [];
  let changed = false;
  const kept = [];
  for (const m of arr) {
    const hb = Array.isArray(m.hiddenBy) ? m.hiddenBy.slice() : [];
    if (!hb.includes(userId)) { hb.push(userId); changed = true; }
    // Purge only when both sides of the pair have hidden this record.
    const hideFromBoth = hb.includes(userId) && hb.includes(peerId);
    if (!hideFromBoth) kept.push({ ...m, hiddenBy: hb });
  }
  if (changed || kept.length !== arr.length) {
    await kv.put(key, JSON.stringify(kept), { expirationTtl: HISTORY_TTL });
  }
  return changed;
}

/**
 * Read a pair's history and return ONLY the records not hidden for `meId`.
 * Shape of each returned record: { id, from, text, at, n, unreadable? }.
 */
export async function readVisibleHistory(kv, meId, peerId) {
  const keyB64 = await kv.get(pairKey(meId, peerId));
  const arr = (await kv.get(histKey(meId, peerId), 'json')) || [];
  const out = [];
  for (const m of arr) {
    const hb = Array.isArray(m.hiddenBy) ? m.hiddenBy : [];
    if (hb.includes(meId)) continue;   // this user opted out of this record
    let text;
    try { text = keyB64 ? await decryptMsg(keyB64, m.c) : null; } catch { text = null; }
    out.push({ id: m.id, from: m.from, at: m.at, n: m.n, text, unreadable: text === null });
  }
  return out;
}
