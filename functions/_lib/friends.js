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
 *  hist:<A>:<B>     (A < B)  ->  JSON array
 *     [{ id, from, c (base64url GCM blob), at,
 *        hiddenBy:[u], seenBy:[u], readBy:[u] }]
 *     c = { v:1, iv, ct, tag } base64url, one record per message (capped)
 *     hiddenBy = users who cleared it; seenBy/readBy = durable receipts
 *     (readBy ⊇ seenBy), written only by the message's RECEIVER.
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
// File attachment METADATA only (name/type/size/fileId/at, no content).
// Content streams live over P2P; this record is what makes a previously-sent
// file reappear as a placeholder in the shared-files list on a new device.
export const filesKey = (a, b) => `files:${pair(a, b).join(':')}`;

/**
 * Append one file-metadata record to the pair's file list (deduped by fileId,
 * capped like history). Called by BOTH sides on send/receive so the metadata
 * survives a device change. Content is NEVER written here.
 */
export const FILES_CAP = 100;
export async function pushFileMeta(kv, a, b, meta) {
  const key = filesKey(a, b);
  const arr = (await kv.get(key, 'json')) || [];
  const i = arr.findIndex(x => x.fileId === meta.fileId);
  const rec = {
    fileId: meta.fileId,
    name: String(meta.name || 'file').slice(0, 200),
    type: String(meta.type || '').slice(0, 100),
    size: Number.isFinite(meta.size) ? meta.size : 0,
    at: meta.at || Date.now(),
    // 'sending' | 'sent' | 'received' — set by the sender on send, receiver on
    // completion. Drives the placeholder's icon state in the shared-files list.
    status: ['sending', 'sent', 'received'].includes(meta.status) ? meta.status : 'sending',
  };
  if (i >= 0) arr[i] = { ...arr[i], ...rec }; else arr.push(rec);
  while (arr.length > FILES_CAP) arr.shift();
  await kv.put(key, JSON.stringify(arr), { expirationTtl: HISTORY_TTL });
  return arr;
}

/** Read the pair's file-metadata list, filtered to records not hidden for me. */
export async function readFileMeta(kv, meId, peerId) {
  const arr = (await kv.get(filesKey(meId, peerId), 'json')) || [];
  // metadata has no per-user hiddenBy (clear conversation doesn't touch it);
  // return oldest->newest.
  return arr;
}

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
 * Receipt safety: a record's `readBy` / `seenBy` arrays are the durable read
 * state. Both are owned and written ONLY by the *receiver* of the message (via
 * markAckForUser), and are monotonically-additive user-id sets. Writers run
 * concurrently on (eventually consistent) KV — `pushHistory` here,
 * `markHiddenForUser` on every clear, `markAckForUser` on every read/delivered
 * ack, and both sides' clients — so all three NEVER clobber a flag another
 * writer just set. Concretely:
 *   - a NEW record always starts with `hiddenBy:[], seenBy:[], readBy:[]`;
 *   - `readBy` is a strict superset of `seenBy` (read implies seen);
 *   - on DEDUPE we keep the EXISTING record and ALL its flags as-is;
 *   - the cap trim drops the oldest records, and a record hidden by BOTH users
 *     is already gone from KV (markHiddenForUser purges it).
 * The sender never writes readBy/seenBy — it only READS the peer's membership
 * (see readVisibleHistory) to compute the tick.
 */

/* De-dupe preserving order. */
const uniq = ids => Array.from(new Set(ids));

/**
 * Normalize + merge the per-record receipt flags additively. Guarantees all
 * three arrays exist (empty on old records) and that "read implies seen".
 * Shared by pushHistory / markHiddenForUser / markAckForUser so they can't
 * drift. In-place on `m`'s flag fields; returns `m`.
 */
function withFlags(m, { addSeen = [], addRead = [] } = {}) {
  // Ensure all three flag arrays exist (old records may lack seenBy/readBy)
  // and merge the new ids in additively.
  m.hiddenBy = uniq([...(Array.isArray(m.hiddenBy) ? m.hiddenBy : [])]);
  m.seenBy = uniq([...(Array.isArray(m.seenBy) ? m.seenBy : []), ...addSeen]);
  m.readBy = uniq([...(Array.isArray(m.readBy) ? m.readBy : []), ...addRead]);
  // read implies seen: anything read must also be seen.
  m.seenBy = uniq([...m.seenBy, ...m.readBy]);
  return m;
}

/** A record purges only when BOTH users of the pair have hidden it. */
function isPurged(m, a, b) {
  const hb = Array.isArray(m.hiddenBy) ? m.hiddenBy : [];
  return hb.includes(a) && hb.includes(b);
}

export async function pushHistory(kv, a, b, msg) {
  const key = histKey(a, b);
  const arr = (await kv.get(key, 'json')) || [];
  const existing = arr.find(x => x.id === msg.id);
  if (existing) {
    // De-dupe: the archive already has this logical message. Keep it — and all
    // of its receipt/hidden flags (an ack or clear may have landed since we
    // first pushed) — rather than overwriting them with blank arrays. Only
    // refresh the content if the copy we hold is missing the encrypted blob.
    if (existing.c === undefined && msg.c !== undefined) existing.c = msg.c;
    withFlags(existing);   // normalize (backfill seenBy/readBy on old records)
  } else {
    const rec = { id: msg.id, from: msg.from, c: msg.c, at: msg.at };
    withFlags(rec, {});   // -> hiddenBy/seenBy/readBy all []
    arr.push(rec);
  }
  // newest last; cap from the front; drop both-hidden records.
  while (arr.length > HISTORY_CAP) arr.shift();
  const kept = arr.filter(m => !isPurged(m, a, b));
  await kv.put(key, JSON.stringify(kept), { expirationTtl: HISTORY_TTL });
  return kept;
}

/**
 * Read a pair's history and decrypt it for the given me/peer pair.
 * Returns [{ id, from, at, text, seen, read, unreadable? }] oldest->newest,
 * where `seen`/`read` are resolved against `peerId` (the other side): for a
 * record with from === peerId they report whether that peer has seen/read it.
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
    out.push({
      id: m.id, from: m.from, at: m.at, text, unreadable: text === null,
      // Did the PEER see/read a record the peer SENT (from === peerId)? The
      // receiver-side ack of the peer's own message.
      seen: m.from === peerId && (Array.isArray(m.seenBy) ? m.seenBy : []).includes(peerId),
      read: m.from === peerId && (Array.isArray(m.readBy) ? m.readBy : []).includes(peerId),
      // Did the PEER see/read a record I SENT (from === meId)? The tick state
      // of MY outgoing message — what the sender's UI restores across refresh.
      peerSeen: m.from === meId && (Array.isArray(m.seenBy) ? m.seenBy : []).includes(peerId),
      peerRead: m.from === meId && (Array.isArray(m.readBy) ? m.readBy : []).includes(peerId),
    });
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
    if (hideFromBoth) continue;
    // Write the merged hiddenBy back onto the record, then preserve the
    // receipt flags through the rewrite (withFlags is additive + "read
    // implies seen", and backfills seenBy/readBy on old records).
    m.hiddenBy = hb;
    withFlags(m);
    kept.push(m);
  }
  if (changed || kept.length !== arr.length) {
    await kv.put(key, JSON.stringify(kept), { expirationTtl: HISTORY_TTL });
  }
  return changed;
}

/**
 * Record a receipt from `userId` for a set of message ids in the pair's
 * history. `kind` is 'seen' (delivered) or 'read' (actually viewed; a read
 * also counts as seen). Only the RECEIVER writes these flags; the sender
 * later reads the peer's membership (readVisibleHistory) to flip the tick.
 *
 * Additive + idempotent: re-acking is a no-op, and unknown ids are ignored
 * (a stale/early ack that raced a not-yet-archived record just gets re-sent
 * on the next poll, so it self-heals). Returns true if the array was rewritten.
 */
export async function markAckForUser(kv, userId, peerId, ids, kind) {
  const key = histKey(userId, peerId);
  const arr = (await kv.get(key, 'json')) || [];
  const want = new Set(ids);
  let changed = false;
  for (const m of arr) {
    if (!want.has(m.id)) continue;
    if (kind === 'read') {
      const read = Array.isArray(m.readBy) ? m.readBy : [];
      if (!read.includes(userId)) { read.push(userId); changed = true; }
      withFlags(m, { addSeen: [userId], addRead: [userId] });
    } else {
      const seen = Array.isArray(m.seenBy) ? m.seenBy : [];
      if (!seen.includes(userId)) { seen.push(userId); changed = true; }
      withFlags(m, { addSeen: [userId] });
    }
  }
  if (changed) {
    await kv.put(key, JSON.stringify(arr), { expirationTtl: HISTORY_TTL });
  }
  return changed;
}

/**
 * Read a pair's history and return ONLY the records not hidden for `meId`.
 * Each returned record also carries `seen`/`read` booleans resolved against
 * `peerId` (the other side): for a record where from === peerId, they report
 * whether that peer has seen/read it. This is what the sender's client uses
 * to restore ticks durably across refresh / device change.
 * Shape of each returned record: { id, from, at, text, seen, read, unreadable? }.
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
    out.push({
      id: m.id, from: m.from, at: m.at, text, unreadable: text === null,
      // Did the PEER see/read a record the peer SENT (from === peerId)? The
      // receiver-side ack of the peer's own message.
      seen: m.from === peerId && (Array.isArray(m.seenBy) ? m.seenBy : []).includes(peerId),
      read: m.from === peerId && (Array.isArray(m.readBy) ? m.readBy : []).includes(peerId),
      // Did the PEER see/read a record I SENT (from === meId)? The tick state
      // of MY outgoing message — what the sender's UI restores across refresh.
      peerSeen: m.from === meId && (Array.isArray(m.seenBy) ? m.seenBy : []).includes(peerId),
      peerRead: m.from === meId && (Array.isArray(m.readBy) ? m.readBy : []).includes(peerId),
    });
  }
  return out;
}
