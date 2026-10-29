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
 *  clr:<U>:<P>      (directional) -> JSON { ids:[msgId] }
 *     The ACCOUNT-level "cleared" ledger: ids of the messages user U has cleared
 *     in the chat with P. Written ONLY by U's own clear, but shared by ALL of U's
 *     devices, so a clear on any one device hides the message on every device.
 *     A message is destroyed from hist when its id is in BOTH users' ledgers.
 *  hist:<A>:<B>     (A < B)  ->  JSON array
 *     [{ id, from, c (base64url GCM blob), at,
 *        hiddenBy:[u] (legacy, still honoured), seenBy:[u], readBy:[u],
 *        recalled?:true, recalledAt? }]
 *     A RECALLED record is a tombstone: `c` is deleted (the ciphertext is gone
 *     from KV), the id/from/at stay so the peer's devices learn about the recall.
 *     c = { v:1, iv, ct, tag } base64url, one record per message (capped)
 *     seenBy/readBy = durable receipts
 *     (readBy ⊇ seenBy), written only by the message's RECEIVER.
 *
 * Live P2P is NOT in KV: the real-time path is a WebRTC DataChannel between the
 * two logged-in devices (DTLS-encrypted). The AES here is what makes the *persisted*
 * history safe at rest and recoverable on a new device. See "Known limits" in README.
 */

// How long after sending a message its author may still recall it. The client
// has the same constant (RECALL_WINDOW_MS in index.html); the server adds a
// small grace so clock skew can't reject a recall the UI still offered.
export const RECALL_WINDOW_MS = 10 * 60 * 1000;
export const RECALL_GRACE_MS = 15 * 1000;

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
  // metadata is not per-user hidden (clear conversation doesn't touch it);
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
 *   - a NEW record always starts with `seenBy:[], readBy:[]`;
 *   - `readBy` is a strict superset of `seenBy` (read implies seen);
 *   - on DEDUPE we keep the EXISTING record and ALL its flags as-is;
 *   - the cap trim drops the oldest records, and a record hidden by BOTH users
 *     is already gone from KV (markHiddenForUser purges it).
 * The sender never writes readBy/seenBy — it only READS the peer's membership
 * (see readVisibleHistory) to compute the tick.
 */

/* ── account-level "cleared" ledger ─────────────────────────────
   Clearing is a property of the ACCOUNT, not of a device or of a single
   record's flags:
     - user A clears (on any device)  -> A's ledger gains those message ids; A
       no longer sees them on ANY of A's devices.
     - user B clears the same ids too -> the ids are in both ledgers, so the
       message is DESTROYED from KV.
   The ledger keeps the ids even after the record is destroyed, so a stale
   device that still holds a copy can learn it is gone, and a late duplicate
   push can't resurrect it. Ids (not timestamps) are used on purpose: the same
   message carries the sender's clock over P2P and the server's clock in KV. */
export const clearKey = (owner, peer) => `clr:${owner}:${peer}`;
export const CLEARED_CAP = 600;   // newest N cleared ids remembered per user per chat

export async function readCleared(kv, owner, peer) {
  const v = await kv.get(clearKey(owner, peer), 'json');
  return Array.isArray(v?.ids) ? v.ids.filter(x => typeof x === 'string') : [];
}

/** { [a]: Set, [b]: Set } of cleared ids for both users of a pair. */
async function loadCleared(kv, a, b) {
  const [ca, cb] = await Promise.all([readCleared(kv, a, b), readCleared(kv, b, a)]);
  return { [a]: new Set(ca), [b]: new Set(cb) };
}

/** Has `uid` cleared this record? (ledger, or the legacy per-record hiddenBy) */
function isHiddenFor(m, uid, cleared) {
  return !!cleared[uid]?.has(m.id) || (Array.isArray(m.hiddenBy) && m.hiddenBy.includes(uid));
}

/** Destroyed = cleared by BOTH accounts of the pair. */
function isPurged(m, a, b, cleared) {
  return isHiddenFor(m, a, cleared) && isHiddenFor(m, b, cleared);
}

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
  if (Array.isArray(m.hiddenBy)) m.hiddenBy = uniq(m.hiddenBy);   // legacy field: keep, never write new
  m.seenBy = uniq([...(Array.isArray(m.seenBy) ? m.seenBy : []), ...addSeen]);
  m.readBy = uniq([...(Array.isArray(m.readBy) ? m.readBy : []), ...addRead]);
  // read implies seen: anything read must also be seen.
  m.seenBy = uniq([...m.seenBy, ...m.readBy]);
  return m;
}

export async function pushHistory(kv, a, b, msg) {
  const key = histKey(a, b);
  const [arr0, cleared] = await Promise.all([kv.get(key, 'json'), loadCleared(kv, a, b)]);
  const arr = arr0 || [];
  const existing = arr.find(x => x.id === msg.id);
  if (existing) {
    // De-dupe: the archive already has this logical message. Keep it — and all
    // of its receipt/hidden flags (an ack or clear may have landed since we
    // first pushed) — rather than overwriting them with blank arrays. Only
    // refresh the content if the copy we hold is missing the encrypted blob.
    // A recalled tombstone must never be resurrected by a late/duplicate push.
    if (!existing.recalled && existing.c === undefined && msg.c !== undefined) existing.c = msg.c;
    withFlags(existing);   // normalize (backfill seenBy/readBy on old records)
  } else {
    // A message both accounts already cleared is destroyed for good: a late or
    // duplicate push must not bring it back.
    if (isPurged({ id: msg.id }, a, b, cleared)) return arr.filter(m => !isPurged(m, a, b, cleared));
    const rec = { id: msg.id, from: msg.from, c: msg.c, at: msg.at };
    withFlags(rec, {});   // -> seenBy/readBy []
    arr.push(rec);
  }
  // newest last; cap from the front; drop records both accounts cleared.
  while (arr.length > HISTORY_CAP) arr.shift();
  const kept = arr.filter(m => !isPurged(m, a, b, cleared));
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
    if (m.recalled) text = '';   // tombstone: nothing to decrypt, and nothing to show
    else { try { text = keyB64 ? await decryptMsg(keyB64, m.c) : null; } catch { text = null; } }
    out.push({
      id: m.id, from: m.from, at: m.at, text, unreadable: text === null,
      recalled: !!m.recalled,
      // Did *I* (the caller) already see/read a record the peer sent me? Lets a
      // fresh device restore "read" locally instead of re-acknowledging it.
      mineSeen: m.from === peerId && (Array.isArray(m.seenBy) ? m.seenBy : []).includes(meId),
      mineRead: m.from === peerId && (Array.isArray(m.readBy) ? m.readBy : []).includes(meId),
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

/* ── clear (per ACCOUNT, across all of its devices) ────────────
   POST /api/friends/clear adds the ids the clearing device was showing to the
   caller's ledger (clr:<me>:<peer>). Because the ledger belongs to the account,
   every other device logged in to the same account drops those messages on its
   next history poll. A record is physically DELETED from hist only when BOTH
   accounts have cleared it; until then the other account still sees it. */

/**
 * Mark message ids as cleared by `userId` in the chat with `peerId`.
 *
 * `ids` = what the clearing device was showing (this also covers messages that
 * never reached KV, e.g. file messages, so the account's OTHER devices drop
 * them too). If no ids are supplied (an older client), every record currently
 * in the pair's history is cleared.
 *
 * Ordering is crash-safe: the ledger is written FIRST (worst case afterwards:
 * hidden but not yet deleted), then records now cleared by both accounts are
 * destroyed. Idempotent. Returns { cleared:[ids], added, purged }.
 */
export async function markHiddenForUser(kv, userId, peerId, ids) {
  const key = histKey(userId, peerId);
  const [arr, mine, theirs] = await Promise.all([
    kv.get(key, 'json').then(v => v || []),
    readCleared(kv, userId, peerId),
    readCleared(kv, peerId, userId),
  ]);
  const want = Array.isArray(ids) && ids.length ? ids : arr.map(m => m.id);
  const set = new Set(mine);
  let added = 0;
  for (const id of want) if (!set.has(id)) { set.add(id); added++; }
  const ledger = Array.from(set).slice(-CLEARED_CAP);   // Set keeps insertion order -> keep the newest
  if (added || ledger.length !== mine.length) {
    await kv.put(clearKey(userId, peerId), JSON.stringify({ ids: ledger }), { expirationTtl: HISTORY_TTL });
  }
  // Destroy what BOTH accounts have now cleared.
  const cleared = { [userId]: new Set(ledger), [peerId]: new Set(theirs) };
  const kept = arr.filter(m => !isPurged(m, userId, peerId, cleared));
  const purged = arr.length - kept.length;
  if (purged) await kv.put(key, JSON.stringify(kept), { expirationTtl: HISTORY_TTL });
  return { cleared: ledger, added, purged };
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
  const mine = { [meId]: new Set(await readCleared(kv, meId, peerId)) };
  const out = [];
  for (const m of arr) {
    if (isHiddenFor(m, meId, mine)) continue;   // my ACCOUNT cleared it (on any device)
    let text;
    if (m.recalled) text = '';   // tombstone: nothing to decrypt, and nothing to show
    else { try { text = keyB64 ? await decryptMsg(keyB64, m.c) : null; } catch { text = null; } }
    out.push({
      id: m.id, from: m.from, at: m.at, text, unreadable: text === null,
      recalled: !!m.recalled,
      // Did *I* (the caller) already see/read a record the peer sent me? Lets a
      // fresh device restore "read" locally instead of re-acknowledging it.
      mineSeen: m.from === peerId && (Array.isArray(m.seenBy) ? m.seenBy : []).includes(meId),
      mineRead: m.from === peerId && (Array.isArray(m.readBy) ? m.readBy : []).includes(meId),
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

/* ── recall ─────────────────────────────────────────────────────
   The AUTHOR of a message can retract it within RECALL_WINDOW_MS. Recalling:
     - deletes the encrypted content from KV (the record becomes a tombstone),
     - keeps { id, from, at, recalled:true } so the peer's devices — which may be
       offline right now — learn about it on their next history poll,
     - never resurrects: pushHistory ignores late copies of a recalled id.
   A tombstone is also created for an id KV has not seen yet (the archive write
   can lose a race with the recall, and file messages are never archived at all),
   so the peer still gets told.
   Returns { ok:true, tombstoned } | { ok:false, code } with code one of
   'forbidden' (not your message) | 'too_late'. */
export async function recallMessage(kv, userId, peerId, id, atHint) {
  const key = histKey(userId, peerId);
  const [arr0, cleared] = await Promise.all([kv.get(key, 'json'), loadCleared(kv, userId, peerId)]);
  const arr = arr0 || [];
  const now = Date.now();
  let rec = arr.find(x => x.id === id);
  if (rec) {
    if (rec.from !== userId) return { ok: false, code: 'forbidden' };
    if (!rec.recalled && now - rec.at > RECALL_WINDOW_MS + RECALL_GRACE_MS) return { ok: false, code: 'too_late' };
    if (rec.recalled) return { ok: true, tombstoned: false };   // idempotent
    delete rec.c;
    rec.recalled = true; rec.recalledAt = now;
    withFlags(rec);
  } else {
    // Unknown id: trust the author's timestamp only inside a sane range.
    const at = Number.isFinite(atHint) && atHint <= now && atHint > now - 30 * 864e5 ? atHint : now;
    if (now - at > RECALL_WINDOW_MS + RECALL_GRACE_MS) return { ok: false, code: 'too_late' };
    rec = { id, from: userId, at, recalled: true, recalledAt: now };
    withFlags(rec);
    arr.push(rec);
    arr.sort((a, b) => a.at - b.at);
  }
  while (arr.length > HISTORY_CAP) arr.shift();
  const kept = arr.filter(m => !isPurged(m, userId, peerId, cleared));
  await kv.put(key, JSON.stringify(kept), { expirationTtl: HISTORY_TTL });
  return { ok: true, tombstoned: true };
}

/** Remove one attachment's metadata record (used when a file message is recalled). */
export async function dropFileMeta(kv, a, b, fileId) {
  const key = filesKey(a, b);
  const arr = (await kv.get(key, 'json')) || [];
  const next = arr.filter(x => x.fileId !== fileId);
  if (next.length !== arr.length) await kv.put(key, JSON.stringify(next), { expirationTtl: HISTORY_TTL });
  return next.length !== arr.length;
}
