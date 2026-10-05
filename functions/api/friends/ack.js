/**
 * POST /api/friends/ack   Body: { uuid, kind: 'read'|'seen', ids: string[] }
 * 200 { ok, updated }
 *
 * Durable read-receipt write. The *receiver* of a message records their own
 * user id on each record's `seenBy` (delivered) and/or `readBy` (actually
 * viewed) arrays. The *sender* later reads the peer's membership via
 * history-get to flip their tick — so the receipt survives a down P2P channel
 * and a refresh, which is the whole point of persisting it in KV.
 *
 *   kind: 'seen' -> caller's id added to `seenBy` of each id (delivered tick)
 *   kind: 'read' -> caller's id added to `readBy` of each id, and implied into
 *                   `seenBy` (read ⊇ seen, so a read always covers delivered)
 *
 * Idempotent + additive: re-acking is a no-op, and unknown ids (an ack that
 * raced a not-yet-archived message) are silently ignored — the client
 * re-sends on the next poll so nothing gets stuck.
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { friendKey, markAckForUser } from '../../_lib/friends.js';

const MAX_IDS = 50; // keep a single call bounded; the client batches to this.

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  const kind = body?.kind === 'read' ? 'read' : 'seen';
  const ids = Array.isArray(body?.ids)
    ? body.ids.filter(x => typeof x === 'string' && x.length <= 64).slice(0, MAX_IDS)
    : [];
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');
  if (!ids.length) return json({ ok: true, updated: 0 });

  // Only friends (accepted) have history to acknowledge.
  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  const updated = await markAckForUser(env.WORM_HOLE, me.id, uuid, ids, kind);
  return json({ ok: true, updated });
}
