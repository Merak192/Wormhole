/**
 * GET /api/friends/history-get?uuid=<8 digits>
 * 200 { ok, key, cleared:[id], msgs:[{ id, from, at, text, seen, read, unreadable? }] }
 *
 * `key` is the pair's AES-256 key (base64url) — returned to the *authenticated
 * owner* so their browser can decrypt the blobs client-side. A KV reader that
 * doesn't have the key gets `key: null` and all messages unreadable.
 *
 * `msgs` is already filtered to the caller's visibility: anything the caller's
 * ACCOUNT cleared via POST /api/friends/clear (from any device) is omitted.
 * `cleared` is the account's ledger of cleared message ids. A device that still
 * holds one of those ids locally (a copy from before another device cleared it,
 * or a localStorage mirror) must drop it — that is how a clear on one device
 * reaches the account's other devices, even after the record was destroyed.
 *
 * `seen`/`read` are the durable receipt state, resolved against the peer:
 * for a record the peer sent (`from === uuid`) they report whether that peer
 * has delivered / read it. `peerSeen`/`peerRead` are the inverse — for a
 * record *I* sent, whether the peer has delivered / read it. The caller's
 * client uses these to restore tick state across refresh / device change,
 * even when P2P is down (see POST /api/friends/ack, where the receiver
 * writes them).
 */
import { ID_RE, json, fail, guard, getSessionUser } from '../../_lib/auth.js';
import { friendKey, pairKey, readVisibleHistory, readCleared } from '../../_lib/friends.js';

export async function onRequestGet({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const uuid = new URL(request.url).searchParams.get('uuid') || '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');

  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  // No relation yet -> empty (nothing to decrypt).
  if (!rel) return json({ ok: true, key: null, cleared: [], msgs: [] });

  const key = await env.WORM_HOLE.get(pairKey(me.id, uuid));
  const [msgs, cleared] = await Promise.all([
    key ? readVisibleHistory(env.WORM_HOLE, me.id, uuid) : [],
    readCleared(env.WORM_HOLE, me.id, uuid),
  ]);
  return json({ ok: true, key, cleared, msgs });
}
