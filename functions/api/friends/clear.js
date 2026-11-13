/**
 * POST /api/friends/clear   Body: { uuid, ids?: string[] }
 * 200 { ok, hidden, purged, cleared:[id] }
 *
 * "Clear conversation" is per ACCOUNT, not per device. The ids the clearing
 * device was showing (`ids`; if omitted, every record in the pair's history)
 * are added to the caller's account-level ledger `clr:<me>:<peer>`. Every other
 * device logged in to the same account reads that ledger via history-get and
 * drops the same messages, so one device clearing hides them everywhere for
 * this account.
 *
 *   - The peer account still sees the messages (they stay in KV).
 *   - When the peer account has cleared the same messages too (their ledger
 *     holds the same ids), the message is DESTROYED from KV.
 *
 *   hidden  = true if this call hid something new or destroyed something
 *   purged  = number of records destroyed from KV by this call
 *   cleared = the account's full ledger (clients drop any local copy of these)
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { friendKey, markHiddenForUser } from '../../_lib/friends.js';

const MAX_IDS = 400;   // one call stays bounded; matches HISTORY_CAP * 2 (text + file messages)

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');
  const ids = Array.isArray(body?.ids)
    ? body.ids.filter(x => typeof x === 'string' && x.length <= 64 && /^[\w-]+$/.test(x)).slice(0, MAX_IDS)
    : [];

  // Only friends (accepted) have history to clear.
  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  const r = await markHiddenForUser(env.WORM_HOLE, me.id, uuid, ids);
  return json({ ok: true, hidden: r.added > 0 || r.purged > 0, purged: r.purged, cleared: r.cleared });
}
