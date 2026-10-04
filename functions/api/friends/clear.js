/**
 * POST /api/friends/clear   Body: { uuid }
 * 200 { ok, hidden, purged }
 *
 * "Clear conversation" is PER-USER, not per-device and not global. Clearing
 * marks every record in the pair's KV history as hidden for THIS user by
 * appending the user's id to each record's `hiddenBy` array. The record stays
 * in KV (the peer still sees it); it is physically deleted only when BOTH
 * users of the pair have hidden it. This replaces the older per-device
 * clear-marker model: hiding now lives on the message record itself, so a
 * user clearing on one device also hides it on their other devices, which is
 * what "clear this conversation" means to the user.
 *
 *   hidden = true  -> this user's id was added to at least one record OR a
 *                     record was pruned (i.e. the history array was rewritten)
 *   The response is informational; clients should key off `ok`, not `hidden`.
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { friendKey, markHiddenForUser } from '../../_lib/friends.js';

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');

  // Only friends (accepted) have history to clear.
  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  const hidden = await markHiddenForUser(env.WORM_HOLE, me.id, uuid);
  return json({ ok: true, hidden });
}
