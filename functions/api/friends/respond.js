/**
 * POST /api/friends/respond  Body: { uuid, accept: true|false }
 * 200 { ok, friend:{ id, username, status } }
 *  On accept the shared pair key is already present (created at request time),
 *  so both sides can now read/write the pair's encrypted history.
 *  On decline the relation is removed (the pair key is kept: it's cheap, and a
 *  re-request will just mint a new one).
 */
import { ID_RE, json, fail, guard, readJson, publicUser, getSessionUser } from '../../_lib/auth.js';
import { friendKey, indexPair } from '../../_lib/friends.js';

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  const accept = body?.accept === true;
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter the 8-digit ID of the user you want to respond to.');

  const target = await env.WORM_HOLE.get(`user:id:${uuid}`, 'json');
  if (!target) return fail(404, 'unknown_user', 'No account with that ID.');

  const fk = friendKey(me.id, uuid);
  const rel = await env.WORM_HOLE.get(fk, 'json');
  if (!rel) return fail(404, 'no_request', 'There is no pending request between you and this user.');
  if (rel.status === 'friend') return fail(409, 'already_friend', 'You are already friends.');
  if (rel.by !== uuid) return fail(409, 'not_theirs', 'They did not send you a request.');

  if (accept) {
    await env.WORM_HOLE.put(fk, JSON.stringify({ status: 'friend', by: rel.by, at: Date.now() }));
    await indexPair(env.WORM_HOLE, me.id, uuid);
  } else {
    await env.WORM_HOLE.delete(fk);
    // keep the index entry so the peer still sees "you requested / I requested"
    // until they delete it client-side; the request just no longer blocks re-adding.
  }
  return json({ ok: true, friend: { ...publicUser(target), status: accept ? 'friend' : 'declined' } });
}
