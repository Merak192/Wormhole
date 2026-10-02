/**
 * POST /api/friends/request   Body: { uuid }
 * 201 { ok, friend:{ id, username, status } }
 *   the relation is created as "pending, requested by me". A new pair key is
 *   generated at this point, so both users will later share one AES-256 key.
 * 409 { ok:false, error:{ code } }  — already a friend, already pending, or self
 */
import { ID_RE, json, fail, guard, readJson, clientIp, isLimited, hit, publicUser, getSessionUser } from '../../_lib/auth.js';
import { friendKey, pairKey, genPairKey, indexPair } from '../../_lib/friends.js';

const REQ_LIMIT = 20;
const REQ_WINDOW = 60 * 60; // 20 requests / IP / hour

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter the 8-digit ID of the user you want to add.');
  if (uuid === me.id) return fail(400, 'self', "That's your own ID.");

  const bucket = `frr:${clientIp(request)}`;
  if (await isLimited(env, bucket, REQ_LIMIT)) return fail(429, 'rate_limited', 'Too many requests. Try again later.');

  const target = await env.WORM_HOLE.get(`user:id:${uuid}`, 'json');
  if (!target) return fail(404, 'unknown_user', 'No account with that ID.');

  const fk = friendKey(me.id, uuid);
  const rel = await env.WORM_HOLE.get(fk, 'json');
  if (rel?.status === 'friend') return fail(409, 'already_friend', 'You are already friends.');
  if (rel?.status === 'pending' && rel.by === me.id) return fail(409, 'already_pending', 'You already sent a request; waiting for a reply.');

  // New pair key (or keep an existing one if the relation was pending the other way).
  let pk = await env.WORM_HOLE.get(pairKey(me.id, uuid));
  if (!pk) {
    pk = genPairKey();
    await env.WORM_HOLE.put(pairKey(me.id, uuid), pk);
  }

  await env.WORM_HOLE.put(fk, JSON.stringify({ status: 'pending', by: me.id, at: Date.now() }));
  await indexPair(env.WORM_HOLE, me.id, uuid);
  await hit(env, bucket, REQ_WINDOW);
  return json({ ok: true, friend: { ...publicUser(target), status: 'pending' } }, 201);
}
