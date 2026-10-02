/**
 * GET /api/friends
 * 200 { ok, friends:[{id,username,status}], requests:[{uuid,username,by,status}] }
 *
 *  friends   — accepted relations; these become the left-panel list
 *  requests  — pending relations: by === me.id ("you requested") or incoming
 *
 * Both are read off the per-user index idx:<me.id> (maintained in
 * request.js / respond.js), so no KV scan is required.
 */
import { json, fail, guard, publicUser, getSessionUser } from '../../_lib/auth.js';
import { friendKey } from '../../_lib/friends.js';

export async function onRequestGet({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const idx = (await env.WORM_HOLE.get(`idx:${me.id}`, 'json')) || [];
  const friends = [];
  const requests = [];
  for (const peer of idx) {
    const rel = await env.WORM_HOLE.get(friendKey(me.id, peer), 'json');
    if (!rel) continue;
    const u = await env.WORM_HOLE.get(`user:id:${peer}`, 'json');
    if (!u) continue;
    if (rel.status === 'friend') friends.push({ ...publicUser(u), status: 'friend' });
    else requests.push({ uuid: peer, ...publicUser(u), by: rel.by, status: 'pending' });
  }
  return json({ ok: true, friends, requests });
}
