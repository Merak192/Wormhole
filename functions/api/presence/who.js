/**
 * GET /api/presence/who?uuid=<8 digits>
 * 200 { ok, online }
 *
 * "Is this user on the web right now?" Checks their heartbeat TTL. This is
 * the fallback for the P2P presence channel: P2P says "online" the instant the
 * channel connects, and this endpoint keeps that state true between refreshes
 * and for the first few seconds of a session, when P2P isn't up yet.
 */
import { ID_RE, json, fail, guard, getSessionUser } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const uuid = new URL(request.url).searchParams.get('uuid') || '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');

  // presence is a TTL key: if it's in KV, the user beat within the last 15s
  const beat = await env.WORM_HOLE.get(`present:${uuid}`);
  return json({ ok: true, online: !!beat });
}
