/**
 * GET /api/auth/me
 * 200 -> { ok: true, user }   when the session cookie is valid
 * 401 -> { ok: false }        otherwise (the front-end then shows the sign-in screen)
 */
import { json, fail, guard, getSessionUser } from '../../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const user = await getSessionUser(env, request);
  if (!user) return fail(401, 'unauthenticated', 'Not signed in.');
  return json({ ok: true, user });
}
