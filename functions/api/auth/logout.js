/**
 * POST /api/auth/logout
 * Deletes the server-side session and expires the cookie.
 */
import { json, guard, destroySession, clearCookie } from '../../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  await destroySession(env, request);
  return json({ ok: true }, 200, { 'set-cookie': clearCookie(request) });
}
