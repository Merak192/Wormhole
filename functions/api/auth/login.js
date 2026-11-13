/**
 * POST /api/auth/login
 * Body: { identifier, password }   identifier = username OR the 8-digit ID
 * 200 -> { ok: true, user: { id, username, createdAt } }  + session cookie
 */
import {
  ID_RE, PASSWORD_MAX,
  json, fail, guard, readJson, clientIp,
  hashPassword, verifyPassword, iterationsFor, createSession, publicUser,
  sha256Hex, isLimited, hit, clearHits,
} from '../../_lib/auth.js';

const MAX_FAILS = 5;
const LOCK_WINDOW = 15 * 60; // seconds

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const body = await readJson(request);
  if (!body) return fail(400, 'bad_request', 'Send a JSON body.');

  const identifier = typeof body.identifier === 'string' ? body.identifier.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  if (!identifier || !password) {
    return fail(400, 'missing_fields', 'Enter your username or ID and your password.');
  }

  const invalid = () => fail(401, 'invalid_credentials', 'Incorrect username/ID or password.');
  if (identifier.length > 64 || password.length > PASSWORD_MAX) return invalid();

  // Throttle per (IP, account) so one attacker can't lock out everyone, and one
  // account can't be guessed from a single IP.
  const bucket = `login:${clientIp(request)}:${await sha256Hex(identifier.toLowerCase())}`;
  if (await isLimited(env, bucket, MAX_FAILS)) {
    return fail(429, 'rate_limited', 'Too many attempts. Try again in 15 minutes.');
  }

  // 8 digits => ID lookup; anything else => username lookup (usernames start with a letter).
  const userId = ID_RE.test(identifier)
    ? identifier
    : await env.WORM_HOLE.get(`user:name:${identifier.toLowerCase()}`);
  const user = userId ? await env.WORM_HOLE.get(`user:id:${userId}`, 'json') : null;

  if (!user) {
    await hashPassword(password, iterationsFor(env)); // burn equal time: don't reveal which accounts exist
    await hit(env, bucket, LOCK_WINDOW);
    return invalid();
  }
  if (!(await verifyPassword(password, user.pw))) {
    await hit(env, bucket, LOCK_WINDOW);
    return invalid();
  }

  await clearHits(env, bucket);
  const cookie = await createSession(env, request, user.id);
  return json({ ok: true, user: publicUser(user) }, 200, { 'set-cookie': cookie });
}
