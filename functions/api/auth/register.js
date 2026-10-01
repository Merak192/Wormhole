/**
 * POST /api/auth/register
 * Body: { username, password, confirm }
 * 201 -> { ok: true, user: { id, username, createdAt } }  + session cookie (auto sign-in)
 */
import {
  USERNAME_RE, PASSWORD_MIN, PASSWORD_MAX,
  json, fail, guard, readJson, clientIp,
  allocateId, hashPassword, iterationsFor, createSession, publicUser,
  isLimited, hit,
} from '../../_lib/auth.js';

const REG_LIMIT = 10;          // accounts per IP...
const REG_WINDOW = 60 * 60;    // ...per hour

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const body = await readJson(request);
  if (!body) return fail(400, 'bad_request', 'Send a JSON body.');

  const username = typeof body.username === 'string' ? body.username.trim() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  const confirm = typeof body.confirm === 'string' ? body.confirm : '';

  // ── validation (mirrors the client, never trusts it) ──
  if (!USERNAME_RE.test(username)) {
    return fail(400, 'invalid_username',
      'Use 3–20 characters: start with a letter, then letters, numbers or underscores.', 'username');
  }
  if (password.length < PASSWORD_MIN) {
    return fail(400, 'weak_password', `Password must be at least ${PASSWORD_MIN} characters.`, 'password');
  }
  if (password.length > PASSWORD_MAX) {
    return fail(400, 'long_password', `Password must be ${PASSWORD_MAX} characters or fewer.`, 'password');
  }
  if (password !== confirm) {
    return fail(400, 'password_mismatch', 'Passwords do not match.', 'confirm');
  }

  // ── throttle mass sign-ups ──
  const bucket = `reg:${clientIp(request)}`;
  if (await isLimited(env, bucket, REG_LIMIT)) {
    return fail(429, 'rate_limited', 'Too many accounts created from this network. Try again later.');
  }

  // ── uniqueness (case-insensitive) ──
  const lower = username.toLowerCase();
  if (await env.WORM_HOLE.get(`user:name:${lower}`)) {
    return fail(409, 'username_taken', 'That username is already taken.', 'username');
  }

  const id = await allocateId(env);
  const pw = await hashPassword(password, iterationsFor(env));
  const user = { id, username, usernameLower: lower, pw, createdAt: new Date().toISOString() };

  // Claim the name first, then write the record.
  await env.WORM_HOLE.put(`user:name:${lower}`, id);
  await env.WORM_HOLE.put(`user:id:${id}`, JSON.stringify(user));

  // KV has no atomic "put if absent". If two people claimed the same name at the same
  // moment, the loser notices here (last write wins) and backs out.
  if ((await env.WORM_HOLE.get(`user:name:${lower}`)) !== id) {
    await env.WORM_HOLE.delete(`user:id:${id}`);
    return fail(409, 'username_taken', 'That username is already taken.', 'username');
  }

  await hit(env, bucket, REG_WINDOW);
  const cookie = await createSession(env, request, id);
  return json({ ok: true, user: publicUser(user) }, 201, { 'set-cookie': cookie });
}
