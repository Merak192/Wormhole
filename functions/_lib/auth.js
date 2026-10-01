/**
 * Shared helpers for the auth endpoints.
 *
 * KV data model (binding: WORM_HOLE)
 * ─────────────────────────────────────────────────────────────────────────────
 *  user:name:<lowercase username>  ->  "<8-digit id>"                 (name index)
 *  user:id:<8-digit id>            ->  JSON user record               (source of truth)
 *  session:<sha256(token)>         ->  JSON { uid, exp }   TTL 7 days (login session)
 *  rl:<bucket>                     ->  JSON { n }          TTL window  (rate limiting)
 *
 * The raw session token only ever lives in the browser's HttpOnly cookie; KV stores
 * its SHA-256, so a leaked KV dump cannot be replayed as a login.
 */

const enc = new TextEncoder();

export const COOKIE_NAME = 'wh_session';
export const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days, seconds

// Username must START WITH A LETTER. That guarantees a username can never be mistaken
// for an 8-digit ID at sign-in.
export const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_]{2,19}$/;
export const ID_RE = /^\d{8}$/;
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 128;

/* ───────────────────────── responses ───────────────────────── */

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
  });
}

export function fail(status, code, message, field, headers = {}) {
  return json({ ok: false, error: { code, message, ...(field ? { field } : {}) } }, status, headers);
}

/* ───────────────────────── request guards ───────────────────────── */

/** Returns a Response if the request must be rejected, otherwise null. */
export function guard(request, env) {
  if (!env || !env.WORM_HOLE) {
    return fail(500, 'misconfigured', 'Server is missing the WORM_HOLE KV binding.');
  }
  // CSRF defence in depth (cookies are also SameSite=Lax): browsers always send Origin on
  // cross-site POSTs, so refuse any POST whose Origin is not this site.
  if (request.method === 'POST') {
    const origin = request.headers.get('origin');
    if (origin) {
      let ok = false;
      try { ok = new URL(origin).host === new URL(request.url).host; } catch (_) {}
      if (!ok) return fail(403, 'bad_origin', 'Cross-site requests are not allowed.');
    }
  }
  return null;
}

/** Parses a small JSON object body. Returns null if missing/invalid/too large. */
export async function readJson(request) {
  if (!(request.headers.get('content-type') || '').includes('application/json')) return null;
  const text = await request.text();
  if (text.length > 4096) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
  } catch (_) {
    return null;
  }
}

export const clientIp = request => request.headers.get('CF-Connecting-IP') || 'unknown';

/* ───────────────────────── crypto ───────────────────────── */

const toB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const toB64Url = buf => toB64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export async function sha256Hex(str) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Workers cap PBKDF2 at 100,000 iterations. Each user record stores the count it was
 * hashed with, so lowering PBKDF2_ITERATIONS later never locks existing users out.
 */
export function iterationsFor(env) {
  const n = parseInt(env && env.PBKDF2_ITERATIONS, 10);
  return Number.isFinite(n) ? Math.min(100000, Math.max(10000, n)) : 100000;
}

export async function hashPassword(password, iterations, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return { algo: 'PBKDF2-SHA256', hash: toB64(bits), salt: toB64(salt), iterations };
}

export async function verifyPassword(password, pw) {
  const { hash } = await hashPassword(password, pw.iterations, fromB64(pw.salt));
  return timingSafeEqual(hash, pw.hash);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Uniform random 8-digit number, 10000000–99999999 (never a leading zero, so it is
 * always visibly 8 digits). Rejection sampling avoids modulo bias.
 */
export function randomId() {
  const range = 90000000;
  const limit = Math.floor(0x100000000 / range) * range;
  const buf = new Uint32Array(1);
  let x;
  do { crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
  return String(10000000 + (x % range));
}

/** Picks an ID that is not already taken. */
export async function allocateId(env) {
  for (let i = 0; i < 12; i++) {
    const id = randomId();
    if (!(await env.WORM_HOLE.get(`user:id:${id}`))) return id;
  }
  throw new Error('Could not allocate a unique ID');
}

/* ───────────────────────── sessions ───────────────────────── */

function cookieString(value, maxAge, request) {
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export async function createSession(env, request, userId) {
  const token = toB64Url(crypto.getRandomValues(new Uint8Array(32)));
  const exp = Date.now() + SESSION_TTL * 1000;
  await env.WORM_HOLE.put(`session:${await sha256Hex(token)}`, JSON.stringify({ uid: userId, exp }), {
    expirationTtl: SESSION_TTL,
  });
  return cookieString(token, SESSION_TTL, request);
}

export const clearCookie = request => cookieString('', 0, request);

export function readSessionToken(request) {
  const m = (request.headers.get('cookie') || '').match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));
  return m ? m[1] : null;
}

export async function destroySession(env, request) {
  const token = readSessionToken(request);
  if (token) await env.WORM_HOLE.delete(`session:${await sha256Hex(token)}`);
}

export async function getSessionUser(env, request) {
  const token = readSessionToken(request);
  if (!token) return null;
  const s = await env.WORM_HOLE.get(`session:${await sha256Hex(token)}`, 'json');
  if (!s || s.exp < Date.now()) return null;
  const user = await env.WORM_HOLE.get(`user:id:${s.uid}`, 'json');
  return user ? publicUser(user) : null;
}

/** The only shape of a user that is ever sent to the browser. */
export const publicUser = u => ({ id: u.id, username: u.username, createdAt: u.createdAt });

/* ───────────────────────── rate limiting (best effort) ─────────────────────────
 * KV is eventually consistent, so this slows brute force rather than hard-capping it.
 * For a strict cap, add a Cloudflare WAF Rate Limiting rule on /api/auth/*.
 */
export async function isLimited(env, bucket, limit) {
  const rec = await env.WORM_HOLE.get(`rl:${bucket}`, 'json');
  return !!rec && rec.n >= limit;
}
export async function hit(env, bucket, windowSec) {
  const rec = await env.WORM_HOLE.get(`rl:${bucket}`, 'json');
  await env.WORM_HOLE.put(`rl:${bucket}`, JSON.stringify({ n: (rec ? rec.n : 0) + 1 }), {
    expirationTtl: Math.max(60, windowSec), // KV minimum TTL is 60s
  });
}
export const clearHits = (env, bucket) => env.WORM_HOLE.delete(`rl:${bucket}`);
