// Runs the real Pages Function handlers against an in-memory KV.  `npm test`
import test from 'node:test';
import assert from 'node:assert/strict';
import { onRequestPost as register } from '../functions/api/auth/register.js';
import { onRequestPost as login } from '../functions/api/auth/login.js';
import { onRequestPost as logout } from '../functions/api/auth/logout.js';
import { onRequestGet as me } from '../functions/api/auth/me.js';

class MockKV {
  constructor() { this.m = new Map(); }
  async get(k, type) {
    const e = this.m.get(k);
    if (!e || (e.exp && e.exp < Date.now())) return null;
    return type === 'json' ? JSON.parse(e.v) : e.v;
  }
  async put(k, v, o = {}) { this.m.set(k, { v, exp: o.expirationTtl ? Date.now() + o.expirationTtl * 1000 : 0 }); }
  async delete(k) { this.m.delete(k); }
}

const URL_BASE = 'https://wormhole.test';
const mkEnv = () => ({ WORM_HOLE: new MockKV(), PBKDF2_ITERATIONS: '10000' }); // fast in tests
const post = (path, body, headers = {}) =>
  new Request(URL_BASE + path, { method: 'POST', headers: { 'content-type': 'application/json', 'CF-Connecting-IP': '1.2.3.4', ...headers }, body: JSON.stringify(body) });
const cookieOf = res => (res.headers.get('set-cookie') || '').split(';')[0];

async function signUp(env, username = 'Alice_1', password = 'correct horse', ip = '1.2.3.4') {
  return register({ request: post('/api/auth/register', { username, password, confirm: password }, { 'CF-Connecting-IP': ip }), env });
}

test('register: validation', async () => {
  const env = mkEnv();
  let r = await register({ request: post('/x', { username: 'a', password: 'longenough', confirm: 'longenough' }), env });
  assert.equal(r.status, 400); assert.equal((await r.json()).error.field, 'username');

  r = await register({ request: post('/x', { username: '12345678', password: 'longenough', confirm: 'longenough' }), env });
  assert.equal(r.status, 400, 'username may not look like an ID');

  r = await register({ request: post('/x', { username: 'alice', password: 'short', confirm: 'short' }), env });
  assert.equal((await r.json()).error.field, 'password');

  r = await register({ request: post('/x', { username: 'alice', password: 'longenough', confirm: 'different!' }), env });
  assert.equal((await r.json()).error.field, 'confirm');
});

test('register: creates user with unique 8-digit id, sets session cookie, hashes password', async () => {
  const env = mkEnv();
  const r = await signUp(env);
  assert.equal(r.status, 201);
  const { user } = await r.json();
  assert.match(user.id, /^[1-9]\d{7}$/);
  assert.equal(user.username, 'Alice_1');
  const cookie = r.headers.get('set-cookie');
  assert.match(cookie, /wh_session=/); assert.match(cookie, /HttpOnly/); assert.match(cookie, /Secure/); assert.match(cookie, /SameSite=Lax/);

  const stored = await env.WORM_HOLE.get(`user:id:${user.id}`, 'json');
  assert.equal(stored.pw.algo, 'PBKDF2-SHA256');
  assert.ok(!JSON.stringify(stored).includes('correct horse'), 'plaintext password must never be stored');
  assert.equal(await env.WORM_HOLE.get('user:name:alice_1'), user.id);
});

test('register: username uniqueness is case-insensitive; ids never collide', async () => {
  const env = mkEnv();
  await signUp(env, 'Alice_1');
  const dup = await signUp(env, 'ALICE_1');
  assert.equal(dup.status, 409);

  const ids = new Set();
  for (let i = 0; i < 25; i++) ids.add((await (await signUp(env, 'user' + i, 'correct horse', `9.9.9.${i}`)).json()).user.id);
  assert.equal(ids.size, 25);
});

test('register: at most 10 accounts per IP per hour', async () => {
  const env = mkEnv();
  for (let i = 0; i < 10; i++) assert.equal((await signUp(env, 'bulk' + i)).status, 201);
  assert.equal((await signUp(env, 'bulk10')).status, 429);
});

test('login: by username (any case) and by 8-digit id', async () => {
  const env = mkEnv();
  const { user } = await (await signUp(env)).json();

  let r = await login({ request: post('/x', { identifier: 'alice_1', password: 'correct horse' }), env });
  assert.equal(r.status, 200); assert.equal((await r.json()).user.id, user.id);

  r = await login({ request: post('/x', { identifier: user.id, password: 'correct horse' }), env });
  assert.equal(r.status, 200); assert.equal((await r.json()).user.username, 'Alice_1');
});

test('login: wrong password / unknown user give the same generic 401', async () => {
  const env = mkEnv();
  await signUp(env);
  const a = await login({ request: post('/x', { identifier: 'alice_1', password: 'nope-nope' }), env });
  const b = await login({ request: post('/x', { identifier: 'ghost', password: 'nope-nope' }), env });
  assert.equal(a.status, 401); assert.equal(b.status, 401);
  assert.deepEqual(await a.json(), await b.json());
});

test('login: locks out after 5 failures, resets on success path', async () => {
  const env = mkEnv();
  await signUp(env);
  for (let i = 0; i < 5; i++) await login({ request: post('/x', { identifier: 'alice_1', password: 'wrong-pass' }), env });
  const locked = await login({ request: post('/x', { identifier: 'alice_1', password: 'correct horse' }), env });
  assert.equal(locked.status, 429);
});

test('session: me -> logout -> me', async () => {
  const env = mkEnv();
  const cookie = cookieOf(await signUp(env));
  const authed = () => new Request(URL_BASE + '/api/auth/me', { headers: { cookie } });

  let r = await me({ request: authed(), env });
  assert.equal(r.status, 200); assert.equal((await r.json()).user.username, 'Alice_1');

  r = await me({ request: new Request(URL_BASE + '/api/auth/me'), env });
  assert.equal(r.status, 401);

  r = await logout({ request: post('/api/auth/logout', {}, { cookie }), env });
  assert.equal(r.status, 200); assert.match(r.headers.get('set-cookie'), /Max-Age=0/);

  r = await me({ request: authed(), env });
  assert.equal(r.status, 401, 'session must be revoked server-side');
});

test('guards: cross-site origin rejected, missing KV binding reported', async () => {
  const env = mkEnv();
  const r = await register({ request: post('/x', { username: 'bob', password: 'longenough', confirm: 'longenough' }, { origin: 'https://evil.example' }), env });
  assert.equal(r.status, 403);

  const r2 = await register({ request: post('/x', {}), env: {} });
  assert.equal(r2.status, 500); assert.equal((await r2.json()).error.code, 'misconfigured');
});
