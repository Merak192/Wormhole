#!/usr/bin/env node
/**
 * Local dev server: serves the static site in public/ as the web root AND runs
 * the real Cloudflare Pages Functions (functions/api/auth/*) against an
 * in-memory KV. One command, no wrangler required.
 *
 *   node local/dev.mjs        # default: http://127.0.0.1:8788
 *   PORT=4000 node local/dev.mjs
 *
 * This mirrors `wrangler pages dev public --kv WORM_HOLE` closely enough to
 * develop the front-end and exercise sign-in/register against real logic.
 */
import http from 'node:http';
import { createReadStream, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { onRequestPost as register } from '../functions/api/auth/register.js';
import { onRequestPost as login } from '../functions/api/auth/login.js';
import { onRequestPost as logout } from '../functions/api/auth/logout.js';
import { onRequestGet as me } from '../functions/api/auth/me.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const publicDir = path.join(root, 'public');
const port = process.env.PORT ? Number(process.env.PORT) : 8788;

/* ── in-memory KV standing in for the WORM_HOLE binding ── */
class MemoryKV {
  constructor() { this.m = new Map(); }
  async get(k, type) {
    const e = this.m.get(k);
    if (!e || (e.exp && e.exp < Date.now())) return null;
    if (type === 'json') {
      try { return JSON.parse(e.v); } catch { return null; }
    }
    return e.v;
  }
  async put(k, v, o = {}) { this.m.set(k, { v, exp: o.expirationTtl ? Date.now() + o.expirationTtl * 1000 : 0 }); }
  async delete(k) { this.m.delete(k); }
}
const env = { WORM_HOLE: new MemoryKV(), PBKDF2_ITERATIONS: process.env.PBKDF2_ITERATIONS || '100000' };

/* ── pages-function dispatcher (matches the /api/auth/* routes) ── */
const routes = {
  '/api/auth/register': { post: ctx => register({ request: ctx.request, env }) },
  '/api/auth/login':    { post: ctx => login({ request: ctx.request, env }) },
  '/api/auth/logout':   { post: ctx => logout({ request: ctx.request, env }) },
  '/api/auth/me':       { get:  ctx => me({ request: ctx.request, env }) },
};

/* ── static file serving with security headers from public/_headers ── */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8',
};
const HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};

async function serveStatic(req, res) {
  let urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (urlPath === '/') urlPath = '/index.html';
  const safePath = path.normalize(urlPath);
  if (safePath.startsWith('../')) { res.writeHead(403, { ...HEADERS }); return res.end('Forbidden'); }
  const filePath = path.join(publicDir, safePath);
  if (!filePath.startsWith(publicDir)) { res.writeHead(403, { ...HEADERS }); return res.end('Forbidden'); }
  try {
    const st = statSync(filePath);
    if (st.isDirectory()) {
      res.writeHead(403, { ...HEADERS }); return res.end('Forbidden');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { ...HEADERS, 'Content-Type': MIME[ext] || 'application/octet-stream' });
    createReadStream(filePath).pipe(res);
  } catch {
    res.writeHead(404, { ...HEADERS, 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
  }
}

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  const route = routes[p];
  if (route && (route[req.method.toLowerCase()] || req.method === 'GET')) {
    try {
      const ctx = {
        request: new Request(`http://127.0.0.1:${port}${p}`, {
          method: req.method,
          headers: req.headers,
          duplex: 'half',
          body: req.method === 'POST' ? await collectBody(req) : undefined,
        }),
        env,
      };
      const handler = route[req.method.toLowerCase()];
      if (!handler) { res.writeHead(405, { ...HEADERS, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ ok: false, error: { code: 'method_not_allowed', message: `Method ${req.method} not allowed.` } })); }
      const out = await handler(ctx);
      const body = Buffer.from(await out.arrayBuffer());
      // out.headers is a Headers instance — read it explicitly (spread would drop it;
      // set-cookie is multi-valued and requires getSetCookie()).
      const hdrs = { 'Content-Length': body.length };
      out.headers.forEach((v, k) => { if (k !== 'set-cookie') hdrs[k] = v; });
      const setCookies = out.headers.getSetCookie();
      res.writeHead(out.status, { ...HEADERS, ...hdrs, ...(setCookies.length ? { 'set-cookie': setCookies } : {}) });
      res.end(body);
    } catch (e) {
      console.error('route error', p, e);
      res.writeHead(500, { ...HEADERS, 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: { code: 'internal', message: String(e) } }));
    }
    return;
  }
  if (p.startsWith('/api/')) {
    res.writeHead(404, { ...HEADERS, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: false, error: { code: 'not_found', message: 'Unknown route.' } }));
  }
  await serveStatic(req, res);
});

function collectBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

server.listen(port, '127.0.0.1', () => {
  console.log(`\n  worm-hole local dev\n`);
  console.log(`  UI + auth API : http://127.0.0.1:${port}/\n`);
  console.log(`  KV: in-memory (not persisted across restarts)\n`);
});
