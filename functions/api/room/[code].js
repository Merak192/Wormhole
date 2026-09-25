/**
 * Cloudflare Pages Function — file-based routing.
 * Path: /api/room/:code  (code = 4-digit room code)
 *
 * This is a pure ciphertext relay backed by Workers KV:
 *  - POST stores one opaque base64 ciphertext string under a unique key.
 *  - GET lists keys newer than a client-supplied cursor and returns them.
 *
 * The server never decrypts anything — it doesn't have the key, which only
 * ever exists in each participant's browser (derived from the room code via
 * PBKDF2). Messages auto-expire from KV after 10 minutes (expirationTtl)
 * so nothing lingers.
 *
 * NOTE ON LATENCY: Workers KV is eventually consistent — a write can take
 * a few seconds (occasionally longer) to become visible to reads from a
 * different edge location, independent of how often the client polls.
 * Tightening the poll interval (see app.js) reduces added client-side
 * delay but cannot eliminate this underlying propagation lag. True
 * instant delivery would require a Durable Object, which needs its own
 * separately-deployed Worker — intentionally not used here.
 *
 * Requires a KV namespace bound as `WORM_HOLE` in the Pages project
 * (Settings → Functions → KV namespace bindings — no wrangler.toml needed).
 */

const ROOM_CODE_RE = /^\d{4}$/;
const MESSAGE_TTL_SECONDS = 600; // 10 minutes
const PRESENCE_TTL_SECONDS = 60; // Cloudflare KV enforces a 60s minimum TTL

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const code = params.code;

  if (!ROOM_CODE_RE.test(code)) {
    return jsonResponse({ error: 'Room code must be exactly 4 digits.' }, 400);
  }
  if (!env.WORM_HOLE) {
    return jsonResponse({ error: 'WORM_HOLE KV binding is not configured on this Pages project.' }, 500);
  }

  const url = new URL(request.url);
  const after = url.searchParams.get('after') || '';
  const clientId = url.searchParams.get('clientId') || '';
  const heartbeat = url.searchParams.get('hb') === '1';

  // Only write a presence heartbeat occasionally (not on every poll) to
  // stay well within Workers KV's free-tier write limits.
  if (heartbeat && clientId) {
    context.waitUntil(
      env.WORM_HOLE.put(`presence:${code}:${clientId}`, '1', { expirationTtl: PRESENCE_TTL_SECONDS })
    );
  }

  const msgPrefix = `msg:${code}:`;
  const list = await env.WORM_HOLE.list({ prefix: msgPrefix, limit: 200 });

  const messages = [];
  const afterFullKey = msgPrefix + after;
  for (const key of list.keys) {
    if (key.name > afterFullKey) {
      const value = await env.WORM_HOLE.get(key.name);
      if (value !== null) {
        messages.push({ key: key.name.slice(msgPrefix.length), ciphertext: value });
      }
    }
  }

  const cursor = messages.length ? messages[messages.length - 1].key : after;

  const presenceList = await env.WORM_HOLE.list({ prefix: `presence:${code}:` });

  return jsonResponse({ messages, cursor, online: presenceList.keys.length });
}

export async function onRequestPost(context) {
  const { request, env, params } = context;
  const code = params.code;

  if (!ROOM_CODE_RE.test(code)) {
    return jsonResponse({ error: 'Room code must be exactly 4 digits.' }, 400);
  }
  if (!env.WORM_HOLE) {
    return jsonResponse({ error: 'WORM_HOLE KV binding is not configured on this Pages project.' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body.' }, 400);
  }

  const { ciphertext, clientId } = body || {};
  if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
    return jsonResponse({ error: 'Missing ciphertext.' }, 400);
  }
  if (ciphertext.length > 20000) {
    return jsonResponse({ error: 'Message too large.' }, 413);
  }

  const ts = Date.now().toString().padStart(15, '0');
  const rand = crypto.randomUUID();
  const key = `msg:${code}:${ts}-${rand}`;

  await env.WORM_HOLE.put(key, ciphertext, { expirationTtl: MESSAGE_TTL_SECONDS });

  if (typeof clientId === 'string' && clientId) {
    context.waitUntil(
      env.WORM_HOLE.put(`presence:${code}:${clientId}`, '1', { expirationTtl: PRESENCE_TTL_SECONDS })
    );
  }

  return jsonResponse({ ok: true, key: key.slice(`msg:${code}:`.length) });
}
