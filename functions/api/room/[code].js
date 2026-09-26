/**
 * Cloudflare Pages Function — file-based routing.
 * Path: /api/room/:code  (code = 4-digit room code)
 *
 * IMPORTANT: this endpoint carries only WebRTC *signaling* data (SDP
 * offers/answers, ICE candidates, and small "hello" presence broadcasts)
 * — never chat message content. Once two browsers finish this handshake,
 * they open a direct RTCDataChannel to each other and all actual chat
 * messages (still AES-256-GCM encrypted) flow peer-to-peer, completely
 * bypassing this server. This function and the KV store behind it never
 * see a single chat message, encrypted or otherwise.
 *
 * Signaling envelopes are small and short-lived (2 minute TTL) — plenty
 * for connection setup, cleaned up quickly afterward.
 *
 * Requires a KV namespace bound as `WORM_HOLE` in the Pages project
 * (Settings → Functions → KV namespace bindings — no wrangler.toml needed).
 */

const ROOM_CODE_RE = /^\d{4}$/;
const SIGNAL_TTL_SECONDS = 120; // 2 minutes — only needs to outlive connection setup
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

  if (heartbeat && clientId) {
    context.waitUntil(
      env.WORM_HOLE.put(`presence:${code}:${clientId}`, '1', { expirationTtl: PRESENCE_TTL_SECONDS })
    );
  }

  const msgPrefix = `sig:${code}:`;
  const list = await env.WORM_HOLE.list({ prefix: msgPrefix, limit: 200 });

  const messages = [];
  const afterFullKey = msgPrefix + after;
  for (const key of list.keys) {
    if (key.name > afterFullKey) {
      const value = await env.WORM_HOLE.get(key.name);
      if (value !== null) {
        let signal;
        try {
          signal = JSON.parse(value);
        } catch {
          continue;
        }
        messages.push({ key: key.name.slice(msgPrefix.length), signal });
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

  const { from, to, type, name, data } = body || {};
  if (typeof from !== 'string' || !from) {
    return jsonResponse({ error: 'Missing "from".' }, 400);
  }
  if (typeof type !== 'string' || !type) {
    return jsonResponse({ error: 'Missing "type".' }, 400);
  }

  const envelope = { from, to: to ?? null, type, name: name || 'Anonymous', data: data ?? null };
  const serialized = JSON.stringify(envelope);
  if (serialized.length > 20000) {
    return jsonResponse({ error: 'Signal too large.' }, 413);
  }

  const ts = Date.now().toString().padStart(15, '0');
  const rand = crypto.randomUUID();
  const key = `sig:${code}:${ts}-${rand}`;

  await env.WORM_HOLE.put(key, serialized, { expirationTtl: SIGNAL_TTL_SECONDS });

  context.waitUntil(
    env.WORM_HOLE.put(`presence:${code}:${from}`, '1', { expirationTtl: PRESENCE_TTL_SECONDS })
  );

  return jsonResponse({ ok: true });
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
