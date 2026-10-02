/**
 * GET /api/friends/history-get?uuid=<8 digits>
 * 200 { ok, key, msgs:[{ id, from, text, at, unreadable? }] }
 *
 * `key` is the pair's AES-256 key (base64url) — returned to the *authenticated
 * owner* so their browser can decrypt the blobs client-side. A KV reader that
 * doesn't have the key gets `key: null` and all messages unreadable.
 */
import { ID_RE, json, fail, guard, getSessionUser } from '../../_lib/auth.js';
import { friendKey, pairKey, readHistory } from '../../_lib/friends.js';

export async function onRequestGet({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const uuid = new URL(request.url).searchParams.get('uuid') || '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');

  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  // No relation yet -> empty (nothing to decrypt).
  if (!rel) return json({ ok: true, key: null, msgs: [] });

  const key = await env.WORM_HOLE.get(pairKey(me.id, uuid));
  const msgs = key ? await readHistory(env.WORM_HOLE, me.id, uuid) : [];
  return json({ ok: true, key, msgs });
}
