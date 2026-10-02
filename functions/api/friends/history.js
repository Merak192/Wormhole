/**
 * POST /api/friends/history   Body: { uuid, text, id? }
 * 201 { ok, msg:{ id, from, at, n } }
 *
 * Encrypts the message with the pair's AES-256 key and stores it in KV.
 * The KV record is what a new device decrypts to restore the conversation.
 *
 * The live path (two devices both open) is the WebRTC DataChannel — that's
 * handled client-side and does NOT touch this endpoint. This is the
 * "also keep an encrypted copy in KV" requirement.
 *
 * `id` (optional) is the sender's message id. Clients pass it so the SAME
 * logical message has one id across the P2P channel and this KV archive,
 * which is what lets a device de-duplicate when it gets a message live AND
 * later loads it from history.
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { pairKey, friendKey, encryptMsg, pushHistory } from '../../_lib/friends.js';

const genId = () => `${Date.now().toString(36)}${Math.floor(Math.random() * 1e9).toString(36)}`;

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  const text = typeof body?.text === 'string' ? body.text : '';
  // Client-provided id wins; cap its length so a stray value can't bloat KV.
  const clientMsgId = typeof body?.id === 'string' && body.id.length <= 64 ? body.id : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');
  if (!text.trim()) return fail(400, 'empty', 'Message is empty.');
  if (text.length > 2000) return fail(400, 'too_long', 'Message is too long (2000 chars max).');

  // Must be a friend (accepted) to store history.
  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  const pk = await env.WORM_HOLE.get(pairKey(me.id, uuid));
  if (!pk) return fail(500, 'misconfigured', 'Pair key missing. Try re-sending the friend request.');

  const c = await encryptMsg(pk, text);
  const msgId = clientMsgId || genId();
  const msg = { id: msgId, from: me.id, c, at: Date.now(), n: 1 };
  await pushHistory(env.WORM_HOLE, me.id, uuid, msg);
  return json({ ok: true, msg: { id: msg.id, from: msg.from, at: msg.at, n: msg.n } }, 201);
}
