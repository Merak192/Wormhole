/**
 * POST /api/friends/recall   Body: { uuid, id, at?, fileId? }
 * 200 { ok, tombstoned }
 *
 * Recall (retract) a message the caller SENT, within RECALL_WINDOW_MS. The
 * encrypted content is deleted from KV and replaced by a tombstone, so the
 * peer's devices — including ones that are offline right now — see "Message
 * recalled" on their next history poll. The live P2P `recall` message is the
 * fast path; this endpoint is the durable one.
 *
 *   403 forbidden  the id belongs to a message the peer sent
 *   403 too_late   the recall window has passed
 *
 * Idempotent: recalling twice is a no-op. `fileId` (file messages only) also
 * drops that attachment's metadata from the shared-files list.
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { friendKey, recallMessage, dropFileMeta } from '../../_lib/friends.js';

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  const id = typeof body?.id === 'string' ? body.id : '';
  const fileId = typeof body?.fileId === 'string' && body.fileId.length <= 64 ? body.fileId : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');
  if (!id || id.length > 64 || !/^[\w-]+$/.test(id)) return fail(400, 'invalid_id', 'Invalid message id.');

  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  const r = await recallMessage(env.WORM_HOLE, me.id, uuid, id, Number(body?.at));
  if (!r.ok) {
    return fail(403, r.code, r.code === 'too_late'
      ? 'This message can no longer be recalled.'
      : 'You can only recall your own messages.');
  }
  if (fileId) await dropFileMeta(env.WORM_HOLE, me.id, uuid, fileId);
  return json({ ok: true, tombstoned: r.tombstoned });
}
