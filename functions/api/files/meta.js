/**
 * POST /api/files/meta   Body: { uuid, fileId, name, type, size, at?, status? }
 * 201 { ok, fileId }
 *
 * Persist file-attachment METADATA for the pair (NOT the content). Content is
 * streamed over the P2P DataChannel; this record is what makes a previously
 * shared file reappear as a placeholder in the "Shared files" list on a new
 * device or after a refresh. Both the sender and receiver write it (the
 * receiver marks it 'received'), so the metadata is eventually consistent on
 * both sides' new devices.
 *
 * Must be friends. The metadata is small (a few hundred bytes), so it never
 * strains KV the way base64 content would.
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { friendKey, pushFileMeta } from '../../_lib/friends.js';

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  const fileId = typeof body?.fileId === 'string' && body.fileId.length <= 64 ? body.fileId : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');
  if (!fileId) return fail(400, 'missing_file_id', 'A file id is required.');

  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  const at = Number.isFinite(body?.at) ? body.at : Date.now();
  await pushFileMeta(env.WORM_HOLE, me.id, uuid, {
    fileId,
    name: body?.name,
    type: body?.type,
    size: body?.size,
    at,
    status: body?.status,
  });
  return json({ ok: true, fileId }, 201);
}
