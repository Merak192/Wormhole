/**
 * GET /api/files/meta?uuid=<8 digits>
 * 200 { ok, files:[{ fileId, name, type, size, at, status }] }
 *
 * Return the pair's file-attachment metadata list, oldest->newest. This is what
 * the "Shared files" panel in the contact info shows on boot / reopen: a
 * previously-sent file re-appears as a placeholder even though its content
 * only ever lived on the original device (or is still streaming). `status`
 * tells the UI how to render it:
 *   'received' -> content is available (download it from IndexedDB by fileId)
 *   'sent'     -> I sent it; content is in my IndexedDB by fileId
 *   'sending'  -> transfer not yet confirmed on the server side
 */
import { ID_RE, json, fail, guard, getSessionUser } from '../../_lib/auth.js';
import { friendKey, readFileMeta } from '../../_lib/friends.js';

export async function onRequestGet({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const uuid = new URL(request.url).searchParams.get('uuid') || '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');

  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  // No relation yet -> empty.
  if (!rel) return json({ ok: true, files: [] });

  const files = await readFileMeta(env.WORM_HOLE, me.id, uuid);
  return json({ ok: true, files });
}
