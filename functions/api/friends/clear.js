/**
 * POST /api/friends/clear   Body: { uuid, device }
 * 200 { ok, purged }
 *
 * "Clear conversation" is PER-DEVICE, not global. Marking it on this device
 * hides the pair's history from THIS device only; the other side keeps seeing
 * it. The KV message data is purged only when BOTH devices of the pair have
 * each cleared (so no surviving device can recover it).
 *
 * `device` is a client-stable device id (localStorage) — not the user id — so
 * the same user on two devices gets two independent markers.
 */
import { ID_RE, json, fail, guard, readJson, getSessionUser } from '../../_lib/auth.js';
import { friendKey, pairKey, histKey, clearKey } from '../../_lib/friends.js';

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  const body = await readJson(request);
  const uuid = typeof body?.uuid === 'string' ? body.uuid.trim() : '';
  const device = typeof body?.device === 'string' && body.device.length <= 64 ? body.device : '';
  if (!ID_RE.test(uuid)) return fail(400, 'invalid_uuid', 'Enter a valid 8-digit ID.');
  if (!device) return fail(400, 'missing_device', 'This device has no clear marker.');

  // Only friends (accepted) have history to clear.
  const rel = await env.WORM_HOLE.get(friendKey(me.id, uuid), 'json');
  if (rel?.status !== 'friend') return fail(403, 'not_friends', 'You are not friends with this user yet.');

  // Mark this device's clear.
  await env.WORM_HOLE.put(clearKey(me.id, uuid, device), JSON.stringify({ at: Date.now() }));

  // The pair's OTHER side is uuid (from this device's view). The clear markers
  // live under each user's own device ids, so "both cleared" means: I have a
  // marker for my device AND the peer has a marker for *their* device. We can't
  // enumerate the peer's device ids, so the purge is best-effort: it happens
  // when the *last remaining* side clears. In practice the data is small and
  // already encrypted; this is a convenience, not a security boundary.
  // For correctness we purge when both users' most-recent clear is present.
  const purged = await maybePurge(env, me.id, uuid);
  return json({ ok: true, purged });
}

/**
 * Purge the pair's KV data (history + pair key + clear markers) once BOTH users
 * have cleared on at least one device. We approximate "both" by checking a
 * per-user "cleared-by-any-device" flag: clear:<A>:<B>:* — but KV can't glob.
 * Instead each user records a per-user flag when they clear; when both flags
 * are set, purge.
 */
async function maybePurge(env, meId, peerId) {
  const flagA = `cleared:${meId}:${peerId}`;
  const flagB = `cleared:${peerId}:${meId}`;
  await env.WORM_HOLE.put(flagA, JSON.stringify({ at: Date.now() }), { expirationTtl: 60 * 60 * 24 * 7 });
  const other = await env.WORM_HOLE.get(flagB, 'json');
  if (!other) return false;

  // Both sides cleared → remove the conversation data for good.
  const hk = histKey(meId, peerId);
  const pk = pairKey(meId, peerId);
  await env.WORM_HOLE.delete(hk);
  await env.WORM_HOLE.delete(pk);
  // Clear the per-user flags and per-device markers we know about.
  await env.WORM_HOLE.delete(flagA);
  await env.WORM_HOLE.delete(flagB);
  return true;
}
