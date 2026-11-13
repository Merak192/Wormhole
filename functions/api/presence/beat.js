/**
 * POST /api/presence/beat   Body: {}
 * 200 { ok }
 *
 * "I'm online right now." Records the user's last-seen timestamp in KV with a
 * short TTL, so it self-expires. Every authenticated, open tab calls this
 * once a second; a user is considered *online* for other devices while their
 * last beat is within the last few seconds.
 *
 * This is the **fallback** presence channel: P2P (Trystero) gives real-time
 * presence when the channel is up, but the heartbeat covers the window where
 * the channel hasn't connected yet, and works even if a relay is blocked.
 */
import { json, fail, guard, getSessionUser } from '../../_lib/auth.js';

const BEAT_TTL = 15;   // seconds. A beat older than this = "offline".
const ONLINE_WINDOW = 5; // peers consider you online if your last beat < this old

export async function onRequestPost({ request, env }) {
  const rejected = guard(request, env);
  if (rejected) return rejected;

  const me = await getSessionUser(env, request);
  if (!me) return fail(401, 'unauthenticated', 'Not signed in.');

  await env.WORM_HOLE.put(`present:${me.id}`, JSON.stringify({ at: Date.now() }), {
    expirationTtl: BEAT_TTL,
  });
  return json({ ok: true, onlineWindow: ONLINE_WINDOW });
}
