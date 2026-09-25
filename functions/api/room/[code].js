/**
 * Cloudflare Pages Function — file-based routing.
 * Path: /api/room/:code  (code = 4-digit room code)
 *
 * This handler does no message handling itself. It validates the room
 * code, then hands the WebSocket upgrade request off to the ChatRoom
 * Durable Object (bound as `env.ROOMS` — see the root wrangler.toml, which
 * points at the separately-deployed "aes-room-chat-do" Worker). The
 * Durable Object relays ciphertext between sockets in the same room; this
 * function and the Durable Object both never see plaintext or the key.
 */

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const code = params.code;

  if (!/^\d{4}$/.test(code)) {
    return new Response('Room code must be exactly 4 digits.', { status: 400 });
  }

  const upgradeHeader = request.headers.get('Upgrade');
  if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
    return new Response('Expected WebSocket upgrade.', { status: 426 });
  }

  if (!env.ROOMS) {
    return new Response(
      'ROOMS Durable Object binding is not configured. Deploy do-worker/ ' +
        'once via `wrangler deploy` and ensure wrangler.toml\'s script_name matches.',
      { status: 500 }
    );
  }

  const id = env.ROOMS.idFromName(code);
  const stub = env.ROOMS.get(id);
  return stub.fetch(request);
}
