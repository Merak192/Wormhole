/**
 * Cloudflare Pages "Advanced Mode" worker.
 *
 * Responsibilities:
 *  - Serve static assets (index.html, app.js, style.css) via env.ASSETS
 *  - Upgrade /api/room/<4-digit-code> to a WebSocket
 *  - Relay whatever bytes/text a client sends to every OTHER client in the
 *    same room (identified by the Durable Object name = the 4-digit code)
 *
 * IMPORTANT: This worker never decrypts, inspects, stores, or logs message
 * contents. Clients send AES-256-GCM ciphertext as opaque base64 strings.
 * The Durable Object simply fans that string out to the other connected
 * sockets in the same room. There is no server-side key, no database, and
 * no persistence of message content — everything lives only in each
 * client's browser memory for the duration of the session.
 */

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    /** @type {Set<WebSocket>} */
    this.sessions = new Set();
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
      return new Response('Expected WebSocket upgrade', { status: 426 });
    }

    // Basic room capacity guard (purely to keep a single room reasonable).
    if (this.sessions.size >= 32) {
      return new Response('Room full', { status: 503 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    server.accept();
    this.sessions.add(server);

    // Let everyone else know someone joined (metadata only — no content).
    this.broadcastSystem(server, { type: 'presence', count: this.sessions.size });

    server.addEventListener('message', (event) => {
      // Pure relay: forward the opaque ciphertext payload to every other
      // socket in this room. We never touch event.data's meaning.
      for (const session of this.sessions) {
        if (session !== server) {
          try {
            session.send(event.data);
          } catch (err) {
            // Drop dead sockets quietly; they'll be cleaned up on their
            // own close/error events.
          }
        }
      }
    });

    const cleanup = () => {
      this.sessions.delete(server);
      this.broadcastSystem(null, { type: 'presence', count: this.sessions.size });
    };
    server.addEventListener('close', cleanup);
    server.addEventListener('error', cleanup);

    return new Response(null, { status: 101, webSocket: client });
  }

  /** Sends a small unencrypted JSON "system" frame (join/leave counts only). */
  broadcastSystem(exclude, obj) {
    const payload = JSON.stringify({ __system: obj });
    for (const session of this.sessions) {
      if (session !== exclude) {
        try {
          session.send(payload);
        } catch (err) {
          /* ignore */
        }
      }
    }
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith('/api/room/')) {
      const code = url.pathname.split('/').pop();
      if (!/^\d{4}$/.test(code)) {
        return new Response('Room code must be exactly 4 digits', { status: 400 });
      }
      const id = env.ROOMS.idFromName(code);
      const stub = env.ROOMS.get(id);
      return stub.fetch(request);
    }

    // Everything else falls through to the static asset bundle
    // (index.html, app.js, style.css) that Pages deploys alongside this file.
    return env.ASSETS.fetch(request);
  },
};
