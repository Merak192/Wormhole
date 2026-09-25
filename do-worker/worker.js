/**
 * This is a small, standalone Cloudflare Worker whose only job is to host
 * the ChatRoom Durable Object class. It is deployed ONCE via `wrangler
 * deploy` from this folder (see ../README.md) and is not connected to
 * GitHub or Cloudflare Pages — it just needs to exist so the Pages project
 * can bind to it by name (`script_name`) for real-time WebSocket relay.
 *
 * The Durable Object is a pure ciphertext relay: it fans out whatever
 * bytes/text a client sends to every other client in the same room. It
 * never decrypts, inspects, stores, or logs message content. There is no
 * server-side key, no database, and no persistence of message content —
 * everything lives only in memory for the duration of the room's activity.
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
    this.broadcastPresence();

    server.addEventListener('message', (event) => {
      // Pure relay: forward the opaque ciphertext payload to every other
      // socket in this room. The Worker never touches event.data's meaning.
      for (const session of this.sessions) {
        if (session !== server) {
          try {
            session.send(event.data);
          } catch (err) {
            // Drop dead sockets quietly; cleaned up on their own close/error.
          }
        }
      }
    });

    const cleanup = () => {
      this.sessions.delete(server);
      this.broadcastPresence();
    };
    server.addEventListener('close', cleanup);
    server.addEventListener('error', cleanup);

    return new Response(null, { status: 101, webSocket: client });
  }

  /** Sends a small unencrypted JSON "system" frame (join/leave counts only). */
  broadcastPresence() {
    const payload = JSON.stringify({ __system: { type: 'presence', count: this.sessions.size } });
    for (const session of this.sessions) {
      try {
        session.send(payload);
      } catch (err) {
        /* ignore */
      }
    }
  }
}

export default {
  async fetch(request) {
    return new Response(
      'This Worker only hosts the ChatRoom Durable Object for aes-room-chat. ' +
        'It has no public HTTP entry point of its own — traffic reaches it ' +
        "through the Pages project's /api/room/<code> route via a Durable " +
        'Object binding.',
      { status: 200 }
    );
  },
};
