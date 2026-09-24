# AES Room Chat

A tiny room-based chat app where two or more people join with the same
**4-digit code** and exchange **AES-256-GCM encrypted** messages. The
Cloudflare Worker that relays messages between browsers never has the
encryption key and never sees plaintext — it only forwards opaque base64
ciphertext.

## How it works

- **Client-side crypto (`public/app.js`)**: each browser derives an
  AES-256 key from the room code using PBKDF2 (100,000 iterations, SHA-256).
  Every chat message is encrypted with AES-256-GCM (random 12-byte IV per
  message) before it's sent. Decryption also happens only in the browser.
- **Server-side relay (`public/_worker.js`)**: a Cloudflare **Durable
  Object** is created per room code. It holds open WebSocket connections
  from everyone in that room and simply re-broadcasts whatever bytes it
  receives to the other connected sockets. It never parses, stores, or logs
  message content — there's no database and nothing is persisted after the
  room empties.
- **Cloudflare Pages "Advanced Mode"**: `public/_worker.js` is deployed
  alongside the static assets (`index.html`, `app.js`, `style.css`) and
  handles both static file serving and the `/api/room/<code>` WebSocket
  upgrade.

### Security notes (read before using for anything sensitive)

- A 4-digit code has only 10,000 possibilities. Treat it like a shared
  "room key" for casual private chat with people you trust to have the
  code — **not** a strong secret against a determined attacker who can
  guess/brute-force room codes.
- There's no authentication, message history, or persistence — closing the
  tab drops the conversation.
- The relay does basic fan-out only; it does not verify identity, so anyone
  with the code can join and decrypt.

## Project structure

Everything lives at the repo root — no subfolder to misconfigure:

```
aes-room-chat/
├── wrangler.toml   # Durable Object binding + Pages build output dir (".")
├── _worker.js      # Worker: static asset serving + DO WebSocket relay
├── index.html
├── style.css
└── app.js          # AES-256-GCM crypto + WebSocket client logic
```

## Local development

Requires [Node.js](https://nodejs.org) and the Cloudflare `wrangler` CLI.

```bash
npm install -g wrangler
wrangler pages dev .
```

This runs the worker and static assets locally (Durable Objects are
emulated by wrangler). Open the printed `http://localhost:8788` URL in two
browser tabs, join with the same 4-digit code, and chat.

## Deploying via GitHub + Cloudflare Pages

1. **Push this project to a new GitHub repository.**

   ```bash
   git init
   git add .
   git commit -m "Initial commit: AES room chat"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```

2. **Create the Pages project in the Cloudflare dashboard.**
   - Go to **Workers & Pages → Create application → Pages → Connect to Git**.
   - Select your GitHub repository and authorize access if prompted.
   - Build settings:
     - **Framework preset:** None
     - **Build command:** *(leave empty)*
     - **Build output directory:** `/` (i.e. the repo root — leave it as the
       default, or type `/`. Do **not** point it at a subfolder; all files
       are already at the repo root.)
   - Click **Save and Deploy**.

3. **Enable the Durable Object binding.**
   Cloudflare Pages reads the Durable Object binding and migration from
   `wrangler.toml` automatically on deploy as long as it's present at the
   repo root (already included in this project). If you ever need to add
   it manually instead: **Pages project → Settings → Functions → Durable
   Object bindings**, add a binding named `ROOMS` pointing at the
   `ChatRoom` class, exported from `_worker.js`.

4. **Done.** Every push to `main` triggers a new deployment automatically.
   Share your `*.pages.dev` URL (or a custom domain attached in **Custom
   domains**) and a 4-digit code with whoever you want to chat with.

## Customizing

- **Longer/stronger codes**: change the `/^\d{4}$/` checks in both
  `public/app.js` and `public/_worker.js` to accept longer codes or
  alphanumeric strings for a much larger keyspace.
- **Room capacity**: adjust the `this.sessions.size >= 32` check in
  `_worker.js`.
- **Message history**: none is stored by design (server can't read it
  anyway); if you want ephemeral history, you could re-broadcast the last
  N ciphertexts from the Durable Object's in-memory state to newly joined
  sockets — the server still couldn't decrypt them.
