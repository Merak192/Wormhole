# AES Room Chat

A tiny room-based chat app where two or more people join with the same
**4-digit code** and exchange **AES-256-GCM encrypted** messages
**instantly** over a WebSocket. The Cloudflare backend that relays
messages between browsers never has the encryption key and never sees
plaintext — it only forwards opaque base64 ciphertext.

## How it works

- **Client-side crypto (`app.js`)**: each browser derives an AES-256 key
  from the room code using PBKDF2 (100,000 iterations, SHA-256). Every
  chat message is encrypted with AES-256-GCM (random 12-byte IV per
  message) before it's sent. Decryption also happens only in the browser.
- **Thin proxy (`functions/api/room/[code].js`)**: a Cloudflare Pages
  Function that validates the room code and hands the WebSocket upgrade
  request off to a Durable Object. It never touches message content.
- **Relay (`do-worker/worker.js`)**: a `ChatRoom` Durable Object — one
  instance per room code — that holds open WebSocket connections from
  everyone in that room and re-broadcasts whatever bytes it receives to
  the other connected sockets. No database, no persistence, no logging of
  content.

### Why is there a separate `do-worker/` folder?

Cloudflare Pages projects **cannot host a Durable Object class themselves**
— a Durable Object must live in its own, separately-deployed Worker, which
the Pages project then binds to by name (`script_name`). This is a
Cloudflare platform constraint, not a choice made here. In practice that
means:

- Everything in the **repo root** (`index.html`, `app.js`, `style.css`,
  `functions/`) deploys automatically via GitHub → Cloudflare Pages, same
  as any normal push.
- The **`do-worker/` folder** deploys differently: **once**, via the
  `wrangler` CLI, not through Git. It's not part of the Pages build at
  all — Pages ignores it. You only need to redeploy it if you change
  `do-worker/worker.js` itself (the relay logic), which should be rare.

### Security notes (read before using for anything sensitive)

- A 4-digit code has only 10,000 possibilities. Treat it like a shared
  "room key" for casual private chat with people you trust to have the
  code — **not** a strong secret against a determined attacker who can
  guess/brute-force room codes.
- There's no authentication, message history, or persistence — closing the
  tab drops the conversation, and nothing is ever written to disk.
- Anyone with the code can join and decrypt; there's no per-user identity
  verification.

## Project structure

```
aes-room-chat/
├── wrangler.toml              # Pages config: binds to the external DO worker
├── index.html
├── style.css
├── app.js                     # AES-256-GCM crypto + WebSocket client
├── functions/
│   └── api/
│       └── room/
│           └── [code].js       # Thin proxy: upgrade → hand off to the Durable Object
└── do-worker/                 # Deployed separately via CLI — NOT part of the Pages build
    ├── wrangler.toml
    └── worker.js                # ChatRoom Durable Object (the actual relay)
```

## One-time setup: deploy the Durable Object worker

You need [Node.js](https://nodejs.org) and the Cloudflare `wrangler` CLI
for this step only. It does not need to be repeated on future code
changes to the frontend or Pages Function — only if you edit
`do-worker/worker.js`.

```bash
npm install -g wrangler
wrangler login          # opens a browser to authorize wrangler with your Cloudflare account
cd do-worker
wrangler deploy
```

This creates a live Worker named `aes-room-chat-do` (from
`do-worker/wrangler.toml`) with the `ChatRoom` Durable Object registered.
You'll see a success message with a `*.workers.dev` URL — you can ignore
that URL; nothing calls this Worker directly over HTTP. It exists purely
so the Pages project can bind to its Durable Object by name.

**If you rename `do-worker/wrangler.toml`'s `name` field**, update
`script_name` in the root `wrangler.toml` to match exactly, or the binding
won't resolve.

## Local development

```bash
# from the repo root
wrangler pages dev . --compatibility-date=2024-09-23
```

Durable Object bindings with `script_name` pointing at an already-deployed
Worker work in `wrangler pages dev` as long as you've completed the
one-time deploy above first. Open the printed local URL in two browser
tabs, join with the same 4-digit code, and chat.

## Deploying via GitHub + Cloudflare Pages

1. **Complete the one-time Durable Object deploy above, first.**

2. **Push this project to a GitHub repository** (repo root = these files,
   no extra wrapping folder — `do-worker/` comes along for reference but
   Pages will simply ignore it during builds).

   ```bash
   git init
   git add .
   git commit -m "Initial commit: AES room chat (WebSocket + Durable Object)"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```

3. **Create the Pages project.**
   - Cloudflare dashboard → **Workers & Pages → Create application → Pages
     → Connect to Git**.
   - Select your repository.
   - Build settings:
     - **Framework preset:** None
     - **Build command:** *(leave empty)*
     - **Build output directory:** `/` (repo root — leave as default)
     - **Root directory:** *(leave empty)*
   - Click **Save and Deploy**.

4. **Cloudflare Pages reads `wrangler.toml` automatically** on deploy and
   picks up the Durable Object binding (`script_name = "aes-room-chat-do"`)
   — no dashboard binding UI steps needed, unlike the KV approach. If the
   build log shows a Wrangler validation error, double check the root
   `wrangler.toml` has no `migrations` block (Pages rejects that — only
   `do-worker/wrangler.toml` should have one) and that `script_name`
   exactly matches the Worker name from step 1.

5. **Done.** Every future push to `main` redeploys the Pages side
   automatically. Open your `*.pages.dev` URL in two tabs, join with the
   same 4-digit code, and messages should now appear instantly.

## Customizing

- **Longer/stronger codes**: change the `/^\d{4}$/` checks in both
  `app.js` and `functions/api/room/[code].js` to accept longer or
  alphanumeric codes for a much larger keyspace.
- **Room capacity**: adjust `this.sessions.size >= 32` in
  `do-worker/worker.js`, then redeploy it (`cd do-worker && wrangler deploy`).
