# AES Room Chat

A tiny room-based chat app where two or more people join with the same
**4-digit code** and exchange **AES-256-GCM encrypted** messages. The
Cloudflare backend that relays messages between browsers never has the
encryption key and never sees plaintext — it only stores and forwards
opaque base64 ciphertext.

This version is deployable **entirely through the Cloudflare Pages
dashboard** connected to a GitHub repo — no `wrangler.toml`, no CLI, no
separately-deployed Worker. The only manual step is adding one KV
namespace binding in the dashboard (two clicks, covered below).

## How it works

- **Client-side crypto (`app.js`)**: each browser derives an AES-256 key
  from the room code using PBKDF2 (100,000 iterations, SHA-256). Every
  chat message is encrypted with AES-256-GCM (random 12-byte IV per
  message) before it's sent. Decryption also happens only in the browser.
- **Server-side relay (`functions/api/room/[code].js`)**: a Cloudflare
  Pages Function backed by a Workers KV namespace. `POST` stores a
  ciphertext string under a unique, time-ordered key; `GET` returns any
  ciphertext stored after the caller's last-seen cursor. The function
  never parses, decrypts, or logs message content, and every message
  auto-expires from KV after 10 minutes.
- **Transport**: the browser polls the API roughly every 1.2 seconds. This
  is not instant like a WebSocket, but it needs no Durable Objects, no
  standalone Worker, and no CLI deploy step — everything ships through a
  normal Git-connected Pages build.

### Why not WebSockets / Durable Objects?

An earlier version of this project used a Durable Object for real-time
WebSocket relay. Cloudflare Pages, however, requires a Durable Object's
class to be defined in a **separately deployed Worker** (referenced by
`script_name`) — it can't be defined inside the Pages project's own code.
That means a pure GitHub+dashboard workflow can't use Durable Objects
without an extra one-time `wrangler deploy` from the command line. Workers
KV, by contrast, can be created and bound entirely from the dashboard, so
this version uses that instead, trading instant delivery for zero-CLI
deployment.

If you do want true real-time delivery later and don't mind running the
CLI once, you can reintroduce a Durable-Object-based Worker and bind it
into this Pages project via `script_name` — ask if you'd like that version.

### Security & limits (read before using for anything sensitive)

- A 4-digit code has only 10,000 possibilities. Treat it like a shared
  "room key" for casual private chat with people you trust to have the
  code — **not** a strong secret against a determined attacker who can
  guess/brute-force room codes.
- No authentication, no message history beyond 10 minutes, no persistence
  after that TTL.
- Workers KV's free tier allows 1,000 writes/day and 100,000 reads/day
  **across your whole Cloudflare account**. Each sent message is one
  write; presence heartbeats are batched to roughly one write per client
  every ~9 seconds to conserve this budget. Casual use by a handful of
  people is fine; heavy sustained use may hit free-tier limits (upgrade
  the KV namespace's plan if needed).
- Anyone with the code can join and decrypt; there's no per-user identity
  verification.

## Project structure

Everything needed lives at the repo root plus one `functions/` folder —
Cloudflare Pages auto-detects `functions/` for serverless routes, no
config file required:

```
aes-room-chat/
├── index.html
├── style.css
├── app.js                        # AES-256-GCM crypto + polling client
└── functions/
    └── api/
        └── room/
            └── [code].js          # KV-backed relay: GET (poll) / POST (send)
```

## Local development

Requires [Node.js](https://nodejs.org) and the Cloudflare `wrangler` CLI
(only needed for local testing — not for deployment).

```bash
npm install -g wrangler
wrangler pages dev . --kv=ROOM_KV
```

Open the printed `http://localhost:8788` URL in two browser tabs, join
with the same 4-digit code, and chat.

## Deploying via GitHub + Cloudflare Pages

1. **Push this project to a GitHub repository** (repo root = these files,
   no extra wrapping folder).

   ```bash
   git init
   git add .
   git commit -m "Initial commit: AES room chat"
   git branch -M main
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   git push -u origin main
   ```

2. **Create the Pages project.**
   - Cloudflare dashboard → **Workers & Pages → Create application → Pages
     → Connect to Git**.
   - Select your repository.
   - Build settings:
     - **Framework preset:** None
     - **Build command:** *(leave empty)*
     - **Build output directory:** `/` (repo root — leave as default)
     - **Root directory:** *(leave empty)*
   - Click **Save and Deploy**. The first deploy will work for static
     files, but chat won't function yet — the API needs the KV binding
     from the next step.

3. **Create and bind a KV namespace (one-time, dashboard-only).**
   - Go to your Pages project → **Settings → Functions → KV namespace
     bindings → Add binding**.
   - **Variable name:** `ROOM_KV` (must match exactly — this is what
     `env.ROOM_KV` refers to in the code).
   - **KV namespace:** choose "Create new" if you don't have one yet, name
     it something like `aes-room-chat-kv`, then select it.
   - Save.

4. **Trigger a new deployment** so the binding takes effect — bindings
   only apply to deployments created *after* they're added:
   - **Deployments** tab → **⋯** on the latest deployment → **Retry
     deployment** does *not* pick up new bindings on some setups reliably,
     so the safest path is pushing a new commit (even an empty one):
     ```bash
     git commit --allow-empty -m "trigger redeploy with KV binding"
     git push
     ```

5. **Done.** Open your `*.pages.dev` URL in two tabs, join with the same
   4-digit code, and messages should appear within ~1–2 seconds of being
   sent. Every future push to `main` deploys automatically.

## Customizing

- **Longer/stronger codes**: change the `/^\d{4}$/` checks in both
  `app.js` and `functions/api/room/[code].js` to accept longer or
  alphanumeric codes for a much larger keyspace.
- **Poll speed**: adjust `POLL_INTERVAL_MS` in `app.js` (lower = snappier,
  but more KV reads).
- **Message retention**: change `MESSAGE_TTL_SECONDS` in
  `functions/api/room/[code].js`.
