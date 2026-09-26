# AES Room Chat

A tiny room-based chat app where two or more people join with the same
**4-digit code** and exchange **AES-256-GCM encrypted** messages
**directly, peer-to-peer**. There is no custom backend at all — no
Cloudflare Function, no KV, no Worker, no `wrangler.toml`. This is a plain
static site: three files, deployed straight from GitHub.

## How it works

Two distinct things happen, and only one of them ever touches anything
outside your own browser and the other person's:

1. **Finding each other** — WebRTC needs a way for two browsers to
   exchange a small amount of connection information before they can talk
   directly. This project uses [Trystero](https://github.com/dmotz/trystero),
   a library that handles this using existing public infrastructure (by
   default, the Nostr network) instead of a custom server. Your room code
   is used directly as the "room" identifier Trystero matches people on.
   Trystero also encrypts this connection-setup metadata in transit using
   a key derived from your room code.
2. **Chatting** — once two browsers find each other this way, they open a
   direct `RTCDataChannel`. From that point on, every message is
   encrypted with **AES-256-GCM** (key derived from the room code via
   PBKDF2, 100,000 iterations) and sent straight over that channel.
   WebRTC data channels are also always DTLS-encrypted in transit as part
   of the protocol itself — so message content is protected twice over,
   and nothing outside the two browsers involved ever has a way to read
   it, encrypted or not.

For 3+ participants, every browser connects directly to every other
browser (a mesh) — simple and fine for a handful of people, less so for
large groups.

### Why this is fast

There's no store-then-poll round trip and no custom relay server at all —
once connected, messages travel directly from one browser's
`chatAction.send()` to the other's `onMessage` handler, typically with
network-ping-level latency. Connection setup itself (finding the other
person via Trystero) is usually quick — commonly under a couple of
seconds — since it rides on existing, actively-used public relay
infrastructure rather than a small custom store.

### Network limitations (please read)

- WebRTC needs to negotiate a direct path between two computers, which
  usually means traversing NAT. Trystero configures sensible default STUN
  servers for this, which works for the great majority of home and office
  networks.
- **No TURN relay is configured.** TURN is what allows a connection to
  succeed even when both sides are behind especially restrictive NATs —
  but running one isn't free, so it's intentionally left out here. If two
  specific people can't connect, chat between just that pair won't work;
  everyone else in the room is unaffected. See Trystero's own
  [troubleshooting notes](https://github.com/dmotz/trystero#troubleshooting-connection-issues)
  if you want to add a TURN server later (including a free tier from
  Cloudflare itself, ironically) — you'd pass it via `rtcConfig` /
  `turnConfig` in the `joinRoom()` call in `app.js`.

### Security notes

- A 4-digit code has only 10,000 possibilities. Treat it like a shared
  "room key" for casual private chat with people you trust to have the
  code — **not** a strong secret against a determined attacker who can
  guess/brute-force room codes.
- Connection-setup metadata (which briefly passes through Trystero's
  public relays) can include IP-address-revealing details, same as any
  WebRTC app (video calling apps work the same way) — this is inherent to
  peer-to-peer connections, not specific to this project.
- No authentication beyond knowing the room code; no message history —
  closing the tab ends the conversation, nothing is ever written to disk,
  anywhere.

## Project structure

```
aes-room-chat/
├── index.html
├── style.css
└── app.js   # AES-256-GCM crypto + Trystero-based P2P mesh client
```

That's the entire project. No `functions/`, no `wrangler.toml`, no
server-side code whatsoever.

## Local development

Since there's no backend, you can just open `index.html` directly, or
serve the folder with any static file server, e.g.:

```bash
npx serve .
```

Open the printed URL in two browser tabs (or better, two different
devices), join with the same 4-digit code, and chat.

## Deploying via GitHub + Cloudflare Pages

1. **Push this project to a GitHub repository** (repo root = these three
   files, no wrapping folder).

   ```bash
   git init
   git add .
   git commit -m "AES room chat: peer-to-peer via Trystero"
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
   - Click **Save and Deploy**.

3. **Done.** No bindings, no KV, no Functions, nothing else to configure.
   Open your `*.pages.dev` URL on two different devices, join with the
   same 4-digit code, and chat.

## Customizing

- **Longer/stronger codes**: change the `/^\d{4}$/` check in `app.js`.
- **Add a TURN server for reliability across all networks**: pass
  `rtcConfig` / `turnConfig` in the `joinRoom()` call — see
  [Trystero's docs](https://github.com/dmotz/trystero#troubleshooting-connection-issues).
- **Switch matchmaking network**: by default this uses Trystero's Nostr
  strategy (`https://esm.run/trystero`). Trystero also supports
  BitTorrent, MQTT, IPFS, Supabase, and Firebase as alternatives — swap
  the import in `app.js` (see Trystero's README for the exact package
  names) if you'd like to try a different one.
