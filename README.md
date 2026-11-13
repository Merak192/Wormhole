# Wormhole

A small, private messenger that runs entirely on **Cloudflare Pages + Workers KV**. No servers to manage, no database to provision, no build step.

- **Accounts** — username + password, plus a random 8-digit ID that friends use to add you.
- **Friends** — send / accept requests by ID.
- **Live chat** — device-to-device over WebRTC (via [Trystero](https://github.com/dmotz/trystero), signalled through public Nostr relays).
- **Persistent history** — every message is also saved to KV, AES-256-GCM encrypted, so a new device (or a reload) gets the conversation back.
- **Files** — streamed peer-to-peer in encrypted 128 KB chunks. The receiver must accept each file. Only *metadata* is ever stored in KV.
- **Receipts, recall, clear** — delivered / read ticks, 10-minute message recall, and a per-account "clear conversation" (messages **and** files).
- **Notifications** — desktop notifications for new messages and incoming file requests, with per-chat mute (see below).

---

## Project layout

```
index.html                    the whole front end (HTML + CSS + JS in one file)
sw.js                         service worker: shows notifications on Android, handles taps
manifest.webmanifest          app name/icons (lets phones install it as an app)
icon-192.png, icon-512.png    app / notification icons
_headers                      security headers / CSP
package.json                  wrangler scripts
wrangler.example.toml         optional: bindings as code
functions/
  _lib/auth.js                sessions, password hashing, rate limiting, request guards
  _lib/friends.js             pairing, encrypted history, receipts, clear ledger
  api/auth/                   register · login · logout · me
  api/friends/                request · respond · list · history · history-get · ack · recall · clear
  api/files/                  meta · meta-list
  api/presence/               beat · who
```

## Deploy

1. **Create a KV namespace** (Cloudflare dashboard → Storage & Databases → KV).
2. **Create a Pages project** from this repo (framework: *None*, build command: *none*, output directory: `/`).
3. **Bind the namespace:** Pages project → Settings → Bindings → *KV namespace* → variable name **`WORM_HOLE`**. Do this for both *Production* and *Preview*.
4. Deploy. Nothing else is required.

Optional environment variable: `PBKDF2_ITERATIONS` (10 000 – 100 000, default 100 000 — the Workers maximum). Each user record stores the iteration count it was hashed with, so changing it never locks anyone out.

Local development:

```bash
npm install
npm run dev        # wrangler pages dev . --kv WORM_HOLE   (local KV, no cloud needed)
npm run deploy     # wrangler pages deploy .
```

If you prefer bindings in code, rename `wrangler.example.toml` to `wrangler.toml` and fill in the namespace ids. Once that file exists the dashboard Bindings page becomes read-only.

---

## Notifications and mute

On first sign-in the app shows a small card asking to turn notifications on (browsers require a click; "Not now" asks again after 7 days). Once allowed:

- A new message or incoming file request shows a system notification with the sender's name and a short preview. There is one notification per chat, updated in place; clicking it opens that chat.
- Nothing pops up for the chat you are looking at while the window is visible and focused.
- The tab title shows the unread count, e.g. `(3) Messages`.
- **Mute** (Info panel or the chat menu) is per account and stored in the browser (`wh-muted:<id>` in localStorage), so it survives reloads. A muted chat gets no notification, no row pulse and is left out of the tab-title count; its unread badge still counts.
- A message that arrives both live (P2P) and from KV notifies once. Opening a chat for the first time in a session loads history silently.

The **bell button** in the sidebar footer shows the state and is the way back if you dismissed the card: lit = on (tap to pause everything without touching browser settings), dim = paused / not asked yet / blocked (tapping explains how to unblock in the browser).

**Android:** Chrome refuses `new Notification()` on phones, so all notifications go through the service worker (`sw.js`, served from the site root). Tapping one focuses the app and opens that chat. **iPhone:** only works for the app installed to the Home Screen (iOS 16.4+), via the manifest.

Limits: notifications work while the page is open, including as a background tab. There is no push server (Web Push would need a server-side sender), so nothing arrives after the app is fully closed.

---

## How data is stored in KV

Everything lives in **one** KV namespace (binding `WORM_HOLE`). There is no other database. KV is a flat key → string store, so the "tables" below are just key prefixes, and structured values are JSON strings.

Two user ids are always written in **canonical order** (`pair(a, b)` = the numerically/lexically smaller one first), so A→B and B→A resolve to the same key. Below, `<A>:<B>` means the sorted pair, `<U>`/`<P>` means *owner*/*peer* (directional).

| Key | Value | Written by | Lifetime |
|---|---|---|---|
| `user:id:<id>` | JSON user record | register | permanent |
| `user:name:<lowercase-name>` | the user's `<id>` (plain string) | register | permanent |
| `session:<sha256(token)>` | JSON `{ uid, exp }` | login / register | 7 days |
| `idx:<id>` | JSON array of peer ids | friend request / accept | permanent |
| `friend:<A>:<B>` | JSON `{ status, by, at }` | request / respond | permanent (deleted on decline) |
| `pairkey:<A>:<B>` | plain string: base64url 32-byte AES key | first request / first history write | permanent |
| `hist:<A>:<B>` | JSON array of message records | send / ack / recall / clear | refreshed to 10 y on every write |
| `clr:<U>:<P>` | JSON `{ ids: [msgId, …] }` | **U's** clear | refreshed to 10 y |
| `files:<A>:<B>` | JSON array of file metadata | send / receive | refreshed to 10 y |
| `present:<id>` | JSON `{ at }` | heartbeat | **15 seconds** |
| `rl:<bucket>` | JSON `{ n }` | rate limiter | 60 s – 1 h |

### Record shapes

**`user:id:<id>`**

```json
{
  "id": "48213907",
  "username": "Alice",
  "usernameLower": "alice",
  "pw": { "algo": "PBKDF2-SHA256", "hash": "…", "salt": "…", "iterations": 100000 },
  "createdAt": "2026-10-30T12:00:00.000Z"
}
```

Passwords are never stored; only a salted PBKDF2-SHA256 hash. Usernames start with a letter (3–20 chars of `A-Za-z0-9_`), so a username can never be confused with an 8-digit id at sign-in. IDs are uniformly random in `10000000–99999999`.

**`session:<sha256(token)>`** — the browser holds the random token in an `HttpOnly; SameSite=Lax` cookie (`wh_session`); KV only ever sees its SHA-256, so a KV read cannot be replayed as a login.

**`friend:<A>:<B>`** — `status` is `"pending"` or `"friend"`; `by` is who sent the request; `at` is a millisecond timestamp. A declined request is deleted.

**`idx:<id>`** — e.g. `["20481733","77120045"]`. A per-user index of every peer with a pending or accepted relation, so listing friends never needs a KV scan.

**`hist:<A>:<B>`** — an array, oldest first, capped at the newest **200** records:

```json
[{
  "id": "k3j9x0…",              // message id (also the P2P id)
  "from": "48213907",           // sender
  "c": "…base64url…",           // ciphertext, see below
  "at": 1761825600000,          // SERVER time when it was archived
  "seenBy": ["20481733"],       // delivered receipts — written only by the receiver
  "readBy": ["20481733"],       // read receipts — superset of seenBy
  "recalled": true,             // tombstone: `c` removed, id/from/at kept
  "recalledAt": 1761825650000,
  "hiddenBy": ["…"]             // legacy field from older versions; still honoured, no longer written
}]
```

`c` is one base64url string: `[ 12-byte random IV ][ ciphertext + 16-byte GCM tag ]`, AES-256-GCM, with the constant additional-data string `wh-msg`, keyed by that pair's `pairkey`. A recalled message is replaced by a **tombstone** (no `c`), so the ciphertext is really gone from KV but the peer's other devices learn the message was recalled.

**`clr:<U>:<P>`** — the *account-level cleared ledger*, see "Clear" below. Capped at the newest 600 ids.

**`files:<A>:<B>`** — capped at 100:

```json
[{ "fileId": "…", "name": "report.pdf", "type": "application/pdf", "size": 482113, "at": 1761825600000, "status": "sent" }]
```

`status` is `sending`, `sent` or `received`. File **content is never stored** — it only travels peer-to-peer.

**`present:<id>`** — a heartbeat that expires on its own after 15 s; a peer counts as online if the beat is under 5 s old.

**`rl:<bucket>`** — best-effort throttling counters. Buckets: `login:<ip>:<sha256(identifier)>` (5 failures / 15 min), `reg:<ip>` (10 accounts / hour), `frr:<ip>` (20 friend requests / hour). KV is eventually consistent, so add a Cloudflare WAF rate-limit rule on `/api/auth/*` if you need a hard cap.

### Clear conversation (per account, not per device)

Clearing belongs to the **account**:

1. Account A clears (on any device). The ids A's device was showing are added to A's ledger `clr:A:B`. A's other devices read that ledger on their next history poll and drop the same messages — including local caches. B is untouched and still sees everything.
2. When B clears the same messages, their ids are now in **both** ledgers, and the server **deletes those records from `hist`** (whichever account clears second triggers the delete).
3. Ledgers keep the ids after the records are gone, so a stale device can learn a message is gone and a late duplicate can't resurrect it.

**Files are cleared with the conversation.** Each file record is cleared under its chat-bubble id (`file-<fileId>`), so the "Shared files" list empties on every device of the account, the file's stored content in the browser (IndexedDB) is deleted, and the `files:` record is destroyed from KV once both accounts have cleared it. New messages and files after a clear show up normally.

### Concurrency & consistency

KV is **eventually consistent** (changes can take up to ~60 s to be visible everywhere) and has no transactions, so writers are written to be additive: receipt flags are owned by the receiver and only ever added, ledgers have one writer each, and every `hist` write re-reads before it writes. A write that lands in the same instant as another write to the *same* `hist` key can still lose one of them; this is a KV limitation.

---

## API

All endpoints are `POST` JSON unless marked `GET`, return `{ ok, … }` or `{ ok:false, error:{ code, message } }`, and require the session cookie except `register` / `login`.

| Endpoint | Purpose |
|---|---|
| `auth/register`, `auth/login`, `auth/logout`, `GET auth/me` | accounts and sessions |
| `friends/request`, `friends/respond`, `GET friends/list` | friend graph |
| `friends/history` | archive one message (the server encrypts it with the pair key) |
| `GET friends/history-get` | read my visible history `{ key, cleared:[id], msgs:[…] }` |
| `friends/ack` | delivered / read receipts |
| `friends/recall` | recall a message (10 min window) |
| `friends/clear` | clear for **my account** `{ uuid, ids? }` |
| `files/meta`, `GET files/meta-list` | file metadata |
| `presence/beat`, `GET presence/who` | online status |

Every state-changing request is also checked for same-origin `Origin`, on top of `SameSite=Lax` cookies.

## Security notes — read before trusting it

- **Encrypted at rest, but not zero-knowledge.** History is AES-GCM encrypted, but each chat's key sits in the **same KV namespace** (`pairkey:`) so new devices can recover history. That protects against a casual look at one `hist:` value; it does **not** protect against someone with full read access to the namespace (that includes you, the owner, and anyone with a Cloudflare API token for it). Guard the namespace like a database of plaintext.
- Live P2P traffic is DTLS-encrypted by WebRTC; file chunks add an extra per-chunk AES-GCM layer.
- Public Nostr relays are used only for WebRTC signalling (pinned list in `index.html`, `RELAY_URLS`). Swap in your own relays if you want to avoid third parties.
- Sessions last 7 days; passwords are 8–128 characters.

---

## Admin console (optional)

`admin.html` is a standalone page for **browsing and cleaning the KV namespace**. It is deployed as its **own** Pages project, separate from the chat app.

**What it does**

- Lists every key, filtered by type (users, sessions, chats, ledgers, …), with search, paging and expiry times.
- Opens any value: friendly views for users (password hash masked), message history, file metadata, friend index and cleared ledgers; raw JSON for the rest.
- **Decrypts chat history in your browser** on demand (it fetches that chat's `pairkey` and decrypts locally).
- Deletes single keys, a multi-selection, or *everything under a prefix*; removes individual messages / file records / ids from inside an array; edits raw values.
- **Delete user & all data** — account, username index, sessions, friendships, every chat and file list with their friends (both sides), and the id in friends' indexes. Needs a one-off *Scan all keys*.
- Destructive actions list exactly what will go; bulk and account-level ones require typing a confirmation word.

**Why there is a small server part:** a browser can't talk to KV directly, and Cloudflare's REST API blocks cross-origin calls. So the admin Pages project gets a ~50-line function that binds the *same* KV namespace and does the four operations the page needs, behind a secret token.

### Set it up

```
wormhole-admin/
├─ index.html              ← admin.html, renamed
├─ functions/api/admin.js  ← the function below
└─ _headers                ← optional: "/*"  then "  X-Robots-Tag: noindex"
```

1. Create the files above (copy the function from below).
2. `npx wrangler pages deploy . --project-name wormhole-admin`
3. In that project: Settings → Bindings → KV namespace → variable **`WORM_HOLE`** → pick the **same namespace** as the chat app (Production and Preview).
4. Set a long random secret: `npx wrangler pages secret put ADMIN_TOKEN --project-name wormhole-admin` (min. 16 characters; `openssl rand -base64 32` works).
5. Open the page, keep the endpoint `/api/admin`, paste the token.

> **Strongly recommended:** put the admin project behind **Cloudflare Access** (Zero Trust → Access → Applications) so only you can even load it. The token is a second lock, not the only one. The token is held in `sessionStorage` and cleared on *Disconnect*.

`functions/api/admin.js`:

```js
const MAX_BATCH = 100;

export async function onRequest({ request, env }) {
  const reply = (obj, status = 200) => new Response(JSON.stringify(obj), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

  const token = env.ADMIN_TOKEN;
  if (!env.WORM_HOLE) return reply({ error: 'KV binding WORM_HOLE is missing' }, 500);
  if (!token || token.length < 16) return reply({ error: 'ADMIN_TOKEN is not set (min 16 characters)' }, 503);

  const given = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!(await sameSecret(given, token))) return reply({ error: 'Unauthorized' }, 401);

  const url = new URL(request.url);
  const op = url.searchParams.get('op');
  const kv = env.WORM_HOLE;

  try {
    if (op === 'list' && request.method === 'GET') {
      const limit = Math.min(1000, Math.max(1, parseInt(url.searchParams.get('limit'), 10) || 200));
      const r = await kv.list({ prefix: url.searchParams.get('prefix') || '', cursor: url.searchParams.get('cursor') || undefined, limit });
      return reply({ keys: r.keys.map(k => ({ name: k.name, expiration: k.expiration || null })), list_complete: r.list_complete, cursor: r.cursor || null });
    }
    if (op === 'get' && request.method === 'GET') {
      const key = url.searchParams.get('key');
      if (!key) return reply({ error: 'key required' }, 400);
      const value = await kv.get(key);
      return reply({ key, exists: value !== null, value });
    }
    if (op === 'put' && request.method === 'POST') {
      const { key, value, expiration } = await request.json();
      if (typeof key !== 'string' || !key || typeof value !== 'string') return reply({ error: 'key and value (string) required' }, 400);
      const keep = Number(expiration) > Date.now() / 1000 + 120;   // KV needs a future expiry ≥ 60 s
      await kv.put(key, value, keep ? { expiration: Math.floor(Number(expiration)) } : undefined);
      return reply({ ok: true });
    }
    if (op === 'delete' && request.method === 'POST') {
      const { keys } = await request.json();
      if (!Array.isArray(keys) || !keys.length || keys.length > MAX_BATCH || keys.some(k => typeof k !== 'string' || !k)) {
        return reply({ error: `keys must be 1–${MAX_BATCH} strings` }, 400);
      }
      await Promise.all(keys.map(k => kv.delete(k)));
      return reply({ ok: true, deleted: keys.length });
    }
    return reply({ error: 'Unknown operation' }, 400);
  } catch (e) {
    return reply({ error: String(e && e.message || e) }, 500);
  }
}

// Constant-time comparison (hash both sides first so lengths don't leak).
async function sameSecret(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([a, b].map(async s => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(s)))));
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
```

**Hosting the admin page somewhere that isn't Cloudflare** (Netlify, Vercel, …): the HTML works anywhere, but KV can't be bound there. Implement the same four operations (`list`, `get`, `put`, `delete`) in that host's function using the [Cloudflare KV REST API](https://developers.cloudflare.com/api/resources/kv/) (`/accounts/{id}/storage/kv/namespaces/{ns}/keys`, `/values/{key}`, `/bulk/delete`) with an API token that has *Workers KV Storage: Edit*, and keep the same request/response shapes as above.

### Admin cautions

- Deleting `user:*`, `session:*` or `pairkey:*` keys signs people out, removes accounts, or makes stored history permanently unreadable. There is no undo; KV has no backups.
- Editing `hist:` / `clr:` / `idx:` while people are chatting can race the live app. Prefer the per-item **Remove** buttons over *Edit raw*, and do bulk work when the app is quiet.
- Counts and *Delete user & all data* rely on a scan; run *Rescan* first if the data changed.

---

## Known limits

- History is capped at the newest 200 messages per chat, file metadata at 100 per chat.
- A message cleared by one account stays on the other account until *they* clear it too (by design).
- Live delivery needs both devices online and able to reach a relay and each other (WebRTC); otherwise messages arrive from KV history on the next poll.
- KV's eventual consistency means other devices can take up to about a minute to reflect a change made from a different region.
