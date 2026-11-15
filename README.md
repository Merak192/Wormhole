# Wormhole

A small, private messenger that runs entirely on **Cloudflare Pages + Workers KV**. There are no servers to manage, no database to provision and no build step: one static page, a handful of serverless functions, and one KV namespace.

| | |
|---|---|
| **Accounts** | Username + password. Every account also gets a random 8-digit ID that friends use to find you. |
| **Friends** | Send and accept friend requests by ID. |
| **Live chat** | Device to device over WebRTC ([Trystero](https://github.com/dmotz/trystero), signalled through public Nostr relays), with a KV fallback when a direct channel can't be opened. |
| **History** | Every message is also saved to KV, AES-GCM encrypted, so a new device or a reload gets the conversation back. |
| **Files** | Streamed peer to peer in encrypted 128 KB chunks. The receiver must accept each file. Only metadata is ever stored in KV. |
| **Receipts, recall, clear** | Delivered and read ticks, a 10-minute message recall, and a per-account "clear conversation" that also clears the shared-files list. |
| **Typing indicator** | Live "typing…" status (can be turned off). |
| **Notifications** | Desktop notifications for new messages and file requests, with per-chat mute. |
| **Settings** | Theme, language, text size, compact mode, reduced motion, notification options, message options and the encryption method, all stored in the browser. |
| **Six languages** | English, 中文, Français, Русский, Español and العربية (the UN's official languages), with a right-to-left layout for Arabic. |

---

## Contents

1. [How it works](#how-it-works)
2. [Project layout](#project-layout)
3. [Deploy](#deploy)
4. [Using the app](#using-the-app)
5. [Settings](#settings)
6. [Languages](#languages)
7. [Encryption and privacy](#encryption-and-privacy)
8. [Data model (KV)](#data-model-kv)
9. [API](#api)
10. [Browser storage](#browser-storage)
11. [Security notes](#security-notes)
12. [Limits](#limits)
13. [Troubleshooting](#troubleshooting)

---

## How it works

```
                     ┌──────────────────────── Cloudflare ────────────────────────┐
  Browser A ─ HTTPS ─┤  Pages (index.html)   Pages Functions (/api/*)  ─►  KV      │
  Browser B ─ HTTPS ─┤                       accounts · friends · history · files   │
                     └─────────────────────────────────────────────────────────────┘
       │                                                                  ▲
       └──────── WebRTC data channel (live messages, file chunks) ────────┘
                 found via public Nostr relays (signalling only)
```

- **Two delivery paths.** The live path is a direct WebRTC channel between the two browsers. The archive path is KV: every message is written there (encrypted) and every client polls it, once a second while the direct channel to a friend isn't open and about every 4 seconds while it is (that is how read and delivered ticks catch up). A message always arrives, even if the other person opens the page later or the channel never comes up.
- **No server-side session memory.** A session is a random token in an `HttpOnly` cookie; KV only stores its SHA-256.
- **Presence.** Each open tab sends a heartbeat; a person counts as online while their heartbeat key (15-second TTL) exists in KV, or while the direct channel to them is up.
- **Files never touch KV.** The bytes travel over the data channel; KV only holds a small metadata record so a file reappears in the *Shared files* list on a new device.

---

## Project layout

```
index.html                     the whole front end: HTML + CSS + JS + UI translations, one file
_headers                       security headers and Content-Security-Policy
package.json                   wrangler scripts (dev / deploy)
wrangler.example.toml          optional: KV binding as code
functions/
  _lib/auth.js                 sessions, password hashing, rate limiting, request guards
  _lib/friends.js              pairing, encrypted history, receipts, cleared ledger, file metadata
  api/auth/                    register · login · logout · me
  api/friends/                 request · respond · list · history · history-get · ack · recall · clear
  api/files/                   meta · meta-list
  api/presence/                beat · who
```

There is nothing to compile. `index.html` is served as-is, and every file under `functions/` becomes a route (`functions/api/auth/login.js` → `POST /api/auth/login`).

---

## Deploy

**Requirements:** a Cloudflare account (the free plan works) and, for the command-line route, Node.js.

### From the dashboard

1. **Create a KV namespace:** Storage & Databases → KV → *Create*.
2. **Create a Pages project** from this repository: framework preset *None*, build command *empty*, output directory `/`.
3. **Bind the namespace:** the project's Settings → Bindings → *KV namespace* → variable name **`WORM_HOLE`**. Do this for **both** Production and Preview.
4. Deploy. Nothing else is required.

### From the command line

```bash
npm install
npm run deploy        # wrangler pages deploy .
```

The first deploy creates the Pages project; add the `WORM_HOLE` KV binding in the dashboard as in step 3 above and deploy again.

### Local development

```bash
npm install
npm run dev           # wrangler pages dev . --kv WORM_HOLE   (local KV, no cloud account needed)
```

### Optional configuration

| Setting | Where | Default | Meaning |
|---|---|---|---|
| `PBKDF2_ITERATIONS` | environment variable | `100000` | Password-hash cost, clamped to 10 000 – 100 000 (the Workers maximum). Each user record stores the count it was hashed with, so changing it never locks anyone out. |
| Bindings as code | rename `wrangler.example.toml` to `wrangler.toml` | – | Fill in the namespace ids. Once this file exists the dashboard's Bindings page becomes read-only. |
| Signalling relays | `RELAY_URLS` in `index.html` | 4 public Nostr relays | Swap in your own to avoid third parties. |

> **Updating an existing deployment:** deploy the whole project again, not just `index.html`. The browser and the functions evolve together (for example the encryption method and the shared-files clearing need both sides).

---

## Using the app

**Sign up / sign in.** Create an account with a username (3–20 letters, digits or `_`, starting with a letter) and a password (8–128 characters). You can sign in with the username or the 8-digit ID. The ID is shown after registration and in the sidebar footer; it can't be changed.

**Add a friend.** The **+** button in the sidebar takes their 8-digit ID and sends a request. Incoming requests appear above the conversation list with *Accept* / *Decline*.

**Chat.**
- **Enter** sends and **Shift+Enter** adds a line (or the reverse, see [Messages settings](#messages-settings)).
- Hover (or tap) a message of yours for **Copy** and **Recall**. Recall works for 10 minutes; the text is removed from KV and the other side shows "Message recalled".
- Ticks show the state of your messages: sent, delivered, read.
- **Ctrl/⌘ + K** focuses conversation search; the search icon in the chat header searches inside the open chat.

**Send files.** Use the paperclip, drag a file onto the chat, or paste from the clipboard. The other person gets an *Accept / Decline* card; nothing is transferred until they accept. Images open in a viewer with zoom and arrow-key navigation; videos and audio play inline.

**Contact panel.** Mute notifications, search the chat, see the ID and local time of the other person, and browse *Shared files*.

**Clear conversation** (chat menu). Hides the messages **and the shared files** of that chat for your account on every device. The other person keeps their copy until they clear it too; when both have, the records are deleted from KV. New messages and files after a clear appear normally. See [Clearing a conversation](#clearing-a-conversation).

**Notifications and mute.**
- On first sign-in a small card asks to turn notifications on (browsers need a click). *Not now* asks again after 7 days.
- A new message or file request shows a system notification with the sender's name and a short preview. There is one notification per chat, updated in place; clicking it opens the chat.
- Nothing pops up for the chat you are looking at while the window is visible and focused.
- The tab title shows the unread count, for example `(3) Messages`.
- **Mute** (contact panel or chat menu) is per account and stored in the browser. A muted chat gets no notification and is left out of the tab-title count; its unread badge still counts.
- Notifications work while the page is open, including as a background tab. There is no push server, so nothing arrives after the app is fully closed. Some mobile browsers only allow notifications through a service worker, which this project does not include.

---

## Settings

The **gear** button in the sidebar footer opens a dialog over a blurred app: sections on the left, options on the right. Everything here is personal to the browser (see [Browser storage](#browser-storage)); the only thing that reaches the server is the encryption method of the messages you send.

### Appearance

| Option | Values | Notes |
|---|---|---|
| Theme | Light · Dark · System | *System* follows the OS and reacts when it changes. The sign-in screen has its own small theme toggle. |
| Language | Auto · English · 中文 · Français · Русский · Español · العربية | See [Languages](#languages). |
| Text size | Small · Default · Large | Scales text across the whole app. |
| Compact messages | on / off | Tighter spacing between messages. |
| Reduce motion | on / off | Fewer sliding and fading effects. The OS "reduce motion" setting is honoured as well. |

### Notifications

| Option | Notes |
|---|---|
| Desktop notifications | The master switch. It asks the browser for permission when needed, and explains when notifications are blocked or unsupported. Turning it off pauses alerts without touching browser settings. |
| Show message preview | Off: alerts only say "New message". |
| Send a test alert | Shows how a notification looks. |
| Unread count in tab title | Toggles the `(3) Messages` prefix. |
| Muted chats | Lists muted chats with an *Unmute* button each. |

### Messages settings

| Option | Notes |
|---|---|
| Enter sends message | On: Enter sends. Off: Ctrl/⌘ + Enter sends and Enter adds a new line. |
| Time format | Auto · 12-hour · 24-hour. Applies to chats and the conversation list immediately. |
| Read receipts | Off: people see your replies as delivered but never as read. |
| Typing indicator | Off: people don't see when you're typing. |

### Encryption

Choose the method used for what you send: **AES-256** (default, recommended) or **AES-128**. Details in [Encryption and privacy](#encryption-and-privacy).

**Reset to defaults** (bottom of the section list) restores every option, including theme and language.

---

## Languages

The interface ships in the six official UN languages: **English, 中文 (简体), Français, Русский, Español, العربية**. Pick one in *Settings → Appearance → Language*, or leave it on **Auto**, which follows the browser's language and falls back to English. The choice is saved in the browser and applied to `<html lang dir>` before the first paint.

- **Everything is translated:** the interface, toasts, notifications, sign-in screens, date labels, and the server's error messages (translated in the browser).
- **Arabic is right-to-left.** The layout mirrors: the sidebar sits on the right, your own messages on the left, and panels and menus slide in from the mirrored side. Message text uses `dir="auto"`, so mixed Arabic / English chats read correctly.
- **Dates and times** use the language's locale (Arabic uses Latin digits, like the 8-digit IDs).

**How it works.** English text is the key. The code calls `tr('Some text', { vars })`, which looks the text up in `window.WH_I18N[lang]` and falls back to the English itself, so a missing translation never breaks the UI. The dictionary is the `/*i18n:start*/ … /*i18n:end*/` block in the `<head>` of `index.html`, so the app has no separate translation file to deploy. Static markup keeps its English text; at start-up every known text node and `placeholder` / `aria-label` / `title` is registered once and re-written on each language change.

**Adding a language:**
1. Add an entry to `LANGS` in the main script (`code`, native `name`, `html` language tag, `locale`, `dir`).
2. Add the code to the allowed list in the small `<head>` script that sets `lang` / `dir` before first paint.
3. Add a block for it to `WH_I18N` with the same keys as the others (copy a block and translate the values; keep `{placeholders}` intact).
4. For a right-to-left language, the `:root[dir="rtl"]` rules at the end of the stylesheet already apply.

---

## Encryption and privacy

| Data | Protection |
|---|---|
| Live messages | Sent over a WebRTC data channel, which the browser encrypts (DTLS). |
| Message archive in KV | AES-GCM with a per-pair key, encrypted by the server. |
| File bytes | Never stored. Sent over the data channel in 128 KB chunks, each chunk encrypted with AES-GCM in the browser on top of DTLS. |
| Passwords | Salted PBKDF2-SHA256 hash (default 100 000 iterations); the password itself is never stored. |
| Sessions | Random token in an `HttpOnly; SameSite=Lax` cookie (`Secure` on https); KV holds only its SHA-256, so a KV read can't be replayed as a login. |

### Choosing AES-256 or AES-128

The **sender** picks the method and every encrypted item carries it, so the reader never needs to know the sender's setting:

- **Message archive:** the browser sends `alg` with `POST /api/friends/history`; the server encrypts with it and stores it on the record as `a`. A missing `a` (records from before this option existed) means AES-256-GCM. An unknown `alg` is rejected with `400 invalid_alg`. `history-get` returns each message's `alg`.
- **Files:** the offer and every `file-chunk` frame carry `alg`; the receiver decrypts each chunk with the method named in that chunk (missing or unknown = AES-256-GCM).
- **Keys:** AES-256-GCM uses the pair key directly. AES-128-GCM uses a 128-bit key derived from the same pair key with HKDF-SHA-256 (zero salt, info `wh-aes-128-gcm`), computed identically on the server and in the browser, so no extra key is stored.
- **Not affected:** live P2P messages (WebRTC's own encryption) and messages already sent. Each keeps the method it was sent with, so changing the setting never makes old history unreadable, and people can always read what you send.

AES-128 is still considered secure; AES-256 has the larger safety margin and is the default.

> **Read this before trusting it.** The archive is encrypted at rest but **not zero-knowledge**: each chat's key sits in the same KV namespace (`pairkey:`) so that new devices can recover history. That protects against a casual look at one `hist:` value; it does **not** protect against someone with full read access to the namespace, which includes you as the owner and anyone with a Cloudflare API token for it. Treat the namespace like a database of plaintext.

---

## Data model (KV)

Everything lives in **one** KV namespace (binding `WORM_HOLE`). KV is a flat key → string store, so the "tables" below are key prefixes and structured values are JSON strings. User ids in pair keys are always written in **canonical order** (the lexically smaller first), so A→B and B→A resolve to the same key. `<A>:<B>` below means that sorted pair; `<U>` / `<P>` means owner / peer (directional).

| Key | Value | Written by | Lifetime |
|---|---|---|---|
| `user:id:<id>` | JSON user record | register | permanent |
| `user:name:<lowercase-name>` | the user's `<id>` | register | permanent |
| `session:<sha256(token)>` | JSON `{ uid, exp }` | login / register | 7 days |
| `idx:<id>` | JSON array of peer ids | friend request / accept | permanent |
| `friend:<A>:<B>` | JSON `{ status, by, at }` | request / respond | permanent (deleted on decline) |
| `pairkey:<A>:<B>` | base64url 32-byte AES key | first request / first history write | permanent |
| `hist:<A>:<B>` | JSON array of message records | send / ack / recall / clear | refreshed to 10 years on every write |
| `clr:<U>:<P>` | JSON `{ ids: [...] }` | **U's** clear | refreshed to 10 years |
| `files:<A>:<B>` | JSON array of file metadata | send / receive / clear | refreshed to 10 years |
| `present:<id>` | JSON `{ at }` | heartbeat | 15 seconds |
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

Usernames start with a letter (3–20 characters of `A-Za-z0-9_`), so a username can never be confused with an 8-digit ID at sign-in. IDs are uniformly random in `10000000–99999999`.

**`friend:<A>:<B>`**: `status` is `"pending"` or `"friend"`, `by` is who sent the request, `at` is a millisecond timestamp. **`idx:<id>`** is a per-user list of every peer with a pending or accepted relation, so listing friends never needs a KV scan.

**`hist:<A>:<B>`** is an array, oldest first, capped at the newest **200** records:

```jsonc
[{
  "id": "k3j9x0…",              // message id (also the P2P id)
  "from": "48213907",           // sender
  "c": "…base64url…",           // ciphertext, see below
  "a": "A256GCM",               // method used for `c`: A256GCM | A128GCM (absent = A256GCM)
  "at": 1761825600000,          // SERVER time when it was archived
  "seenBy": ["20481733"],       // delivered receipts, written only by the receiver
  "readBy": ["20481733"],       // read receipts (a superset of seenBy)
  "recalled": true,             // tombstone: `c` removed, id/from/at kept
  "recalledAt": 1761825650000,
  "hiddenBy": ["…"]             // legacy field from older versions; still honoured, no longer written
}]
```

`c` is one base64url string: `[ 12-byte random IV ][ ciphertext + 16-byte GCM tag ]`, AES-GCM with the constant additional-data string `wh-msg`, keyed by the pair's `pairkey` (or the HKDF-derived key for AES-128). A recalled message becomes a **tombstone** with no `c`: the ciphertext is really gone from KV, but the other person's devices learn it was recalled.

**`clr:<U>:<P>`** is the account-level *cleared ledger* (below), capped at the newest 600 ids.

**`files:<A>:<B>`** is capped at 100 records:

```json
[{ "fileId": "…", "name": "report.pdf", "type": "application/pdf", "size": 482113, "at": 1761825600000, "status": "sent" }]
```

`status` is `sending`, `sent` or `received`. File **content is never stored**.

**`rl:<bucket>`** are best-effort throttling counters: `login:<ip>:<sha256(identifier)>` (5 failures per 15 minutes), `reg:<ip>` (10 accounts per hour), `frr:<ip>` (20 friend requests per hour). KV is eventually consistent, so add a Cloudflare WAF rate-limit rule on `/api/auth/*` if you need a hard cap.

### Clearing a conversation

Clearing belongs to the **account**, not the device:

1. Account A clears (on any device). The ids that device was showing, plus the ids of the files in the *Shared files* list, are added to A's ledger `clr:A:B`. A's other devices read that ledger on their next history poll and drop the same messages, local caches and stored file content. B is untouched and still sees everything.
2. When B clears the same messages, their ids are in **both** ledgers and the server **deletes those records from `hist`**. Whichever account clears second triggers the delete.
3. Ledgers keep the ids after the records are gone, so a stale device can learn a message is gone and a late duplicate can't bring it back.

**Shared files follow the chat.** A file's chat bubble has the message id `file-<fileId>`. The *Shared files* list shows only files that are still part of the conversation:
- `GET /api/files/meta-list` leaves out files the caller's account cleared (it accepts either `file-<fileId>` or the bare `fileId` in the ledger);
- the browser filters the list with its own copy of the ledger as well;
- a file's metadata record is destroyed once **both** accounts have cleared it;
- files still being transferred keep their bubble and stay listed.

### Consistency

KV is **eventually consistent** (changes can take up to about a minute to be visible everywhere) and has no transactions. Writers are therefore additive: receipt flags are owned by the receiver and only ever added, ledgers have one writer each, and every `hist` write re-reads before it writes. Two writes to the *same* `hist` key in the same instant can still lose one of them; that is a KV limitation.

---

## API

All endpoints take and return JSON, answer with `{ ok: true, … }` or `{ ok: false, error: { code, message } }`, and require the session cookie except `register` and `login`. Methods are `POST` unless marked `GET`. Every state-changing request also has its `Origin` checked against the site, on top of `SameSite=Lax`.

| Endpoint | Purpose |
|---|---|
| `auth/register`, `auth/login`, `auth/logout`, `GET auth/me` | accounts and sessions |
| `friends/request`, `friends/respond`, `GET friends/list` | friend graph |
| `friends/history` | archive one message `{ uuid, text, id?, alg? }`; the server encrypts it |
| `GET friends/history-get?uuid=` | my visible history `{ key, cleared: [id], msgs: [...] }`; each message includes `alg` |
| `friends/ack` | delivered / read receipts |
| `friends/recall` | recall a message (10-minute window plus a 15-second grace) |
| `friends/clear` | clear for **my account** `{ uuid, ids? }` |
| `files/meta`, `GET files/meta-list?uuid=` | file metadata (the list excludes files my account cleared) |
| `presence/beat`, `GET presence/who?uuid=` | online status |

Error messages are English; the browser translates the known ones.

### Live (peer-to-peer) messages

Sent over the WebRTC data channel as small objects with a `kind`: `msg`, `read`, `seen`, `typing`, `recall`, and for files `file-offer`, `file-accept`, `file-reject`, `file-chunk` and `file-done`. The room name is derived from the sorted pair of ids, so both sides join the same room without any extra round trip.

---

## Browser storage

| Where | Key | Holds |
|---|---|---|
| `localStorage` | `wh-settings` | JSON of all personal settings except theme: `textSize`, `compact`, `reduceMotion`, `notify`, `preview`, `titleCount`, `enterSend`, `timeFmt`, `readReceipts`, `typing`, `lang` (`auto` or a language code), `encryption` (`A256GCM` or `A128GCM`) |
| `localStorage` | `chat-theme` | `light` or `dark`; absent means follow the system (read before first paint) |
| `localStorage` | `wh-muted:<id>` | muted chats of the signed-in account |
| `localStorage` | `wh-cache:<id>` | local copy of recent messages |
| `localStorage` | `wh-cleared:<id>` | this device's copy of the account's cleared-ids ledger |
| `localStorage` | `wh-notif-ask` | when "Not now" was chosen on the notification card |
| IndexedDB | `wormhole-files` | the content of files sent or received on this device |

Deleting browser data removes settings and local file content, never the account or the KV archive.

---

## Security notes

- The archive is encrypted at rest but not zero-knowledge; see the warning under [Encryption and privacy](#encryption-and-privacy).
- Live traffic is encrypted by WebRTC; file chunks add a per-chunk AES-GCM layer.
- Public Nostr relays are used **only** for WebRTC signalling; message content never goes through them. The relay list is pinned in `index.html` (`RELAY_URLS`).
- The Trystero library is loaded from jsDelivr (version pinned to `0.26.0`). The Content-Security-Policy in `_headers` allows that origin, WebSocket connections for the relays, `blob:` for received images and media, and nothing else third-party.
- Sessions last 7 days. Passwords are 8–128 characters. Login attempts are throttled per IP and identifier.
- `_headers` also sets `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and a restrictive `Permissions-Policy`.
- If you run this for other people, guard the KV namespace and your Cloudflare API tokens accordingly: they can read everything, including pair keys.

---

## Limits

- History is capped at the newest **200** messages per chat; file metadata at **100** per chat; messages at **2000** characters.
- A message cleared by one account stays visible to the other account until *they* clear it too (by design).
- Live delivery needs both devices online and able to reach a relay and each other (WebRTC, with no TURN server configured). When the direct channel can't be opened, messages still arrive through the KV archive on the next poll, but typing indicators and file transfers need the direct channel.
- KV's eventual consistency means other devices may take up to about a minute to reflect a change made from a different region.
- Notifications need the page to be open (a background tab is fine) and a secure (https) origin.

---

## Troubleshooting

| Symptom | What to check |
|---|---|
| Every API call fails with *Server is missing the WORM_HOLE KV binding* | The KV namespace isn't bound. Add the binding named exactly `WORM_HOLE` for Production **and** Preview, then redeploy. |
| The language (or another new feature) doesn't change after an update | The browser is serving the old page. Hard refresh (Ctrl/⌘ + Shift + R) and make sure the new `index.html` is what's deployed. |
| Messages arrive but files or "typing…" don't | The direct WebRTC channel isn't up (restrictive network, blocked relays). Try another network, or set your own relays in `RELAY_URLS`. |
| Notifications never appear | The site must be on https and the permission must be *Allow* in the browser's site settings; also check *Settings → Notifications* isn't paused and the chat isn't muted. |
| "Too many attempts" at sign-in | The login throttle (5 failures per 15 minutes per IP and account) kicked in; wait and retry. |
