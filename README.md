# Worm Hole

Instant-chat front-end with a Cloudflare Pages Functions backend. This stage covers **accounts**: register, sign in, sessions. Users live in Workers KV, bound as `WORM_HOLE`.

```
public/                     static site (build output directory)
  index.html                chat UI + sign-in / register gate
  _headers                  security headers + CSP
functions/
  _lib/auth.js              hashing, sessions, validation, rate limiting
  api/auth/register.js      POST /api/auth/register
  api/auth/login.js         POST /api/auth/login
  api/auth/logout.js        POST /api/auth/logout
  api/auth/me.js            GET  /api/auth/me
test/auth.test.mjs          backend tests (in-memory KV)
wrangler.example.toml       optional, see "Bindings in code"
```

## Deploy (GitHub → Cloudflare Pages)

1. **Push this folder to your GitHub repo** (the repo root must contain `public/` and `functions/`).
2. **Create the KV namespace**: Cloudflare dashboard → *Storage & databases* → *KV* → *Create* (any name, e.g. `worm-hole-users`).
3. **Create the Pages project**: *Workers & Pages* → *Create* → *Pages* → *Connect to Git* → pick the repo.
   - Framework preset: **None**
   - Build command: *(leave empty)*
   - Build output directory: **`public`**
4. **Bind the KV**: Pages project → *Settings* → *Bindings* → *Add* → *KV namespace*
   - Variable name: **`WORM_HOLE`** (exactly, case-sensitive)
   - KV namespace: the one from step 2
   - Add it for both **Production** and **Preview**.
5. **Redeploy** (*Deployments* → latest → *Retry deployment*, or push a commit). Bindings only take effect on a new deployment.

Open the site: you should see the sign-in screen. If the card says *"Server is missing the WORM_HOLE KV binding"*, step 4 or 5 was missed.

### Bindings in code (optional)
If you prefer config-as-code, rename `wrangler.example.toml` to `wrangler.toml` and fill in the namespace IDs. Once that file exists, the dashboard's Bindings page becomes read-only, so use one approach or the other.

### Optional variable
`PBKDF2_ITERATIONS` (default and maximum `100000`, minimum `10000`). If you are on the Workers **Free** plan and see CPU-limit errors (code 1102) on register/login, set this lower (e.g. `50000`). Existing users are unaffected, since each record stores the iteration count it was hashed with.

## Local development

```bash
npm install
npm run dev      # wrangler pages dev public --kv WORM_HOLE  → http://localhost:8788
npm test         # backend tests
```
Local KV data is kept in `.wrangler/state` (git-ignored).

## How it works

**Register**: username, password, confirm password. The server validates, then generates a random **8-digit ID** (10000000–99999999, uniform, collision-checked), hashes the password, stores the user, and signs them in. The UI then shows the ID once, with a Copy button.

**Sign in**: *Username or ID* plus password. Eight digits means an ID lookup; anything else is a username lookup (case-insensitive). Usernames must start with a letter, so the two can never be confused.

**Sessions**: a random 256-bit token in an `HttpOnly; SameSite=Lax` cookie (`Secure` on HTTPS), valid 7 days. KV stores only its SHA-256. `GET /api/auth/me` is how the page decides whether to show the gate.

### API

| Method & path | Body | Success |
|---|---|---|
| `POST /api/auth/register` | `{ username, password, confirm }` | `201 { ok, user:{id,username,createdAt} }` + cookie |
| `POST /api/auth/login` | `{ identifier, password }` | `200 { ok, user }` + cookie |
| `POST /api/auth/logout` | none | `200 { ok }`, cookie cleared |
| `GET  /api/auth/me` | none | `200 { ok, user }` or `401` |

Errors: `{ ok:false, error:{ code, message, field? } }`. Codes: `invalid_username`, `weak_password`, `password_mismatch`, `username_taken` (409), `invalid_credentials` (401), `rate_limited` (429), `bad_origin` (403), `misconfigured` (500).

Rules: username 3–20 chars `[A-Za-z][A-Za-z0-9_]*`, unique case-insensitively; password 8–128 chars.

### KV layout

| Key | Value | TTL |
|---|---|---|
| `user:name:<lowercase username>` | the user's ID | none |
| `user:id:<8-digit id>` | `{ id, username, usernameLower, pw:{algo,hash,salt,iterations}, createdAt }` | none |
| `session:<sha256(token)>` | `{ uid, exp }` | 7 days |
| `rl:<bucket>` | `{ n }` attempt counter | 60 s – 15 min |

## Security notes

- Passwords: PBKDF2-SHA-256, per-user 16-byte salt, constant-time compare. Plaintext is never stored or logged.
- Wrong user and wrong password return the identical `401`, and the unknown-user path does a dummy hash, so accounts can't be enumerated by message or timing. (The register form does reveal whether a username is taken, which is unavoidable.)
- Brute force: 5 failed attempts per (IP, account) lock sign-in for 15 minutes; 10 registrations per IP per hour.
- CSRF: `SameSite=Lax` cookie plus an `Origin` check on every POST. XSS: strict CSP in `public/_headers`, and all user text is escaped before rendering.

### Known limits (KV is not a database)
- **KV is eventually consistent** (changes can take up to ~60 s to be visible in other locations). Two people registering the same username within that window could both pass the pre-check. The handler re-reads after writing and the loser backs out, which closes almost all of the gap but isn't a guarantee. For strict uniqueness and exact rate limits, move user creation to a **Durable Object** or D1. Say the word and I'll do that migration.
- Rate limiting is best-effort for the same reason. Add a Cloudflare WAF *Rate limiting rule* on `/api/auth/*` for a hard cap.
- KV free-plan write limits (1,000/day) apply: each register/login writes a few keys.
- There is no password reset or username change yet: with no email on file, a forgotten password can't be recovered.
