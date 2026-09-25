/**
 * All encryption happens here, in the browser, using the native Web Crypto
 * API. The Cloudflare Pages Function (functions/api/room/[code].js) never
 * receives a key and never sees plaintext — only base64 ciphertext strings.
 *
 * Transport: short-polling over plain fetch() against a Workers-KV-backed
 * API. Not instant like a WebSocket, but requires zero extra Cloudflare
 * setup beyond a KV namespace binding added in the Pages dashboard.
 *
 * Key derivation: PBKDF2(roomCode, fixed app salt, 100_000 iterations) -> AES-256-GCM key.
 * Per-message encryption: random 12-byte IV, AES-GCM, output = base64(iv || ciphertext).
 */

const APP_SALT = new TextEncoder().encode('aes-room-chat.v1.static-salt');
const PBKDF2_ITERATIONS = 100_000;
const POLL_INTERVAL_MS = 1200;
const HEARTBEAT_EVERY_N_POLLS = 7; // ~every 8-9s, keeps KV writes low

let cryptoKey = null;
let roomCode = null;
let displayName = null;
let clientId = null;
let cursor = '';
let pollTimer = null;
let pollCount = 0;

// ---------- DOM references ----------
const joinScreen = document.getElementById('join-screen');
const chatScreen = document.getElementById('chat-screen');
const roomCodeInput = document.getElementById('room-code');
const displayNameInput = document.getElementById('display-name');
const joinBtn = document.getElementById('join-btn');
const joinError = document.getElementById('join-error');
const roomLabel = document.getElementById('room-label');
const presenceLabel = document.getElementById('presence-label');
const leaveBtn = document.getElementById('leave-btn');
const messagesEl = document.getElementById('messages');
const sendForm = document.getElementById('send-form');
const messageInput = document.getElementById('message-input');

roomCodeInput.addEventListener('input', () => {
  roomCodeInput.value = roomCodeInput.value.replace(/\D/g, '').slice(0, 4);
});

joinBtn.addEventListener('click', join);
roomCodeInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') displayNameInput.focus(); });
displayNameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') join(); });
leaveBtn.addEventListener('click', leaveRoom);
sendForm.addEventListener('submit', sendMessage);

// ---------- Crypto helpers ----------

/** Derives a non-extractable AES-256-GCM CryptoKey from the 4-digit room code. */
async function deriveKey(code) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(code),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: APP_SALT,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptText(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);
  return bufToBase64(combined);
}

async function decryptText(key, base64Payload) {
  const combined = base64ToBuf(base64Payload);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plainBuf);
}

function bufToBase64(buf) {
  let binary = '';
  for (const byte of buf) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBuf(base64) {
  const binary = atob(base64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf;
}

// ---------- Room flow ----------

async function join() {
  const code = roomCodeInput.value.trim();
  const name = displayNameInput.value.trim() || 'Anonymous';

  if (!/^\d{4}$/.test(code)) {
    joinError.textContent = 'Room code must be exactly 4 digits.';
    return;
  }
  joinError.textContent = '';
  joinBtn.disabled = true;

  roomCode = code;
  displayName = name;
  clientId = crypto.randomUUID();
  cursor = '';
  pollCount = 0;
  cryptoKey = await deriveKey(code);

  try {
    await poll(true); // initial fetch also sends a heartbeat; throws on failure
  } catch (err) {
    joinError.textContent = 'Could not reach the room API. Check your connection and try again.';
    joinBtn.disabled = false;
    return;
  }

  joinBtn.disabled = false;
  joinScreen.classList.add('hidden');
  chatScreen.classList.remove('hidden');
  roomLabel.textContent = `Room ${code}`;
  addSystemMessage(`You joined as "${name}". Messages are encrypted before they leave your device.`);
  messageInput.focus();

  pollTimer = setInterval(() => {
    pollCount += 1;
    const sendHeartbeat = pollCount % HEARTBEAT_EVERY_N_POLLS === 0;
    poll(sendHeartbeat).catch(() => {
      /* transient network errors are ignored; next tick retries */
    });
  }, POLL_INTERVAL_MS);
}

/** Fetches new messages since `cursor`. Optionally sends a presence heartbeat. */
async function poll(heartbeat) {
  const params = new URLSearchParams({ after: cursor, clientId });
  if (heartbeat) params.set('hb', '1');

  const res = await fetch(`/api/room/${roomCode}?${params.toString()}`);
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    throw new Error(info.error || `Request failed (${res.status})`);
  }
  const data = await res.json();

  if (typeof data.cursor === 'string') cursor = data.cursor;
  if (typeof data.online === 'number') presenceLabel.textContent = `· ${data.online} online`;

  for (const item of data.messages || []) {
    await handleIncoming(item.ciphertext);
  }
}

async function handleIncoming(ciphertextB64) {
  try {
    const plaintext = await decryptText(cryptoKey, ciphertextB64);
    const msg = JSON.parse(plaintext);
    if (msg.clientId === clientId) return; // we already rendered our own message optimistically
    addMessage(msg.name, msg.text, false);
  } catch (err) {
    addBadMessage('Received a message that could not be decrypted (wrong room code on sender\'s side?).');
  }
}

async function sendMessage(e) {
  e.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !roomCode) return;

  const payload = JSON.stringify({ name: displayName, text, ts: Date.now(), clientId });
  let ciphertext;
  try {
    ciphertext = await encryptText(cryptoKey, payload);
  } catch (err) {
    addBadMessage('Encryption failed — message not sent.');
    return;
  }

  addMessage(displayName, text, true); // optimistic local echo
  messageInput.value = '';

  try {
    const res = await fetch(`/api/room/${roomCode}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ciphertext, clientId }),
    });
    if (!res.ok) throw new Error('send failed');
  } catch (err) {
    addBadMessage('Failed to send — check your connection and try again.');
  }
}

function leaveRoom() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  cryptoKey = null;
  roomCode = null;
  cursor = '';
  messagesEl.innerHTML = '';
  presenceLabel.textContent = '';
  chatScreen.classList.add('hidden');
  joinScreen.classList.remove('hidden');
  joinError.textContent = '';
}

// ---------- Rendering ----------

function addMessage(name, text, mine) {
  const div = document.createElement('div');
  div.className = `msg ${mine ? 'mine' : 'theirs'}`;
  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = mine ? 'You' : name;
  div.appendChild(meta);
  div.appendChild(document.createTextNode(text));
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addSystemMessage(text) {
  const div = document.createElement('div');
  div.className = 'msg system';
  div.textContent = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addBadMessage(text) {
  const div = document.createElement('div');
  div.className = 'msg bad';
  div.textContent = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}
