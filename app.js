/**
 * All encryption happens here, in the browser, using the native Web Crypto
 * API. The Durable Object behind /api/room/<code> never receives a key and
 * never sees plaintext — only base64 AES-GCM ciphertext strings travel over
 * the WebSocket.
 *
 * Key derivation: PBKDF2(roomCode, fixed app salt, 100_000 iterations) -> AES-256-GCM key.
 * Per-message encryption: random 12-byte IV, AES-GCM, output = base64(iv || ciphertext).
 */

const APP_SALT = new TextEncoder().encode('aes-room-chat.v1.static-salt');
const PBKDF2_ITERATIONS = 100_000;

let socket = null;
let cryptoKey = null;
let roomCode = null;
let displayName = null;

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
  cryptoKey = await deriveKey(code);

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  socket = new WebSocket(`${proto}://${location.host}/api/room/${code}`);

  socket.addEventListener('open', () => {
    joinBtn.disabled = false;
    joinScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    roomLabel.textContent = `Room ${code}`;
    addSystemMessage(`You joined as "${name}". Messages are encrypted before they leave your device.`);
    messageInput.focus();
  });

  socket.addEventListener('message', onSocketMessage);

  socket.addEventListener('close', () => {
    if (joinScreen.classList.contains('hidden')) {
      addSystemMessage('Connection closed.');
    }
  });

  socket.addEventListener('error', () => {
    joinBtn.disabled = false;
    joinError.textContent = 'Could not connect. Please try again.';
  });
}

async function onSocketMessage(event) {
  let parsed;
  try {
    parsed = JSON.parse(event.data);
  } catch {
    parsed = null;
  }

  // Unencrypted presence frames sent by the Durable Object itself.
  if (parsed && parsed.__system) {
    if (parsed.__system.type === 'presence') {
      presenceLabel.textContent = `· ${parsed.__system.count} online`;
    }
    return;
  }

  // Otherwise treat the raw frame as base64 AES-GCM ciphertext.
  try {
    const plaintext = await decryptText(cryptoKey, event.data);
    const msg = JSON.parse(plaintext);
    addMessage(msg.name, msg.text, false);
  } catch (err) {
    addBadMessage('Received a message that could not be decrypted (wrong room code on sender\'s side?).');
  }
}

async function sendMessage(e) {
  e.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !socket || socket.readyState !== WebSocket.OPEN) return;

  const payload = JSON.stringify({ name: displayName, text, ts: Date.now() });
  const ciphertext = await encryptText(cryptoKey, payload);
  socket.send(ciphertext);

  addMessage(displayName, text, true);
  messageInput.value = '';
}

function leaveRoom() {
  if (socket) socket.close();
  socket = null;
  cryptoKey = null;
  roomCode = null;
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
