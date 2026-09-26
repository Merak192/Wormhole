/**
 * Two layers here:
 *
 * 1. SIGNALING (via the Cloudflare Pages Function + KV): short-polls a
 *    small relay that only ever carries WebRTC handshake data — SDP
 *    offers/answers, ICE candidates, and periodic "hello" presence
 *    broadcasts. No chat content ever touches this path.
 *
 * 2. CHAT (via WebRTC RTCDataChannel, one per peer — a mesh): once two
 *    browsers finish steps in layer 1, they open a direct connection.
 *    Every chat message is AES-256-GCM encrypted (key derived from the
 *    room code via PBKDF2, same as before) and sent straight over that
 *    channel — Cloudflare is not involved at all at this point.
 *
 * Glare avoidance for the mesh: for any pair of peers, whoever has the
 * lexicographically smaller clientId is the "offerer" for that pair. Both
 * sides compute this independently and agree without needing to negotiate.
 */

const APP_SALT = new TextEncoder().encode('aes-room-chat.v1.static-salt');
const PBKDF2_ITERATIONS = 100_000;
const SIGNAL_POLL_INTERVAL_MS = 1000;
const HELLO_REBROADCAST_EVERY_N_POLLS = 15; // ~every 15s — lets late joiners discover existing peers
const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

let cryptoKey = null;
let roomCode = null;
let displayName = null;
let clientId = null;
let cursor = '';
let pollTimer = null;
let pollCount = 0;
let kvOnlineCount = 0;

/** peerId -> { name, pc, dc, connected, remoteSet, offerer, warnedFailure } */
const peers = new Map();
/** peerId -> queued ICE candidate inits received before remote description was set */
const pendingIce = new Map();

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

// ---------- Crypto helpers (unchanged from earlier versions) ----------

async function deriveKey(code) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(code),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: APP_SALT, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
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
  peers.clear();
  pendingIce.clear();
  cryptoKey = await deriveKey(code);

  try {
    await pollSignals(true); // also sends our first "hello" + heartbeat
    await sendSignal(null, 'hello', null);
  } catch (err) {
    joinError.textContent = 'Could not reach the signaling API. Check your connection and try again.';
    joinBtn.disabled = false;
    return;
  }

  joinBtn.disabled = false;
  joinScreen.classList.add('hidden');
  chatScreen.classList.remove('hidden');
  roomLabel.textContent = `Room ${code}`;
  addSystemMessage(`You joined as "${name}". Looking for others in this room…`);
  messageInput.focus();
  updatePresenceDisplay();

  pollTimer = setInterval(() => {
    pollCount += 1;
    const doHeartbeat = pollCount % HELLO_REBROADCAST_EVERY_N_POLLS === 0;
    pollSignals(doHeartbeat).catch(() => {});
    if (doHeartbeat) sendSignal(null, 'hello', null).catch(() => {});
  }, SIGNAL_POLL_INTERVAL_MS);
}

async function pollSignals(heartbeat) {
  const params = new URLSearchParams({ after: cursor, clientId });
  if (heartbeat) params.set('hb', '1');

  const res = await fetch(`/api/room/${roomCode}?${params.toString()}`);
  if (!res.ok) {
    const info = await res.json().catch(() => ({}));
    throw new Error(info.error || `Request failed (${res.status})`);
  }
  const data = await res.json();

  if (typeof data.cursor === 'string') cursor = data.cursor;
  if (typeof data.online === 'number') {
    kvOnlineCount = data.online;
    updatePresenceDisplay();
  }

  for (const item of data.messages || []) {
    handleSignal(item.signal);
  }
}

async function sendSignal(to, type, data) {
  await fetch(`/api/room/${roomCode}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ from: clientId, to, type, name: displayName, data }),
  });
}

function handleSignal(signal) {
  if (!signal || signal.from === clientId) return; // ignore our own broadcasts

  if (signal.type === 'hello') {
    handleHello(signal.from, signal.name);
    return;
  }

  // Everything else is targeted — ignore if it's not addressed to us.
  if (signal.to !== clientId) return;

  if (signal.type === 'offer') handleOffer(signal.from, signal.name, signal.data);
  else if (signal.type === 'answer') handleAnswer(signal.from, signal.data);
  else if (signal.type === 'ice') handleIce(signal.from, signal.data);
}

// ---------- WebRTC mesh ----------

function ensurePeer(peerId, name) {
  let entry = peers.get(peerId);
  if (entry) {
    if (name) entry.name = name;
    return entry;
  }

  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
  entry = { name: name || 'Someone', pc, dc: null, connected: false, remoteSet: false, offerer: false, warnedFailure: false };
  peers.set(peerId, entry);

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      sendSignal(peerId, 'ice', event.candidate.toJSON()).catch(() => {});
    }
  };

  pc.ondatachannel = (event) => {
    setupDataChannel(peerId, entry, event.channel);
  };

  pc.oniceconnectionstatechange = () => {
    if ((pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'disconnected') && !entry.warnedFailure) {
      entry.warnedFailure = true;
      addBadMessage(
        `Could not establish a direct connection to ${entry.name}. You may be on a restrictive network (no relay server is configured for this demo).`
      );
    }
  };

  return entry;
}

function setupDataChannel(peerId, entry, channel) {
  entry.dc = channel;
  channel.onopen = () => {
    entry.connected = true;
    updatePresenceDisplay();
    addSystemMessage(`Connected directly to ${entry.name}.`);
  };
  channel.onclose = () => {
    entry.connected = false;
    updatePresenceDisplay();
  };
  channel.onmessage = (event) => handleIncomingCiphertext(event.data, entry.name);
}

async function createOfferTo(peerId, name) {
  const entry = ensurePeer(peerId, name);
  entry.offerer = true;
  const channel = entry.pc.createDataChannel('chat');
  setupDataChannel(peerId, entry, channel);

  const offer = await entry.pc.createOffer();
  await entry.pc.setLocalDescription(offer);
  await sendSignal(peerId, 'offer', entry.pc.localDescription);
}

async function handleHello(peerId, name) {
  if (peers.has(peerId)) {
    const entry = peers.get(peerId);
    if (name) entry.name = name;
    return; // already known/connecting/connected
  }
  if (clientId < peerId) {
    // We have the smaller id for this pair — we initiate.
    createOfferTo(peerId, name).catch(() => {});
  } else {
    // Just remember their name; they will send us an offer shortly.
    ensurePeer(peerId, name);
  }
}

async function handleOffer(peerId, name, sdp) {
  const entry = ensurePeer(peerId, name);
  await entry.pc.setRemoteDescription(sdp);
  entry.remoteSet = true;
  await flushPendingIce(peerId, entry);

  const answer = await entry.pc.createAnswer();
  await entry.pc.setLocalDescription(answer);
  await sendSignal(peerId, 'answer', entry.pc.localDescription);
}

async function handleAnswer(peerId, sdp) {
  const entry = peers.get(peerId);
  if (!entry) return;
  await entry.pc.setRemoteDescription(sdp);
  entry.remoteSet = true;
  await flushPendingIce(peerId, entry);
}

async function handleIce(peerId, candidateInit) {
  const entry = peers.get(peerId);
  if (entry && entry.remoteSet) {
    try {
      await entry.pc.addIceCandidate(candidateInit);
    } catch (err) {
      /* ignore malformed/late candidates */
    }
  } else {
    const queue = pendingIce.get(peerId) || [];
    queue.push(candidateInit);
    pendingIce.set(peerId, queue);
  }
}

async function flushPendingIce(peerId, entry) {
  const queue = pendingIce.get(peerId);
  if (!queue || !queue.length) return;
  pendingIce.delete(peerId);
  for (const candidateInit of queue) {
    try {
      await entry.pc.addIceCandidate(candidateInit);
    } catch (err) {
      /* ignore malformed/late candidates */
    }
  }
}

// ---------- Chat send/receive ----------

async function handleIncomingCiphertext(ciphertextB64, fromName) {
  try {
    const plaintext = await decryptText(cryptoKey, ciphertextB64);
    const msg = JSON.parse(plaintext);
    addMessage(msg.name || fromName, msg.text, false);
  } catch (err) {
    addBadMessage('Received a message that could not be decrypted (wrong room code on sender\'s side?).');
  }
}

async function sendMessage(e) {
  e.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !roomCode) return;

  const payload = JSON.stringify({ name: displayName, text, ts: Date.now() });
  let ciphertext;
  try {
    ciphertext = await encryptText(cryptoKey, payload);
  } catch (err) {
    addBadMessage('Encryption failed — message not sent.');
    return;
  }

  let deliveredTo = 0;
  for (const entry of peers.values()) {
    if (entry.connected && entry.dc && entry.dc.readyState === 'open') {
      try {
        entry.dc.send(ciphertext);
        deliveredTo += 1;
      } catch (err) {
        /* ignore individual send failures */
      }
    }
  }

  addMessage(displayName, text, true);
  messageInput.value = '';

  if (deliveredTo === 0 && peers.size === 0) {
    addSystemMessage('No one else is connected yet — your message stayed on this device.');
  }
}

function leaveRoom() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  for (const entry of peers.values()) {
    try { entry.dc && entry.dc.close(); } catch (e) {}
    try { entry.pc.close(); } catch (e) {}
  }
  peers.clear();
  pendingIce.clear();
  cryptoKey = null;
  roomCode = null;
  cursor = '';
  kvOnlineCount = 0;
  messagesEl.innerHTML = '';
  presenceLabel.textContent = '';
  chatScreen.classList.add('hidden');
  joinScreen.classList.remove('hidden');
  joinError.textContent = '';
}

// ---------- Rendering ----------

function updatePresenceDisplay() {
  const connectedCount = [...peers.values()].filter((p) => p.connected).length;
  presenceLabel.textContent = `· ${kvOnlineCount} in room · ${connectedCount} connected directly`;
}

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
