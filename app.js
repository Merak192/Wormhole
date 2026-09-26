/**
 * This version has NO custom backend at all — no Cloudflare Function, no
 * KV, no Worker. Peer matchmaking (finding other browsers in the same
 * 4-digit room) is handled by Trystero (https://github.com/dmotz/trystero),
 * a library that uses public Nostr relays to help WebRTC peers discover
 * each other. Once discovered, browsers connect directly — actual chat
 * messages never pass through Trystero's relays or any server of ours.
 *
 * Two layers of protection on message content:
 *  1. WebRTC's data channels are DTLS-encrypted in transit, always
 *     (mandatory part of the WebRTC spec, not optional).
 *  2. On top of that, every chat message is independently encrypted with
 *     AES-256-GCM using a key derived from the room code (PBKDF2, 100,000
 *     iterations) — this is the explicit AES-256 encryption this project
 *     was built around, and it means even Trystero's relays (which only
 *     ever see brief connection-setup metadata, never chat content) could
 *     not read messages even if they tried.
 *
 * Wrapped in an async IIFE so this can stay a plain <script src="app.js">
 * (no type="module" needed) while still using a dynamic ES module import
 * for the Trystero library.
 */

(async () => {
  const { joinRoom } = await import('https://esm.run/trystero');

  // A fixed, unique-ish string that namespaces this app within Trystero's
  // shared public relay network so our room codes don't collide with
  // other apps' rooms of the same number.
  const APP_ID = 'aes-room-chat-wormhole-v1';

  const APP_SALT = new TextEncoder().encode('aes-room-chat.v1.static-salt');
  const PBKDF2_ITERATIONS = 100_000;

  let cryptoKey = null;
  let room = null;
  let chatAction = null;
  let nameAction = null;
  let roomCode = null;
  let displayName = null;

  /** Trystero peerId -> display name */
  const peerNames = new Map();

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
    peerNames.clear();

    try {
      cryptoKey = await deriveKey(code);
      // `password` here encrypts the brief WebRTC connection-setup metadata
      // as it passes through Trystero's public relays. It is separate from
      // (and in addition to) the AES-256-GCM encryption of chat content below.
      room = joinRoom({ appId: APP_ID, password: `wormhole-${code}` }, code);
    } catch (err) {
      joinError.textContent = 'Could not start the room. Please try again.';
      joinBtn.disabled = false;
      return;
    }

    chatAction = room.makeAction('chat');
    nameAction = room.makeAction('name');

    room.onPeerJoin = (peerId) => {
      nameAction.send(displayName, { target: peerId });
      updatePresenceDisplay();
    };

    room.onPeerLeave = (peerId) => {
      const leftName = peerNames.get(peerId);
      peerNames.delete(peerId);
      updatePresenceDisplay();
      addSystemMessage(`${leftName || 'Someone'} left.`);
    };

    nameAction.onMessage = (value, { peerId }) => {
      const isNew = !peerNames.has(peerId);
      peerNames.set(peerId, value);
      updatePresenceDisplay();
      if (isNew) addSystemMessage(`${value} joined.`);
    };

    chatAction.onMessage = async (ciphertextB64, { peerId }) => {
      try {
        const plaintext = await decryptText(cryptoKey, ciphertextB64);
        const msg = JSON.parse(plaintext);
        addMessage(msg.name || peerNames.get(peerId) || 'Someone', msg.text, false);
      } catch (err) {
        addBadMessage('Received a message that could not be decrypted (wrong room code on sender\'s side?).');
      }
    };

    joinBtn.disabled = false;
    joinScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    roomLabel.textContent = `Room ${code}`;
    addSystemMessage(`You joined as "${name}". Looking for others in this room…`);
    messageInput.focus();
    updatePresenceDisplay();
  }

  async function sendMessage(e) {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !room) return;

    const payload = JSON.stringify({ name: displayName, text, ts: Date.now() });
    let ciphertext;
    try {
      ciphertext = await encryptText(cryptoKey, payload);
    } catch (err) {
      addBadMessage('Encryption failed — message not sent.');
      return;
    }

    addMessage(displayName, text, true);
    messageInput.value = '';

    try {
      await chatAction.send(ciphertext);
    } catch (err) {
      addBadMessage('Failed to send to one or more peers.');
    }

    if (peerNames.size === 0) {
      addSystemMessage('No one else is connected yet — your message stayed on this device.');
    }
  }

  function leaveRoom() {
    if (room) {
      try { room.leave(); } catch (err) { /* ignore */ }
    }
    room = null;
    chatAction = null;
    nameAction = null;
    cryptoKey = null;
    roomCode = null;
    peerNames.clear();
    messagesEl.innerHTML = '';
    presenceLabel.textContent = '';
    chatScreen.classList.add('hidden');
    joinScreen.classList.remove('hidden');
    joinError.textContent = '';
  }

  // ---------- Rendering ----------

  function updatePresenceDisplay() {
    presenceLabel.textContent = `· ${peerNames.size} connected`;
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
})();
