// ── WebRTC 连接管理 + AES-256 加密聊天 ───────────────────────────────────────
// P2P DataChannel + RSA-OAEP 密钥交换 + AES-256-GCM 消息加密。
// 服务器仅中转 SDP/ICE，不接触聊天内容。

import {
  generateKeyPair, rsaEncrypt, rsaDecrypt,
  generateAesKey, importAesKey,
  encryptMessage, decryptMessage,
  serializeSig, deserializeSig,
  buf2b64, b642buf, ab2b64,
  type KeyPair, type SessionKeys, type SigMessage,
} from './crypto.ts';

const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

// ── 聊天状态 ─────────────────────────────────────────────────────────────────

export interface ChatState {
  nick: string;
  peerNick: string;
  rsakp: KeyPair;
  sessionKeys: SessionKeys;
  peerPubKey: CryptoKey | null;
  channel: RTCDataChannel | null;
  rtc: RTCPeerConnection;
  isHost: boolean;
  onMessage: (nick: string, text: string) => void;
  onStatus: (text: string, type?: 'connected' | 'error') => void;
  onDisconnect?: () => void;
}

let state: ChatState | null = null;

// ── 工具函数 ─────────────────────────────────────────────────────────────────

function makePC(): RTCPeerConnection {
  return new RTCPeerConnection({ iceServers: ICE_SERVERS });
}

function getParam(name: string): string | null {
  return new URLSearchParams(location.search).get(name);
}

function getRoom(): string {
  const room = getParam('room');
  if (!room) throw new Error('缺少 room 参数');
  return room;
}

// ── 信令：通过 Pages Function 长轮询转发 ─────────────────────────────────────

async function signalingSend<T extends { type: string }>(msg: T): Promise<T> {
  const room = getRoom();
  const resp = await fetch(`/pages/signaling?room=${encodeURIComponent(room)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(msg),
  });
  if (!resp.ok) throw new Error(`信令失败: ${resp.status}`);
  return resp.json() as Promise<T>;
}

async function signalingRecv<T extends { type: string }>(timeoutMs = 60_000): Promise<T> {
  const room = getRoom();
  const resp = await fetch(`/pages/signaling?room=${encodeURIComponent(room)}&timeout=${timeoutMs}`, {
    method: 'GET',
  });
  if (!resp.ok) throw new Error(`等待信令失败: ${resp.status}`);
  return resp.json() as Promise<T>;
}

// ── 等待 ICE 收集完成 ────────────────────────────────────────────────────────

function waitForIceGathering(pc: RTCPeerConnection): Promise<void> {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve) => {
    const check = () => {
      if (pc.iceGatheringState === 'complete') {
        pc.removeEventListener('icegatheringstatechange', check);
        resolve();
      }
    };
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(resolve, 10000);
  });
}

// ── 开始聊天（入口）──────────────────────────────────────────────────────────

export async function startChat(isHost: boolean, nick: string): Promise<ChatState> {
  const rsakp = await generateKeyPair();
  const sessionKeys = await generateAesKey();

  const rtc = makePC();
  const s: ChatState = {
    nick, peerNick: '—', rsakp, sessionKeys,
    peerPubKey: null, channel: null, rtc, isHost,
    onMessage: () => {}, onStatus: () => {},
  };
  state = s;

  // ICE 候选转发
  rtc.onicecandidate = (evt) => {
    if (!evt.candidate) return;
    signalingSend({ type: 'ice', candidate: evt.candidate }).catch(() => {});
  };

  // 连接状态
  rtc.oniceconnectionstatechange = () => {
    const st = rtc.iceConnectionState;
    if (st === 'connected' || st === 'completed') s.onStatus('P2P 连接已建立 🔒', 'connected');
    else if (st === 'disconnected' || st === 'failed') { s.onStatus('连接已断开', 'error'); s.onDisconnect?.(); }
  };

  // 对方创建的 DataChannel
  rtc.ondatachannel = (evt) => setupChannel(evt.channel, s);

  if (isHost) {
    // 主机：创建 DataChannel，发送 offer
    const ch = rtc.createDataChannel('chat', { ordered: true });
    s.channel = ch;
    setupChannel(ch, s);
    s.onStatus('正在等待对方…');

    const offer = await rtc.createOffer();
    await rtc.setLocalDescription(offer);
    await waitForIceGathering(rtc);
    await signalingSend({ type: 'offer', sdp: rtc.localDescription! });
    const ans = await signalingRecv<{ type: 'answer'; sdp: RTCSessionDescriptionInit }>();
    await rtc.setRemoteDescription(new RTCSessionDescription(ans.sdp));
  } else {
    // 访客：等待 offer，发送 answer
    s.onStatus('正在等待房主…');
    const offerSig = await signalingRecv<{ type: 'offer'; sdp: RTCSessionDescriptionInit }>();
    await rtc.setRemoteDescription(new RTCSessionDescription(offerSig.sdp));

    const answer = await rtc.createAnswer();
    await rtc.setLocalDescription(answer);
    await waitForIceGathering(rtc);
    await signalingSend({ type: 'answer', sdp: rtc.localDescription! });
  }

  return s;
}

// ── 设置 DataChannel ─────────────────────────────────────────────────────────

function setupChannel(ch: RTCDataChannel, s: ChatState): void {
  ch.onopen = () => {
    s.onStatus('P2P 通道已打开 🔒', 'connected');
    sendKeyExchange(s);
  };
  ch.onmessage = (evt) => handleMessage(evt.data, s);
  ch.onclose = () => { s.onStatus('对方已断开', 'error'); s.onDisconnect?.(); };
  ch.onerror = (err) => s.onStatus(`通道错误: ${err.message || 'unknown'}`, 'error');
}

// ── 发送密钥交换（RSA 公钥 + 加密的 AES 密钥）───────────────────────────────

async function sendKeyExchange(s: ChatState): Promise<void> {
  const encAes = buf2b64(new Uint8Array(await rsaEncrypt(s.sessionKeys.aesKeyExport, s.rsakp.publicKey)));
  const pubJwk = await crypto.subtle.exportKey('jwk', s.rsakp.publicKey);
  const pubB64 = buf2b64(new TextEncoder().encode(JSON.stringify(pubJwk)));
  chSend(s, { type: 'key-exchange', encAesKey: encAes, publicKey: pubB64 });
}

// ── 处理接收到的 DataChannel 消息 ────────────────────────────────────────────

async function handleMessage(raw: string, s: ChatState): Promise<void> {
  let msg: SigMessage;
  try { msg = deserializeSig(raw); } catch { return; }

  switch (msg.type) {
    case 'key-exchange': {
      const km = msg as SigMessage & { encAesKey: string; publicKey: string };
      const pubJwk = JSON.parse(new TextDecoder().decode(b642buf(km.publicKey))) as JsonWebKey;
      s.peerPubKey = await crypto.subtle.importKey('jwk', pubJwk, 'RSA-OAEP', true, ['encrypt']);
      const encAesBuf = b642buf(km.encAesKey);
      const aesRaw = await rsaDecrypt(encAesBuf, s.rsakp.privateKey);
      s.sessionKeys.aesKey = await importAesKey(new Uint8Array(aesRaw));
      s.onStatus('🔐 加密通道已建立', 'connected');
      break;
    }

    case 'chat': {
      const cm = msg as SigMessage & { iv: string; ciphertext: string };
      if (!s.sessionKeys.aesKey) { chSend(s, { type: 'chat-request' }); return; }
      try {
        const plain = await decryptMessage(b642buf(cm.iv), b642buf(cm.ciphertext), s.sessionKeys.aesKey);
        s.onMessage(s.peerNick, plain);
      } catch { s.onStatus('解密失败，可能密钥不匹配', 'error'); }
      break;
    }

    case 'chat-request':
      await sendKeyExchange(s);
      break;

    case 'ice': {
      const im = msg as SigMessage & { candidate: RTCIceCandidateInit };
      try { await s.rtc.addIceCandidate(new RTCIceCandidate(im.candidate)); } catch {}
      break;
    }
  }
}

// ── 发送加密聊天消息 ─────────────────────────────────────────────────────────

export function sendChatMessage(text: string): Promise<void> {
  if (!state?.channel?.open || !state.sessionKeys.aesKey) {
    return Promise.reject(new Error('通道未就绪'));
  }
  return encryptMessage(text, state.sessionKeys.aesKey).then(({ iv, ciphertext }) => {
    chSend(state, { type: 'chat' as const, iv: buf2b64(iv), ciphertext: buf2b64(ciphertext) });
  });
}

// ── 底层 channel 发送 ─────────────────────────────────────────────────────────

function chSend(s: ChatState, msg: SigMessage): void {
  if (s.channel?.open) s.channel.send(serializeSig(msg));
}

// ── 断开 & 获取状态 ──────────────────────────────────────────────────────────

export function disconnect(): void {
  state?.rtc.close();
  state = null;
}

export function getState(): ChatState | null {
  return state;
}
