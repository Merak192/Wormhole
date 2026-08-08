// ── WebRTC 连接管理 + AES-256 加密聊天 ───────────────────────────────────────
// 握手：双方 POST join → 先到的 host 等，后到的 guest 拿 offer → 各自发 answer
// 服务器仅中转 SDP/ICE，不碰聊天内容。

import {
  generateKeyPair, rsaEncrypt, rsaDecrypt,
  generateAesKey, importAesKey,
  encryptMessage, decryptMessage,
  serializeSig, deserializeSig,
  buf2b64, b642buf,
  type KeyPair, type SessionKeys, type SigMessage,
} from './crypto.ts';

const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
];

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

function makePC(): RTCPeerConnection {
  return new RTCPeerConnection({ iceServers: ICE_SERVERS });
}

// ── 开始聊天 ──────────────────────────────────────────────────────────────────

export async function startChat(nick: string, room: string): Promise<ChatState> {
  const rsakp = await generateKeyPair();
  const sessionKeys = await generateAesKey();

  const rtc = makePC();
  const s: ChatState = {
    nick, peerNick: '—', rsakp, sessionKeys,
    peerPubKey: null, channel: null, rtc, isHost: false,
    onMessage: () => {}, onStatus: () => {},
  };
  state = s;

  // 信令辅助函数（闭包捕获 room，不依赖 location.search）
  const sigPost = async (msg: Record<string, unknown>): Promise<unknown> => {
    const resp = await fetch(`/pages/signaling?room=${encodeURIComponent(room)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(msg),
    });
    if (!resp.ok) throw new Error(`信令失败: ${resp.status}`);
    return resp.json();
  };

  const sigPoll = async (role: 'host' | 'guest', timeoutMs = 60_000): Promise<unknown> => {
    const resp = await fetch(
      `/pages/signaling?room=${encodeURIComponent(room)}&action=poll&role=${role}&timeout=${timeoutMs}`,
      { method: 'GET' }
    );
    if (!resp.ok) throw new Error(`等待信令失败: ${resp.status}`);
    return resp.json();
  };

  const waitForIceGathering = (pc: RTCPeerConnection): Promise<void> => {
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
  };

  // ICE 候选转发（捕获 sigPost，不依赖全局 state）
  rtc.onicecandidate = async (evt) => {
    if (!evt.candidate) return;
    const role = s.isHost ? 'host' : 'guest';
    sigPost({ type: 'ice', role, candidate: evt.candidate }).catch(() => {});
  };

  rtc.oniceconnectionstatechange = () => {
    const st = rtc.iceConnectionState;
    if (st === 'connected' || st === 'completed') s.onStatus('P2P 连接已建立 🔒', 'connected');
    else if (st === 'disconnected' || st === 'failed') { s.onStatus('连接已断开', 'error'); s.onDisconnect?.(); }
  };

  rtc.ondatachannel = (evt) => setupChannel(evt.channel, s);

  s.onStatus('正在建立连接…');

  // 创建 offer
  const offer = await rtc.createOffer();
  await rtc.setLocalDescription(offer);
  await waitForIceGathering(rtc);

  // POST join
  const joinResp = await sigPost({
    type: 'join',
    sdp: rtc.localDescription!,
    iceCandidates: [],
  }) as { role: 'host' | 'guest'; waiting?: boolean; peerSdp?: RTCSessionDescriptionInit; peerIce?: RTCIceCandidateInit[] };

  if (joinResp.role === 'host') {
    s.isHost = true;
    // host 创建 DataChannel
    const ch = rtc.createDataChannel('chat', { ordered: true });
    s.channel = ch;
    setupChannel(ch, s);

    if (joinResp.peerSdp) {
      // 对方已在线，直接拿到 offer
      await rtc.setRemoteDescription(new RTCSessionDescription(joinResp.peerSdp));
      if (joinResp.peerIce) {
        for (const c of joinResp.peerIce) {
          try { await rtc.addIceCandidate(new RTCIceCandidate(c)); } catch {}
        }
      }
      const answer = await rtc.createAnswer();
      await rtc.setLocalDescription(answer);
      await sigPost({ type: 'answer', role: 'host', sdp: rtc.localDescription! });
    } else {
      s.onStatus('等待对方加入…');
      const pollResp = await sigPoll('host') as { type?: string; sdp?: RTCSessionDescriptionInit; iceCandidates?: RTCIceCandidateInit[] };
      if (pollResp.type === 'ready' && pollResp.sdp) {
        await rtc.setRemoteDescription(new RTCSessionDescription(pollResp.sdp));
        if (pollResp.iceCandidates) {
          for (const c of pollResp.iceCandidates) {
            try { await rtc.addIceCandidate(new RTCIceCandidate(c)); } catch {}
          }
        }
      }
    }
  } else {
    s.isHost = false;
    s.onStatus('对方已加入，建立 P2P…');
    if (joinResp.peerSdp) {
      await rtc.setRemoteDescription(new RTCSessionDescription(joinResp.peerSdp));
      if (joinResp.peerIce) {
        for (const c of joinResp.peerIce) {
          try { await rtc.addIceCandidate(new RTCIceCandidate(c)); } catch {}
        }
      }
    }
    const answer = await rtc.createAnswer();
    await rtc.setLocalDescription(answer);
    await waitForIceGathering(rtc);
    await sigPost({ type: 'answer', role: 'guest', sdp: rtc.localDescription! });
    const ack = await sigPoll('guest') as { type?: string; sdp?: RTCSessionDescriptionInit; iceCandidates?: RTCIceCandidateInit[] };
    if (ack.type === 'ready' && ack.sdp) {
      await rtc.setRemoteDescription(new RTCSessionDescription(ack.sdp));
      if (ack.iceCandidates) {
        for (const c of ack.iceCandidates) {
          try { await rtc.addIceCandidate(new RTCIceCandidate(c)); } catch {}
        }
      }
    }
  }

  return s;
}

// ── DataChannel ───────────────────────────────────────────────────────────────

function setupChannel(ch: RTCDataChannel, s: ChatState): void {
  ch.onopen = () => {
    s.onStatus('P2P 通道已打开 🔒', 'connected');
    sendKeyExchange(s);
  };
  ch.onmessage = (evt) => handleMessage(evt.data, s);
  ch.onclose = () => { s.onStatus('对方已断开', 'error'); s.onDisconnect?.(); };
  ch.onerror = () => s.onStatus('通道错误', 'error');
}

async function sendKeyExchange(s: ChatState): Promise<void> {
  const encAes = buf2b64(new Uint8Array(await rsaEncrypt(s.sessionKeys.aesKeyExport, s.rsakp.publicKey)));
  const pubJwk = await crypto.subtle.exportKey('jwk', s.rsakp.publicKey);
  const pubB64 = buf2b64(new TextEncoder().encode(JSON.stringify(pubJwk)));
  chSend(s, { type: 'key-exchange', encAesKey: encAes, publicKey: pubB64 });
}

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
      } catch { s.onStatus('解密失败', 'error'); }
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

export function sendChatMessage(text: string): Promise<void> {
  if (!state?.channel?.open || !state.sessionKeys.aesKey) {
    return Promise.reject(new Error('通道未就绪'));
  }
  return encryptMessage(text, state.sessionKeys.aesKey).then(({ iv, ciphertext }) => {
    chSend(state, { type: 'chat' as const, iv: buf2b64(iv), ciphertext: buf2b64(ciphertext) });
  });
}

function chSend(s: ChatState, msg: SigMessage): void {
  if (s.channel?.open) s.channel.send(serializeSig(msg));
}

export function disconnect(): void {
  state?.rtc.close();
  state = null;
}
