/**
 * Wormhole - P2P Encrypted Chat
 *
 * 信令流程:
 * 1. A 创建房间 → POST /offer, POST /key (公钥)
 * 2. B 加入房间 → GET /offer, 创建 answer, POST /answer, POST /key (公钥)
 * 3. 双方轮询 /state，等待 hasKey=true
 * 4. 获取对方公钥，ECDH 推导共享密钥
 * 5. WebRTC 连接建立，DataChannel 打开
 * 6. 开始加密聊天
 */

// ─── Type Definitions ───────────────────────────────────────────────────────

interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

interface SharedState {
  code: string | null;
  peerConnection: RTCPeerConnection | null;
  dataChannel: RTCDataChannel | null;
  keyPair: KeyPair | null;
  sharedKey: CryptoKey | null;
  isInitiator: boolean;
  status: 'idle' | 'creating' | 'waiting' | 'connecting' | 'connected' | 'error';
  messages: ChatMessage[];
}

interface ChatMessage {
  id: string;
  timestamp: number;
  sender: 'local' | 'remote';
  content: string;
}

// ─── Encryption Module ──────────────────────────────────────────────────────

class CryptoModule {
  static async generateKeyPair(): Promise<KeyPair> {
    return crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' } as EcKeyGenParams,
      true,
      ['deriveKey']
    ) as Promise<KeyPair>;
  }

  static async exportPublicKey(key: CryptoKey): Promise<string> {
    const raw = await crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  static async importPublicKey(base64Key: string): Promise<CryptoKey> {
    const binary = new Uint8Array(Array.from(atob(base64Key)).map(c => c.charCodeAt(0)));
    return crypto.subtle.importKey(
      'spki',
      binary.buffer as ArrayBuffer,
      { name: 'ECDH', namedCurve: 'P-256' } as EcKeyImportParams,
      true,
      []
    ) as Promise<CryptoKey>;
  }

  static async deriveSharedKey(remotePublicKey: CryptoKey, localPrivateKey: CryptoKey): Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: remotePublicKey },
      localPrivateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    ) as Promise<CryptoKey>;
  }

  static async encrypt(plaintext: string, key: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    ) as ArrayBuffer;

    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...result));
  }

  static async decrypt(encryptedBase64: string, key: CryptoKey): Promise<string> {
    const encrypted = new Uint8Array(Array.from(atob(encryptedBase64)).map(c => c.charCodeAt(0)));
    const iv = encrypted.slice(0, 12);
    const data = encrypted.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      data.buffer as ArrayBuffer
    ) as ArrayBuffer;

    return new TextDecoder().decode(decrypted);
  }
}

// ─── Signaling Module ───────────────────────────────────────────────────────

class SignalingModule {
  /** POST /offer */
  static async postOffer(code: string, sdp: RTCSessionDescriptionInit): Promise<void> {
    const res = await fetch('/offer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, sdp }),
    });
    if (!res.ok) throw new Error(`Offer failed: ${res.status}`);
  }

  /** GET /offer?code= */
  static async getOffer(code: string): Promise<RTCSessionDescriptionInit> {
    const res = await fetch(`/offer?code=${code}`);
    if (!res.ok) throw new Error(`Offer not found: ${res.status}`);
    const data = await res.json() as { sdp: RTCSessionDescriptionInit };
    return data.sdp;
  }

  /** POST /answer */
  static async postAnswer(code: string, sdp: RTCSessionDescriptionInit): Promise<void> {
    const res = await fetch('/answer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, sdp }),
    });
    if (!res.ok) throw new Error(`Answer failed: ${res.status}`);
  }

  /** POST /key */
  static async postKey(code: string, publicKey: string, participant: 1 | 2): Promise<void> {
    const res = await fetch('/key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, publicKey, participant }),
    });
    if (!res.ok) throw new Error(`Key exchange failed: ${res.status}`);
  }

  /** GET /key?code=&participant= */
  static async getKey(code: string, participant: 1 | 2): Promise<string> {
    const res = await fetch(`/key?code=${code}&participant=${participant}`);
    if (!res.ok) throw new Error(`Key not found: ${res.status}`);
    const data = await res.json() as { publicKey: string };
    return data.publicKey;
  }

  /** POST /candidate */
  static async postCandidate(code: string, candidate: RTCIceCandidateInit): Promise<void> {
    await fetch('/candidate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, candidate }),
    });
  }

  /** GET /state?code= */
  static async getState(code: string): Promise<{ status: string; hasOffer: boolean; hasAnswer: boolean; bothKeys: boolean }> {
    const res = await fetch(`/state?code=${code}`);
    if (!res.ok) return { status: 'waiting', hasOffer: false, hasAnswer: false, bothKeys: false };
    return res.json() as Promise<{ status: string; hasOffer: boolean; hasAnswer: boolean; bothKeys: boolean }>;
  }
}

// ─── Storage Module ─────────────────────────────────────────────────────────

class StorageModule {
  private static readonly KEY = 'wormhole_messages';

  static load(): ChatMessage[] {
    const data = sessionStorage.getItem(this.KEY);
    return data ? JSON.parse(data) : [];
  }

  static save(messages: ChatMessage[]): void {
    sessionStorage.setItem(this.KEY, JSON.stringify(messages));
  }

  static add(msg: ChatMessage): void {
    const messages = this.load();
    messages.push(msg);
    this.save(messages);
  }

  static clear(): void {
    sessionStorage.removeItem(this.KEY);
  }
}

// ─── Main Application ───────────────────────────────────────────────────────

class WormholeApp {
  private state: SharedState = {
    code: null,
    peerConnection: null,
    dataChannel: null,
    keyPair: null,
    sharedKey: null,
    isInitiator: false,
    status: 'idle',
    messages: [],
  };

  private pollInterval: number | null = null;

  constructor() {
    this.initUI();
  }

  // ── UI Init ──

  private initUI(): void {
    const createBtn = document.getElementById('create-btn') as HTMLButtonElement | null;
    const joinBtn = document.getElementById('join-btn') as HTMLButtonElement | null;
    const codeInput = document.getElementById('code-input') as HTMLInputElement | null;
    const sendBtn = document.getElementById('send-btn') as HTMLButtonElement | null;
    const messageInput = document.getElementById('message-input') as HTMLTextAreaElement | null;
    const backBtn = document.getElementById('back-btn');

    createBtn?.addEventListener('click', () => this.handleCreate(codeInput));
    joinBtn?.addEventListener('click', () => this.handleJoin(codeInput));
    sendBtn?.addEventListener('click', () => this.handleSend(messageInput));
    backBtn?.addEventListener('click', () => this.handleBack());

    codeInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        (this.state.isInitiator ? this.handleCreate : this.handleJoin)(codeInput);
      }
    });

    messageInput?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.handleSend(messageInput);
      }
    });

    // Restore previous session
    this.state.messages = StorageModule.load();
    const savedCode = sessionStorage.getItem('wormhole_code');
    if (savedCode) {
      this.state.code = savedCode;
      this.switchToChatView();
      this.renderMessages();
    }
  }

  // ── Connection Handlers ──

  private async handleCreate(input: HTMLInputElement | null): Promise<void> {
    const code = input?.value.trim() ?? '';
    if (!/^\d{4}$/.test(code)) {
      this.showError('请输入4位数字');
      return;
    }
    this.state.code = code;
    this.state.isInitiator = true;
    sessionStorage.setItem('wormhole_code', code);
    try {
      await this.startConnection();
    } catch (e) {
      this.showError(`创建房间失败: ${e instanceof Error ? e.message : '未知错误'}`);
    }
  }

  private async handleJoin(input: HTMLInputElement | null): Promise<void> {
    const code = input?.value.trim() ?? '';
    if (!/^\d{4}$/.test(code)) {
      this.showError('请输入4位数字');
      return;
    }
    this.state.code = code;
    this.state.isInitiator = false;
    sessionStorage.setItem('wormhole_code', code);
    try {
      await this.joinConnection();
    } catch (e) {
      this.showError(`加入房间失败: ${e instanceof Error ? e.message : '未知错误'}`);
    }
  }

  // ── Connection Logic ──

  private async startConnection(): Promise<void> {
    this.updateStatus('creating');
    this.state.keyPair = await CryptoModule.generateKeyPair();

    this.state.peerConnection = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    });

    // Create data channel
    this.state.dataChannel = this.state.peerConnection.createDataChannel('chat', { ordered: true });
    this.state.dataChannel.onopen = () => this.onChannelOpen();
    this.state.dataChannel.onmessage = (e) => this.onMessage(e.data);
    this.state.dataChannel.onclose = () => this.onChannelClose();
    this.state.dataChannel.onerror = () => this.handleError('DataChannel error');

    this.state.peerConnection.onicecandidate = (e) => {
      if (e.candidate) SignalingModule.postCandidate(this.state.code!, e.candidate.toJSON()).catch(console.error);
    };
    this.state.peerConnection.onconnectionstatechange = () => this.onConnectionStateChange();

    // Generate offer
    const offer = await this.state.peerConnection.createOffer();
    await this.state.peerConnection.setLocalDescription(offer);
    await this.waitForGathering();

    // Post offer and public key (participant=1 for initiator)
    await SignalingModule.postOffer(this.state.code!, this.state.peerConnection.localDescription!);
    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
    await SignalingModule.postKey(this.state.code!, myPublicKey, 1);

    this.updateStatus('waiting');
    this.startPolling();
    this.switchToChatView();
  }

  private async joinConnection(): Promise<void> {
    this.updateStatus('creating');
    this.state.keyPair = await CryptoModule.generateKeyPair();

    this.state.peerConnection = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    });

    this.state.peerConnection.ondatachannel = (e) => {
      this.state.dataChannel = e.channel;
      this.state.dataChannel.onopen = () => this.onChannelOpen();
      this.state.dataChannel.onmessage = (ev) => this.onMessage(ev.data);
      this.state.dataChannel.onclose = () => this.onChannelClose();
      this.state.dataChannel.onerror = () => this.handleError('DataChannel error');
    };

    this.state.peerConnection.onicecandidate = (e) => {
      if (e.candidate) SignalingModule.postCandidate(this.state.code!, e.candidate.toJSON()).catch(console.error);
    };
    this.state.peerConnection.onconnectionstatechange = () => this.onConnectionStateChange();

    // Get offer
    const offerSdp = await SignalingModule.getOffer(this.state.code!);
    await this.state.peerConnection!.setRemoteDescription(new RTCSessionDescription(offerSdp));

    // Generate answer
    const answer = await this.state.peerConnection.createAnswer();
    await this.state.peerConnection.setLocalDescription(answer);
    await this.waitForGathering();

    // Post answer and public key (participant=2 for joiner)
    await SignalingModule.postAnswer(this.state.code!, this.state.peerConnection.localDescription!);
    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
    await SignalingModule.postKey(this.state.code!, myPublicKey, 2);

    this.updateStatus('waiting');
    this.startPolling();
    this.switchToChatView();
  }

  private waitForGathering(): Promise<void> {
    return new Promise((resolve) => {
      if (this.state.peerConnection!.localDescription) { resolve(); return; }
      this.state.peerConnection!.onicegatheringstatechange = () => {
        if (this.state.peerConnection!.iceGatheringState === 'complete') resolve();
      };
      setTimeout(resolve, 5000);
    });
  }

  // ── Polling ──

  private startPolling(): void {
    if (this.pollInterval) clearInterval(this.pollInterval);
    this.pollInterval = window.setInterval(async () => {
      if (!this.state.code) return;
      const state = await SignalingModule.getState(this.state.code);

      if (state.hasOffer && state.hasAnswer && this.state.status === 'waiting') {
        this.updateStatus('connecting');
      }

      if (state.bothKeys && this.state.status === 'connecting') {
        // Derive shared key from remote public key
        // Initiator (1) gets remote key from participant 2, Joiner (2) gets remote key from participant 1
        const remoteParticipant: 1 | 2 = this.state.isInitiator ? 2 : 1;
        try {
          const remotePublicKeyBase64 = await SignalingModule.getKey(this.state.code!, remoteParticipant);
          const remotePublicKey = await CryptoModule.importPublicKey(remotePublicKeyBase64);
          this.state.sharedKey = await CryptoModule.deriveSharedKey(remotePublicKey, this.state.keyPair!.privateKey);
          console.log('[Wormhole] Shared key derived');
          this.updateStatus('connected');
          this.stopPolling();
          this.showConnected();
        } catch (e) {
          console.error('[Wormhole] Key derivation failed:', e);
        }
      }
    }, 1000);
  }

  private stopPolling(): void {
    if (this.pollInterval) { clearInterval(this.pollInterval); this.pollInterval = null; }
  }

  // ── Channel Events ──

  private onChannelOpen(): void {
    console.log('[Wormhole] DataChannel opened');
    if (this.state.status !== 'connected') {
      this.updateStatus('connected');
      this.showConnected();
    }
  }

  private async onMessage(data: string): Promise<void> {
    if (!this.state.sharedKey) {
      console.warn('[Wormhole] Received message but shared key not ready');
      return;
    }
    try {
      const plaintext = await CryptoModule.decrypt(data, this.state.sharedKey);
      this.addMessage('remote', plaintext);
    } catch (e) {
      console.error('[Wormhole] Failed to decrypt message:', e);
    }
  }

  private onChannelClose(): void {
    console.log('[Wormhole] DataChannel closed');
    this.updateStatus('error');
    this.showError('连接已断开');
  }

  private onConnectionStateChange(): void {
    const state = this.state.peerConnection!.connectionState;
    console.log('[Wormhole] Connection state:', state);
    if (state === 'disconnected' || state === 'failed' || state === 'closed') {
      this.updateStatus('error');
      this.showError('连接已断开');
    }
  }

  // ── Message Handling ──

  private async handleSend(input: HTMLTextAreaElement | null): Promise<void> {
    const message = input?.value.trim() ?? '';
    if (!message || !this.state.dataChannel || this.state.dataChannel.readyState !== 'open' || !this.state.sharedKey) return;

    try {
      const encrypted = await CryptoModule.encrypt(message, this.state.sharedKey);
      this.state.dataChannel.send(encrypted);
      this.addMessage('local', message);
      if (input) input.value = '';
    } catch (e) {
      this.showError(`发送失败: ${e instanceof Error ? e.message : '未知错误'}`);
    }
  }

  private addMessage(sender: 'local' | 'remote', content: string): void {
    const msg: ChatMessage = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      sender,
      content,
    };
    this.state.messages.push(msg);
    StorageModule.add(msg);
    this.renderMessages();
  }

  // ── UI Updates ──

  private updateStatus(status: SharedState['status']): void {
    this.state.status = status;
    const texts: Record<string, string> = {
      idle: '准备就绪', creating: '正在创建连接...', waiting: '等待对方加入...',
      connecting: '正在建立加密通道...', connected: '已连接', error: '连接失败',
    };
    const statusEl = document.getElementById('status');
    const statusTextEl = document.getElementById('status-text');
    const statusChatEl = document.getElementById('status-chat');
    const statusChatTextEl = document.getElementById('status-text-chat');
    if (statusEl) statusEl.className = `status-dot status-${status}`;
    if (statusTextEl) statusTextEl.textContent = texts[status] ?? status;
    if (statusChatEl) statusChatEl.className = `status-dot status-${status}`;
    if (statusChatTextEl) statusChatTextEl.textContent = texts[status] ?? status;

    const disabled = status !== 'idle' && status !== 'error';
    const createBtn = document.getElementById('create-btn') as HTMLButtonElement | null;
    const joinBtn = document.getElementById('join-btn') as HTMLButtonElement | null;
    if (createBtn) createBtn.disabled = disabled;
    if (joinBtn) joinBtn.disabled = disabled;
  }

  private showConnected(): void {
    document.getElementById('connected-indicator')?.style.setProperty('display', 'block');
  }

  private showError(msg: string): void {
    const el = document.getElementById('error-message');
    if (el) { el.textContent = msg; el.style.display = 'block'; setTimeout(() => { el.style.display = 'none'; }, 5000); }
  }

  private switchToChatView(): void {
    document.getElementById('connect-view')!.style.display = 'none';
    document.getElementById('chat-view')!.style.display = 'flex';
    document.getElementById('chat-code')!.textContent = this.state.code ?? '';
  }

  private async handleBack(): Promise<void> {
    this.stopPolling();
    this.state.dataChannel?.close();
    this.state.peerConnection?.close();
    this.state = {
      code: null, peerConnection: null, dataChannel: null,
      keyPair: null, sharedKey: null, isInitiator: false,
      status: 'idle', messages: [],
    };
    StorageModule.clear();
    sessionStorage.removeItem('wormhole_code');
    document.getElementById('connect-view')!.style.display = 'flex';
    document.getElementById('chat-view')!.style.display = 'none';
    this.updateStatus('idle');
  }

  private renderMessages(): void {
    const container = document.getElementById('messages');
    if (!container) return;
    container.innerHTML = '';
    for (const msg of this.state.messages) {
      const el = document.createElement('div');
      el.className = `message ${msg.sender}`;
      const time = new Date(msg.timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
      el.innerHTML = `<div class="message-content">${this.escapeHtml(msg.content)}</div><div class="message-time">${time}</div>`;
      container.appendChild(el);
    }
    container.scrollTop = container.scrollHeight;
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  private handleError(msg: string): void { console.error(msg); }
}

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  (window as unknown as Record<string, WormholeApp>).app = new WormholeApp();
});
