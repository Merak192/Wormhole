/**
 * Wormhole - P2P Encrypted Chat
 *
 * Architecture:
 * - WebRTC DataChannel for P2P messaging
 * - Cloudflare Pages Functions + KV for signaling
 * - Web Crypto API for AES-256-GCM encryption
 * - SessionStorage for local message history (cleared on browser close)
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
  encrypted: boolean;
}

// ─── Encryption Module ──────────────────────────────────────────────────────

class CryptoModule {
  /** Generate ECDH key pair for key exchange */
  static async generateKeyPair(): Promise<KeyPair> {
    return crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      } as EcKeyGenParams,
      true,
      ['deriveKey']
    ) as Promise<KeyPair>;
  }

  /** Export public key to base64 string */
  static async exportPublicKey(key: CryptoKey): Promise<string> {
    const raw = await crypto.subtle.exportKey('spki', key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  /** Import public key from base64 string */
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

  /** Derive shared secret key using ECDH */
  static async deriveSharedKey(remotePublicKey: CryptoKey, localPrivateKey: CryptoKey): Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: remotePublicKey },
      localPrivateKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    ) as Promise<CryptoKey>;
  }

  /** Encrypt message using AES-256-GCM */
  static async encrypt(plaintext: string, key: CryptoKey): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    ) as ArrayBuffer;

    // Combine IV + encrypted data
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv);
    result.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...result));
  }

  /** Decrypt message using AES-256-GCM */
  static async decrypt(encryptedBase64: string, key: CryptoKey): Promise<string> {
    const encrypted = new Uint8Array(Array.from(atob(encryptedBase64)).map(c => c.charCodeAt(0)));

    // Extract IV (first 12 bytes)
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
  private static readonly BASE_URL = '';

  /** Submit WebRTC offer to signaling server */
  static async postOffer(code: string, sdp: RTCSessionDescriptionInit): Promise<{ status: string }> {
    const response = await fetch(`${this.BASE_URL}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, sdp }),
    });
    if (!response.ok) throw new Error(`Offer failed: ${response.status}`);
    return response.json() as Promise<{ status: string }>;
  }

  /** Get WebRTC offer from signaling server */
  static async getOffer(code: string): Promise<{ sdp: RTCSessionDescriptionInit }> {
    const response = await fetch(`${this.BASE_URL}/offer?code=${code}`);
    if (!response.ok) throw new Error(`Offer not found: ${response.status}`);
    return response.json() as Promise<{ sdp: RTCSessionDescriptionInit }>;
  }

  /** Submit WebRTC answer to signaling server */
  static async postAnswer(code: string, sdp: RTCSessionDescriptionInit): Promise<{ status: string }> {
    const response = await fetch(`${this.BASE_URL}/answer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, sdp }),
    });
    if (!response.ok) throw new Error(`Answer failed: ${response.status}`);
    return response.json() as Promise<{ status: string }>;
  }

  /** Get WebRTC answer from signaling server */
  static async getAnswer(code: string): Promise<{ sdp: RTCSessionDescriptionInit }> {
    const response = await fetch(`${this.BASE_URL}/answer?code=${code}`);
    if (!response.ok) throw new Error(`Answer not found: ${response.status}`);
    return response.json() as Promise<{ sdp: RTCSessionDescriptionInit }>;
  }

  /** Submit ICE candidate to signaling server */
  static async postCandidate(code: string, candidate: RTCIceCandidateInit): Promise<void> {
    await fetch(`${this.BASE_URL}/candidate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, candidate }),
    });
  }

  /** Get ICE candidates from signaling server */
  static async getCandidates(code: string): Promise<RTCIceCandidateInit[]> {
    const response = await fetch(`${this.BASE_URL}/candidate?code=${code}`);
    if (!response.ok) return [];
    const data = await response.json() as { candidates: RTCIceCandidateInit[] };
    return data.candidates || [];
  }

  /** Poll session state */
  static async getState(code: string): Promise<{ status: string; hasOffer: boolean; hasAnswer: boolean }> {
    const response = await fetch(`${this.BASE_URL}/state?code=${code}`);
    if (!response.ok) return { status: 'waiting', hasOffer: false, hasAnswer: false };
    return response.json() as Promise<{ status: string; hasOffer: boolean; hasAnswer: boolean }>;
  }
}

// ─── Storage Module ─────────────────────────────────────────────────────────

class StorageModule {
  private static readonly STORAGE_KEY = 'wormhole_messages';

  static saveMessages(messages: ChatMessage[]): void {
    sessionStorage.setItem(this.STORAGE_KEY, JSON.stringify(messages));
  }

  static loadMessages(): ChatMessage[] {
    const data = sessionStorage.getItem(this.STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  }

  static clearMessages(): void {
    sessionStorage.removeItem(this.STORAGE_KEY);
  }

  static addMessage(message: ChatMessage): void {
    const messages = this.loadMessages();
    messages.push(message);
    this.saveMessages(messages);
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

  // ── UI Initialization ──

  private initUI(): void {
    // Connect view buttons
    const createBtn = document.getElementById('create-btn') as HTMLButtonElement | null;
    const joinBtn = document.getElementById('join-btn') as HTMLButtonElement | null;
    const codeInput = document.getElementById('code-input') as HTMLInputElement | null;
    const codeDisplay = document.getElementById('code-display');

    if (createBtn) {
      createBtn.addEventListener('click', () => this.handleCreate(codeInput));
    }

    if (joinBtn) {
      joinBtn.addEventListener('click', () => this.handleJoin(codeInput));
    }

    // Allow Enter key to submit
    if (codeInput) {
      codeInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          if (this.state.isInitiator) {
            this.handleCreate(codeInput);
          } else {
            this.handleJoin(codeInput);
          }
        }
      });
    }

    // Chat view send button
    const sendBtn = document.getElementById('send-btn') as HTMLButtonElement | null;
    const messageInput = document.getElementById('message-input') as HTMLTextAreaElement | null;

    if (sendBtn) {
      sendBtn.addEventListener('click', () => this.handleSend(messageInput));
    }

    if (messageInput) {
      messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          this.handleSend(messageInput);
        }
      });
    }

    // Back button
    const backBtn = document.getElementById('back-btn');
    if (backBtn) {
      backBtn.addEventListener('click', () => this.handleBack());
    }

    // Load saved messages
    this.state.messages = StorageModule.loadMessages();

    // Show stored messages if we have a previous code
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
    if (!this.validateCode(code)) {
      this.showError('请输入4位数字');
      return;
    }

    this.state.code = code;
    this.state.isInitiator = true;
    sessionStorage.setItem('wormhole_code', code);

    try {
      await this.startConnection();
    } catch (error) {
      this.showError(`创建房间失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  private async handleJoin(input: HTMLInputElement | null): Promise<void> {
    const code = input?.value.trim() ?? '';
    if (!this.validateCode(code)) {
      this.showError('请输入4位数字');
      return;
    }

    this.state.code = code;
    this.state.isInitiator = false;
    sessionStorage.setItem('wormhole_code', code);

    try {
      await this.joinConnection();
    } catch (error) {
      this.showError(`加入房间失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  private validateCode(code: string): boolean {
    return /^\d{4}$/.test(code);
  }

  // ── Connection Logic ──

  private async startConnection(): Promise<void> {
    this.updateStatus('creating');

    // Generate key pair
    this.state.keyPair = await CryptoModule.generateKeyPair();

    // Create WebRTC peer connection
    this.state.peerConnection = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }],
    });

    // Create data channel
    this.state.dataChannel = this.state.peerConnection.createDataChannel('chat', {
      ordered: true,
    });

    this.state.dataChannel.onopen = () => this.handleChannelOpen();
    this.state.dataChannel.onmessage = (event) => this.handleMessage(event.data);
    this.state.dataChannel.onclose = () => this.handleChannelClose();
    this.state.dataChannel.onerror = () => this.handleError('DataChannel error');

    // Handle ICE candidates
    this.state.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.handleICECandidate(event.candidate);
      }
    };

    // Handle connection state changes
    this.state.peerConnection.onconnectionstatechange = () => {
      this.handleConnectionStateChange();
    };

    // Generate and submit offer
    const offer = await this.state.peerConnection.createOffer();
    await this.state.peerConnection.setLocalDescription(offer);

    // Wait for SDP to be ready
    await this.waitForSDP();

    // Submit offer to signaling server
    await SignalingModule.postOffer(this.state.code!, offer);

    // Exchange public keys - send our public key via the answer channel
    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair!.publicKey);
    await SignalingModule.postAnswer(this.state.code!, { type: 'key-exchange', publicKey: myPublicKey } as unknown as RTCSessionDescriptionInit);

    this.updateStatus('waiting');
    this.startPolling();
    this.switchToChatView();
  }

  private async joinConnection(): Promise<void> {
    this.updateStatus('creating');

    // Generate key pair
    this.state.keyPair = await CryptoModule.generateKeyPair();

    // Create WebRTC peer connection
    this.state.peerConnection = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }],
    });

    // Handle incoming data channel
    this.state.peerConnection.ondatachannel = (event) => {
      this.state.dataChannel = event.channel;
      this.state.dataChannel.onopen = () => this.handleChannelOpen();
      this.state.dataChannel.onmessage = (e) => this.handleMessage(e.data);
      this.state.dataChannel.onclose = () => this.handleChannelClose();
      this.state.dataChannel.onerror = () => this.handleError('DataChannel error');
    };

    // Handle ICE candidates
    this.state.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.handleICECandidate(event.candidate);
      }
    };

    // Handle connection state changes
    this.state.peerConnection.onconnectionstatechange = () => {
      this.handleConnectionStateChange();
    };

    // Get offer from signaling server
    const { sdp: offerSdp } = await SignalingModule.getOffer(this.state.code!);
    await this.state.peerConnection!.setRemoteDescription(new RTCSessionDescription(offerSdp));

    // Generate and submit answer
    const answer = await this.state.peerConnection.createAnswer();
    await this.state.peerConnection.setLocalDescription(answer);

    // Wait for SDP to be ready
    await this.waitForSDP();

    // Submit answer to signaling server
    await SignalingModule.postAnswer(this.state.code!, answer);

    // Exchange public keys - send our public key via the candidate channel (we'll use a special candidate format)
    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair!.publicKey);
    // Use a fake ICE candidate to carry the key exchange data
    await SignalingModule.postCandidate(this.state.code!, {
      candidate: `a=fake-key:${myPublicKey}`,
      sdpMid: 'key-exchange',
      sdpMLineIndex: 0,
    });

    this.updateStatus('waiting');
    this.startPolling();
    this.switchToChatView();
  }

  private handleICECandidate(candidate: RTCIceCandidate): void {
    if (!this.state.code) return;
    SignalingModule.postCandidate(this.state.code, candidate.toJSON()).catch(console.error);
  }

  private async waitForSDP(): Promise<void> {
    return new Promise((resolve) => {
      if (this.state.peerConnection!.localDescription) {
        resolve();
        return;
      }
      this.state.peerConnection!.onicegatheringstatechange = () => {
        if (this.state.peerConnection!.iceGatheringState === 'complete') {
          resolve();
        }
      };
      // Fallback timeout
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

      if (state.status === 'connected' && this.state.status === 'connecting') {
        this.updateStatus('connected');
        this.stopPolling();
        this.showConnected();
      }
    }, 1000);
  }

  private stopPolling(): void {
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  // ── Channel Handlers ──

  private handleChannelOpen(): void {
    console.log('DataChannel opened');
    this.updateStatus('connected');
    this.showConnected();
  }

  private async handleMessage(data: string): Promise<void> {
    try {
      // Check if it's a key exchange message (special format)
      if (data.startsWith('a=fake-key:')) {
        const publicKeyBase64 = data.replace('a=fake-key:', '');
        // Derive shared key
        const remotePublicKey = await CryptoModule.importPublicKey(publicKeyBase64);
        this.state.sharedKey = await CryptoModule.deriveSharedKey(
          remotePublicKey,
          this.state.keyPair!.privateKey
        );
        console.log('Shared key derived successfully');

        // Now send our public key through the data channel
        if (this.state.dataChannel?.readyState === 'open' && this.state.keyPair) {
          const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
          this.state.dataChannel.send(JSON.stringify({ type: 'key-exchange', publicKey: myPublicKey }));
        }
        return;
      }

      // Try to parse as JSON (key exchange message)
      const parsed = JSON.parse(data) as { type?: string; publicKey?: string };

      if (parsed.type === 'key-exchange' && parsed.publicKey) {
        // Derive shared key
        const remotePublicKey = await CryptoModule.importPublicKey(parsed.publicKey);
        this.state.sharedKey = await CryptoModule.deriveSharedKey(
          remotePublicKey,
          this.state.keyPair!.privateKey
        );
        console.log('Shared key derived successfully');
        return;
      }

      // Decrypt message
      if (this.state.sharedKey) {
        const plaintext = await CryptoModule.decrypt(data, this.state.sharedKey);
        this.addMessage('remote', plaintext);
      }
    } catch (error) {
      console.error('Failed to process message:', error);
    }
  }

  private handleChannelClose(): void {
    console.log('DataChannel closed');
    this.updateStatus('error');
    this.showError('连接已断开');
  }

  private handleConnectionStateChange(): void {
    const state = this.state.peerConnection!.connectionState;
    console.log('Connection state:', state);

    if (state === 'disconnected' || state === 'failed' || state === 'closed') {
      this.updateStatus('error');
      this.showError('连接已断开，请重新建立连接');
    }
  }

  private handleError(message: string): void {
    console.error(message);
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
    } catch (error) {
      this.showError(`发送失败: ${error instanceof Error ? error.message : '未知错误'}`);
    }
  }

  private addMessage(sender: 'local' | 'remote', content: string): void {
    const message: ChatMessage = {
      id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      sender,
      content,
      encrypted: false,
    };

    this.state.messages.push(message);
    StorageModule.addMessage(message);
    this.renderMessages();
  }

  // ── UI Updates ──

  private updateStatus(status: SharedState['status']): void {
    this.state.status = status;

    const statusEl = document.getElementById('status');
    const statusText = document.getElementById('status-text');
    const statusChatEl = document.getElementById('status-chat');
    const statusChatText = document.getElementById('status-text-chat');

    if (statusEl && statusText) {
      statusEl.className = `status-dot status-${status}`;
      statusText.textContent = this.getStatusText(status);
    }

    if (statusChatEl && statusChatText) {
      statusChatEl.className = `status-dot status-${status}`;
      statusChatText.textContent = this.getStatusText(status);
    }

    // Update button states
    const createBtn = document.getElementById('create-btn') as HTMLButtonElement | null;
    const joinBtn = document.getElementById('join-btn') as HTMLButtonElement | null;

    if (createBtn) createBtn.disabled = status !== 'idle' && status !== 'error';
    if (joinBtn) joinBtn.disabled = status !== 'idle' && status !== 'error';
  }

  private getStatusText(status: SharedState['status']): string {
    switch (status) {
      case 'idle': return '准备就绪';
      case 'creating': return '正在创建连接...';
      case 'waiting': return '等待对方加入...';
      case 'connecting': return '正在建立连接...';
      case 'connected': return '已连接';
      case 'error': return '连接失败';
      default: return '未知状态';
    }
  }

  private showConnected(): void {
    const connectedEl = document.getElementById('connected-indicator');
    if (connectedEl) {
      connectedEl.style.display = 'block';
    }
  }

  private showError(message: string): void {
    const errorEl = document.getElementById('error-message');
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
      setTimeout(() => {
        errorEl.style.display = 'none';
      }, 5000);
    }
  }

  private switchToChatView(): void {
    const connectView = document.getElementById('connect-view');
    const chatView = document.getElementById('chat-view');
    const chatCode = document.getElementById('chat-code');

    if (connectView) connectView.style.display = 'none';
    if (chatView) chatView.style.display = 'flex';
    if (chatCode && this.state.code) chatCode.textContent = this.state.code;
  }

  private async handleBack(): Promise<void> {
    // Clean up connection
    this.stopPolling();
    if (this.state.dataChannel) {
      this.state.dataChannel.close();
      this.state.dataChannel = null;
    }
    if (this.state.peerConnection) {
      this.state.peerConnection.close();
      this.state.peerConnection = null;
    }

    // Reset state
    this.state = {
      code: null,
      peerConnection: null,
      dataChannel: null,
      keyPair: null,
      sharedKey: null,
      isInitiator: false,
      status: 'idle',
      messages: [],
    };

    // Clear storage
    StorageModule.clearMessages();
    sessionStorage.removeItem('wormhole_code');

    // Switch back to connect view
    const connectView = document.getElementById('connect-view');
    const chatView = document.getElementById('chat-view');

    if (connectView) connectView.style.display = 'flex';
    if (chatView) chatView.style.display = 'none';

    // Reset UI
    this.updateStatus('idle');
    const codeDisplay = document.getElementById('code-display');
    if (codeDisplay) codeDisplay.style.display = 'none';
  }

  private renderMessages(): void {
    const messagesContainer = document.getElementById('messages');
    if (!messagesContainer) return;

    messagesContainer.innerHTML = '';

    for (const message of this.state.messages) {
      const messageEl = document.createElement('div');
      messageEl.className = `message ${message.sender}`;

      const time = new Date(message.timestamp).toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
      });

      messageEl.innerHTML = `
        <div class="message-content">${this.escapeHtml(message.content)}</div>
        <div class="message-time">${time}</div>
      `;

      messagesContainer.appendChild(messageEl);
    }

    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// ─── Initialize Application ─────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  const app = new WormholeApp();
  (window as unknown as Record<string, WormholeApp>).app = app;
});
