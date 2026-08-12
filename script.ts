/**
 * Wormhole - P2P Encrypted Chat
 *
 * 架构:
 * - Cloudflare Pages Functions 作为消息中转站
 * - AES-256-GCM 端到端加密
 * - 服务器只看到密文，看不到内容
 */

// ─── Type Definitions ───────────────────────────────────────────────────────

interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

interface Message {
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

// ─── API Module ─────────────────────────────────────────────────────────────

class API {
  /** POST /key - 交换公钥 */
  static async postKey(code: string, publicKey: string, participant: 1 | 2): Promise<void> {
    const res = await fetch('/key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, publicKey, participant }),
    });
    if (!res.ok) throw new Error(`Key exchange failed: ${res.status}`);
  }

  /** GET /key?code=&participant= - 获取公钥 */
  static async getKey(code: string, participant: 1 | 2): Promise<string> {
    const res = await fetch(`/key?code=${code}&participant=${participant}`);
    if (!res.ok) throw new Error(`Key not found: ${res.status}`);
    const data = await res.json() as { publicKey: string };
    return data.publicKey;
  }

  /** POST /message - 发送消息 */
  static async postMessage(code: string, encryptedMessage: string, participant: 1 | 2): Promise<void> {
    const res = await fetch('/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, message: encryptedMessage, participant }),
    });
    if (!res.ok) throw new Error(`Message send failed: ${res.status}`);
  }

  /** GET /message?code= - 获取消息列表 */
  static async getMessages(code: string, since?: number): Promise<Array<{ id: string; timestamp: number; sender: number; message: string }>> {
    const url = since ? `/message?code=${code}&since=${since}` : `/message?code=${code}`;
    const res = await fetch(url);
    if (!res.ok) {
      console.error('[API] Failed to get messages:', res.status, await res.text());
      return [];
    }
    const data = await res.json();
    // 兼容不同的响应格式
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.messages)) return data.messages;
    console.error('[API] Unexpected response format:', data);
    return [];
  }
}

// ─── Storage Module ─────────────────────────────────────────────────────────

class StorageModule {
  private static readonly KEY = 'wormhole_messages';

  static load(): Message[] {
    const data = sessionStorage.getItem(this.KEY);
    return data ? JSON.parse(data) : [];
  }

  static save(messages: Message[]): void {
    sessionStorage.setItem(this.KEY, JSON.stringify(messages));
  }

  static add(msg: Message): void {
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
  private state: {
    code: string | null;
    keyPair: KeyPair | null;
    sharedKey: CryptoKey | null;
    isInitiator: boolean;
    status: 'idle' | 'connecting' | 'connected' | 'error';
    messages: Message[];
    lastMessageId: string;
  } = {
    code: null,
    keyPair: null,
    sharedKey: null,
    isInitiator: false,
    status: 'idle',
    messages: [],
    lastMessageId: '',
  };

  private pollInterval: number | null = null;
  private messagePollInterval: number | null = null;

  constructor() {
    this.initUI();
  }

  private initUI(): void {
    const createBtn = document.getElementById('create-btn');
    const joinBtn = document.getElementById('join-btn');
    const codeInput = document.getElementById('code-input') as HTMLInputElement;
    const sendBtn = document.getElementById('send-btn');
    const messageInput = document.getElementById('message-input') as HTMLTextAreaElement;
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

    // Restore session
    this.state.messages = StorageModule.load();
    const savedCode = sessionStorage.getItem('wormhole_code');
    if (savedCode) {
      this.state.code = savedCode;
      this.switchToChatView();
      this.renderMessages();
    }
  }

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
      await this.startSession();
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
      await this.joinSession();
    } catch (e) {
      this.showError(`加入房间失败: ${e instanceof Error ? e.message : '未知错误'}`);
    }
  }

  private async startSession(): Promise<void> {
    this.updateStatus('connecting');
    this.state.keyPair = await CryptoModule.generateKeyPair();
    console.log('[Wormhole] A: Key pair generated');

    // Export and post public key
    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
    console.log('[Wormhole] A: Posting public key...');
    await API.postKey(this.state.code!, myPublicKey, 1);
    console.log('[Wormhole] A: Public key posted');

    // Start polling for key exchange
    this.startKeyPolling();
    this.startMessagePolling();
    this.switchToChatView();
    console.log('[Wormhole] A: Waiting for B to join...');
  }

  private async joinSession(): Promise<void> {
    this.updateStatus('connecting');
    this.state.keyPair = await CryptoModule.generateKeyPair();
    console.log('[Wormhole] B: Key pair generated');

    // Export and post public key
    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
    console.log('[Wormhole] B: Posting public key...');
    await API.postKey(this.state.code!, myPublicKey, 2);
    console.log('[Wormhole] B: Public key posted');

    // Start polling for key exchange
    this.startKeyPolling();
    this.startMessagePolling();
    this.switchToChatView();
    console.log('[Wormhole] B: Waiting for A...');
  }

  private startKeyPolling(): void {
    if (this.pollInterval) clearInterval(this.pollInterval);
    this.pollInterval = window.setInterval(async () => {
      if (!this.state.code) return;

      try {
        const remoteParticipant: 1 | 2 = this.state.isInitiator ? 2 : 1;
        const remotePublicKey = await API.getKey(this.state.code!, remoteParticipant);
        console.log('[Wormhole] Remote key received:', remotePublicKey.substring(0, 20) + '...');

        const remoteKey = await CryptoModule.importPublicKey(remotePublicKey);
        this.state.sharedKey = await CryptoModule.deriveSharedKey(remoteKey, this.state.keyPair!.privateKey);
        console.log('[Wormhole] Shared key derived successfully');

        this.updateStatus('connected');
        this.showConnected();

        if (this.pollInterval) clearInterval(this.pollInterval);
      } catch (e) {
        console.log('[Wormhole] Waiting for remote key...');
      }
    }, 1000);
  }

  private startMessagePolling(): void {
    if (this.messagePollInterval) clearInterval(this.messagePollInterval);
    this.messagePollInterval = window.setInterval(async () => {
      if (!this.state.code || !this.state.sharedKey) return;

      try {
        const messages = await API.getMessages(this.state.code!);
        const newMessages = messages.filter(m => m.id !== this.state.lastMessageId);

        const participant: 1 | 2 = this.state.isInitiator ? 1 : 2;

        for (const msg of newMessages) {
          this.state.lastMessageId = msg.id;
          // 如果消息是自己发送的，标记为 local
          const isLocal = msg.sender === participant;
          try {
            const plaintext = await CryptoModule.decrypt(msg.message, this.state.sharedKey!);
            this.addMessage(isLocal ? 'local' : 'remote', plaintext);
          } catch (e) {
            console.error('[Wormhole] Failed to decrypt message:', e);
          }
        }
      } catch (e) {
        console.error('[Wormhole] Failed to poll messages:', e);
      }
    }, 1000);
  }

  private async handleSend(input: HTMLTextAreaElement | null): Promise<void> {
    const message = input?.value.trim() ?? '';
    if (!message || !this.state.sharedKey) return;

    try {
      const encrypted = await CryptoModule.encrypt(message, this.state.sharedKey);
      const participant: 1 | 2 = this.state.isInitiator ? 1 : 2;

      // 先生成消息 ID，然后立即更新 lastMessageId
      const msgId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      this.state.lastMessageId = msgId;

      // 发送到服务器（不包含 ID，服务器会生成自己的 ID）
      await API.postMessage(this.state.code!, encrypted, participant);

      // 添加到本地显示
      this.addMessage('local', message, msgId);
      if (input) input.value = '';
    } catch (e) {
      this.showError(`发送失败: ${e instanceof Error ? e.message : '未知错误'}`);
    }
  }

  private addMessage(sender: 'local' | 'remote', content: string, id?: string): void {
    const msg: Message = {
      id: id || Date.now().toString() + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now(),
      sender,
      content,
    };
    this.state.messages.push(msg);
    StorageModule.add(msg);
    this.renderMessages();
  }

  private updateStatus(status: WormholeApp['state']['status']): void {
    this.state.status = status;
    const statusTexts: Record<string, string> = {
      idle: '准备就绪',
      connecting: '正在建立加密通道...',
      connected: '已连接',
      error: '连接失败',
    };
    const statusEl = document.getElementById('status');
    const statusTextEl = document.getElementById('status-text');
    const statusChatEl = document.getElementById('status-chat');
    const statusChatTextEl = document.getElementById('status-text-chat');
    if (statusEl) statusEl.className = `status-dot status-${status}`;
    if (statusTextEl) statusTextEl.textContent = statusTexts[status] ?? status;
    if (statusChatEl) statusChatEl.className = `status-dot status-${status}`;
    if (statusChatTextEl) statusChatTextEl.textContent = statusTexts[status] ?? status;

    const disabled = status !== 'idle' && status !== 'error';
    const createBtn = document.getElementById('create-btn') as HTMLButtonElement | null;
    const joinBtn = document.getElementById('join-btn') as HTMLButtonElement | null;
    if (createBtn) createBtn.disabled = disabled;
    if (joinBtn) joinBtn.disabled = disabled;
  }

  private showConnected(): void {
    const el = document.getElementById('connected-indicator');
    if (el) {
      el.style.display = 'block';
    }
  }

  private switchToChatView(): void {
    document.getElementById('connect-view')!.style.display = 'none';
    document.getElementById('chat-view')!.style.display = 'flex';
    document.getElementById('chat-code')!.textContent = this.state.code ?? '';
  }

  private async handleBack(): Promise<void> {
    if (this.pollInterval) clearInterval(this.pollInterval);
    if (this.messagePollInterval) clearInterval(this.messagePollInterval);

    this.state = {
      code: null,
      keyPair: null,
      sharedKey: null,
      isInitiator: false,
      status: 'idle',
      messages: [],
      lastMessageId: '',
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

  private showError(msg: string): void {
    const el = document.getElementById('error-message');
    if (el) {
      el.textContent = msg;
      el.style.display = 'block';
      setTimeout(() => { el.style.display = 'none'; }, 5000);
    }
  }
}

// ─── Init ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  (window as unknown as Record<string, WormholeApp>).app = new WormholeApp();
});
