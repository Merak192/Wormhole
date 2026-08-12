/**
 * Wormhole - P2P Encrypted Chat
 *
 * 架构:
 * - Cloudflare Pages Functions 作为消息中转站
 * - AES-256-GCM 端到端加密
 * - 服务器只看到密文，看不到内容
 */
// ─── Encryption Module ──────────────────────────────────────────────────────
class CryptoModule {
    static async generateKeyPair() {
        return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
    }
    static async exportPublicKey(key) {
        const raw = await crypto.subtle.exportKey('spki', key);
        return btoa(String.fromCharCode(...new Uint8Array(raw)));
    }
    static async importPublicKey(base64Key) {
        const binary = new Uint8Array(Array.from(atob(base64Key)).map(c => c.charCodeAt(0)));
        return crypto.subtle.importKey('spki', binary.buffer, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    }
    static async deriveSharedKey(remotePublicKey, localPrivateKey) {
        return crypto.subtle.deriveKey({ name: 'ECDH', public: remotePublicKey }, localPrivateKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }
    static async encrypt(plaintext, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...result));
    }
    static async decrypt(encryptedBase64, key) {
        const encrypted = new Uint8Array(Array.from(atob(encryptedBase64)).map(c => c.charCodeAt(0)));
        const iv = encrypted.slice(0, 12);
        const data = encrypted.slice(12);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data.buffer);
        return new TextDecoder().decode(decrypted);
    }
}
// ─── API Module ─────────────────────────────────────────────────────────────
class API {
    /** POST /key - 交换公钥 */
    static async postKey(code, publicKey, participant) {
        const res = await fetch('/key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, publicKey, participant }),
        });
        if (!res.ok)
            throw new Error(`Key exchange failed: ${res.status}`);
    }
    /** GET /key?code=&participant= - 获取公钥 */
    static async getKey(code, participant) {
        const res = await fetch(`/key?code=${code}&participant=${participant}`);
        if (!res.ok)
            throw new Error(`Key not found: ${res.status}`);
        const data = await res.json();
        return data.publicKey;
    }
    /** POST /message - 发送消息 */
    static async postMessage(code, encryptedMessage, participant) {
        const res = await fetch('/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, message: encryptedMessage, participant }),
        });
        if (!res.ok)
            throw new Error(`Message send failed: ${res.status}`);
    }
    /** GET /message?code= - 获取消息列表 */
    static async getMessages(code, since) {
        const url = since ? `/message?code=${code}&since=${since}` : `/message?code=${code}`;
        const res = await fetch(url);
        if (!res.ok) {
            console.error('[API] Failed to get messages:', res.status, await res.text());
            return [];
        }
        const data = await res.json();
        // 兼容不同的响应格式
        if (Array.isArray(data))
            return data;
        if (data && Array.isArray(data.messages))
            return data.messages;
        console.error('[API] Unexpected response format:', data);
        return [];
    }
}
// ─── Storage Module ─────────────────────────────────────────────────────────
class StorageModule {
    static load() {
        const data = sessionStorage.getItem(this.KEY);
        return data ? JSON.parse(data) : [];
    }
    static save(messages) {
        sessionStorage.setItem(this.KEY, JSON.stringify(messages));
    }
    static add(msg) {
        const messages = this.load();
        messages.push(msg);
        this.save(messages);
    }
    static clear() {
        sessionStorage.removeItem(this.KEY);
    }
}
StorageModule.KEY = 'wormhole_messages';
// ─── Main Application ───────────────────────────────────────────────────────
class WormholeApp {
    constructor() {
        this.state = {
            code: null,
            keyPair: null,
            sharedKey: null,
            isInitiator: false,
            status: 'idle',
            messages: [],
            lastMessageId: '',
        };
        this.pollInterval = null;
        this.messagePollInterval = null;
        this.initUI();
    }
    initUI() {
        const createBtn = document.getElementById('create-btn');
        const joinBtn = document.getElementById('join-btn');
        const codeInput = document.getElementById('code-input');
        const sendBtn = document.getElementById('send-btn');
        const messageInput = document.getElementById('message-input');
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
    async handleCreate(input) {
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
        }
        catch (e) {
            this.showError(`创建房间失败: ${e instanceof Error ? e.message : '未知错误'}`);
        }
    }
    async handleJoin(input) {
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
        }
        catch (e) {
            this.showError(`加入房间失败: ${e instanceof Error ? e.message : '未知错误'}`);
        }
    }
    async startSession() {
        this.updateStatus('connecting');
        this.state.keyPair = await CryptoModule.generateKeyPair();
        console.log('[Wormhole] A: Key pair generated');
        // Export and post public key
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        console.log('[Wormhole] A: Posting public key...');
        await API.postKey(this.state.code, myPublicKey, 1);
        console.log('[Wormhole] A: Public key posted');
        // Start polling for key exchange
        this.startKeyPolling();
        this.startMessagePolling();
        this.switchToChatView();
        console.log('[Wormhole] A: Waiting for B to join...');
    }
    async joinSession() {
        this.updateStatus('connecting');
        this.state.keyPair = await CryptoModule.generateKeyPair();
        console.log('[Wormhole] B: Key pair generated');
        // Export and post public key
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        console.log('[Wormhole] B: Posting public key...');
        await API.postKey(this.state.code, myPublicKey, 2);
        console.log('[Wormhole] B: Public key posted');
        // Start polling for key exchange
        this.startKeyPolling();
        this.startMessagePolling();
        this.switchToChatView();
        console.log('[Wormhole] B: Waiting for A...');
    }
    startKeyPolling() {
        if (this.pollInterval)
            clearInterval(this.pollInterval);
        this.pollInterval = window.setInterval(async () => {
            if (!this.state.code)
                return;
            try {
                const remoteParticipant = this.state.isInitiator ? 2 : 1;
                const remotePublicKey = await API.getKey(this.state.code, remoteParticipant);
                console.log('[Wormhole] Remote key received:', remotePublicKey.substring(0, 20) + '...');
                const remoteKey = await CryptoModule.importPublicKey(remotePublicKey);
                this.state.sharedKey = await CryptoModule.deriveSharedKey(remoteKey, this.state.keyPair.privateKey);
                console.log('[Wormhole] Shared key derived successfully');
                this.updateStatus('connected');
                this.showConnected();
                if (this.pollInterval)
                    clearInterval(this.pollInterval);
            }
            catch (e) {
                console.log('[Wormhole] Waiting for remote key...');
            }
        }, 1000);
    }
    startMessagePolling() {
        if (this.messagePollInterval)
            clearInterval(this.messagePollInterval);
        this.messagePollInterval = window.setInterval(async () => {
            if (!this.state.code || !this.state.sharedKey)
                return;
            try {
                const messages = await API.getMessages(this.state.code);
                const newMessages = messages.filter(m => m.id !== this.state.lastMessageId);
                const participant = this.state.isInitiator ? 1 : 2;
                for (const msg of newMessages) {
                    this.state.lastMessageId = msg.id;
                    // 如果消息是自己发送的，标记为 local
                    const isLocal = msg.sender === participant;
                    try {
                        const plaintext = await CryptoModule.decrypt(msg.message, this.state.sharedKey);
                        this.addMessage(isLocal ? 'local' : 'remote', plaintext);
                    }
                    catch (e) {
                        console.error('[Wormhole] Failed to decrypt message:', e);
                    }
                }
            }
            catch (e) {
                console.error('[Wormhole] Failed to poll messages:', e);
            }
        }, 1000);
    }
    async handleSend(input) {
        const message = input?.value.trim() ?? '';
        if (!message || !this.state.sharedKey)
            return;
        try {
            const encrypted = await CryptoModule.encrypt(message, this.state.sharedKey);
            const participant = this.state.isInitiator ? 1 : 2;
            await API.postMessage(this.state.code, encrypted, participant);
            this.addMessage('local', message);
            if (input)
                input.value = '';
        }
        catch (e) {
            this.showError(`发送失败: ${e instanceof Error ? e.message : '未知错误'}`);
        }
    }
    addMessage(sender, content) {
        const msg = {
            id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
            timestamp: Date.now(),
            sender,
            content,
        };
        this.state.messages.push(msg);
        StorageModule.add(msg);
        this.renderMessages();
    }
    updateStatus(status) {
        this.state.status = status;
        const statusTexts = {
            idle: '准备就绪',
            connecting: '正在建立加密通道...',
            connected: '已连接',
            error: '连接失败',
        };
        const statusEl = document.getElementById('status');
        const statusTextEl = document.getElementById('status-text');
        const statusChatEl = document.getElementById('status-chat');
        const statusChatTextEl = document.getElementById('status-text-chat');
        if (statusEl)
            statusEl.className = `status-dot status-${status}`;
        if (statusTextEl)
            statusTextEl.textContent = statusTexts[status] ?? status;
        if (statusChatEl)
            statusChatEl.className = `status-dot status-${status}`;
        if (statusChatTextEl)
            statusChatTextEl.textContent = statusTexts[status] ?? status;
        const disabled = status !== 'idle' && status !== 'error';
        const createBtn = document.getElementById('create-btn');
        const joinBtn = document.getElementById('join-btn');
        if (createBtn)
            createBtn.disabled = disabled;
        if (joinBtn)
            joinBtn.disabled = disabled;
    }
    showConnected() {
        const el = document.getElementById('connected-indicator');
        if (el) {
            el.style.display = 'block';
        }
    }
    switchToChatView() {
        document.getElementById('connect-view').style.display = 'none';
        document.getElementById('chat-view').style.display = 'flex';
        document.getElementById('chat-code').textContent = this.state.code ?? '';
    }
    async handleBack() {
        if (this.pollInterval)
            clearInterval(this.pollInterval);
        if (this.messagePollInterval)
            clearInterval(this.messagePollInterval);
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
        document.getElementById('connect-view').style.display = 'flex';
        document.getElementById('chat-view').style.display = 'none';
        this.updateStatus('idle');
    }
    renderMessages() {
        const container = document.getElementById('messages');
        if (!container)
            return;
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
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    showError(msg) {
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
    window.app = new WormholeApp();
});
