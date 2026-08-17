// ─── Crypto Module ──────────────────────────────────────────────────────────
class CryptoModule {
    static async generateKeyPair() {
        const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
        return keyPair;
    }
    static async exportPublicKey(publicKey) {
        const raw = await crypto.subtle.exportKey('spki', publicKey);
        return btoa(String.fromCharCode(...new Uint8Array(raw)));
    }
    static async importPublicKey(base64) {
        const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        return crypto.subtle.importKey('spki', raw.buffer, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    }
    static async deriveSharedKey(remotePublicKey, localPrivateKey) {
        return crypto.subtle.deriveBits({ name: 'ECDH', public: remotePublicKey }, localPrivateKey, 256);
        {
            algorithm: {
                name: "ECDH";
            }
            extractable: false,
                type;
            "secret",
                usages;
            ["encrypt", "decrypt"];
        }
        as;
        CryptoKey;
    }
}
async;
encrypt(plaintext, string, key, CryptoKey);
Promise < string > {
    const: encoder = new TextEncoder(),
    const: data = encoder.encode(plaintext),
    const: iv = crypto.getRandomValues(new Uint8Array(12)),
    const: encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data),
    const: combined = new Uint8Array(iv.length + encrypted.byteLength),
    combined, : .set(iv),
    combined, : .set(new Uint8Array(encrypted), iv.length),
    return: btoa(String.fromCharCode(...combined))
};
async;
decrypt(base64, string, key, CryptoKey);
Promise < string > {
    const: raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0)),
    const: iv = raw.slice(0, 12),
    const: data = raw.slice(12),
    const: decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data),
    return: new TextDecoder().decode(decrypted)
};
// ─── API Module ─────────────────────────────────────────────────────────────
class API {
    static async postOffer(code, sdp) {
        const res = await fetch('/offer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, sdp }),
        });
        if (!res.ok)
            throw new Error(`Offer failed: ${res.status}`);
    }
    static async getOffer(code) {
        const res = await fetch(`/offer?code=${code}`);
        if (!res.ok)
            throw new Error(`Offer not found: ${res.status}`);
        const data = await res.json();
        return data.sdp;
    }
    static async postAnswer(code, sdp) {
        const res = await fetch('/answer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, sdp }),
        });
        if (!res.ok)
            throw new Error(`Answer failed: ${res.status}`);
    }
    static async getAnswer(code) {
        const res = await fetch(`/answer?code=${code}`);
        if (!res.ok)
            throw new Error(`Answer not found: ${res.status}`);
        const data = await res.json();
        return data.sdp;
    }
    static async postKey(code, publicKey, participant) {
        const res = await fetch('/key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, publicKey, participant }),
        });
        if (!res.ok)
            throw new Error(`Key post failed: ${res.status}`);
    }
    static async getKey(code, participant) {
        const res = await fetch(`/key?code=${code}&participant=${participant}`);
        if (!res.ok)
            throw new Error(`Key not found: ${res.status}`);
        const data = await res.json();
        return data.publicKey;
    }
    static async postMessage(code, encryptedMessage, participant, id) {
        const res = await fetch('/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, message: encryptedMessage, participant, id }),
        });
        if (!res.ok)
            throw new Error(`Message send failed: ${res.status}`);
    }
    static async getMessages(code) {
        const res = await fetch(`/message?code=${code}`);
        if (!res.ok) {
            console.error('[API] Failed to get messages:', res.status);
            return [];
        }
        return await res.json();
    }
    static async getState(code) {
        const res = await fetch(`/state?code=${code}`);
        if (!res.ok)
            return { status: 'waiting', hasOffer: false, hasAnswer: false, bothKeys: false };
        return res.json();
    }
}
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
            processedIds: [],
            participant: 1,
        };
        this.pollInterval = null;
        this.messagePollInterval = null;
        this.init();
    }
    init() {
        const savedCode = sessionStorage.getItem('wormhole_code');
        if (savedCode) {
            this.state.code = savedCode;
            this.state.isInitiator = sessionStorage.getItem('wormhole_initiator') === 'true';
            this.state.participant = this.state.isInitiator ? 1 : 2;
            this.loadMessages();
        }
        this.bindEvents();
        this.renderMessages();
    }
    bindEvents() {
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
        messageInput?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.handleSend(messageInput);
            }
        });
    }
    async handleCreate(input) {
        const code = input?.value.trim() ?? '';
        if (!this.validateCode(code)) {
            this.showError('请输入4位数字');
            return;
        }
        this.state.code = code;
        this.state.isInitiator = true;
        this.state.participant = 1;
        sessionStorage.setItem('wormhole_code', code);
        sessionStorage.setItem('wormhole_initiator', 'true');
        sessionStorage.removeItem('wormhole_processed_ids');
        try {
            await this.startConnection();
        }
        catch (error) {
            this.showError(`创建房间失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
    }
    async handleJoin(input) {
        const code = input?.value.trim() ?? '';
        if (!this.validateCode(code)) {
            this.showError('请输入4位数字');
            return;
        }
        this.state.code = code;
        this.state.isInitiator = false;
        this.state.participant = 2;
        sessionStorage.setItem('wormhole_code', code);
        sessionStorage.setItem('wormhole_initiator', 'false');
        sessionStorage.removeItem('wormhole_processed_ids');
        try {
            await this.joinConnection();
        }
        catch (error) {
            this.showError(`加入房间失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
    }
    async startConnection() {
        this.state.keyPair = await CryptoModule.generateKeyPair();
        console.log('[Wormhole] A: Key pair generated');
        await API.postOffer(this.state.code, { type: 'offer', sdp: 'offer' });
        console.log('[Wormhole] A: Offer posted');
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        console.log('[Wormhole] A: Public key exported:', myPublicKey.substring(0, 20) + '...');
        await API.postKey(this.state.code, myPublicKey, 1);
        console.log('[Wormhole] A: Public key posted');
        this.updateStatus('waiting');
        this.startPolling();
        this.startMessagePolling();
        this.switchToChatView();
        console.log('[Wormhole] A: Waiting for B to join...');
    }
    async joinConnection() {
        this.state.keyPair = await CryptoModule.generateKeyPair();
        console.log('[Wormhole] B: Key pair generated');
        console.log('[Wormhole] B: Fetching offer...');
        const offer = await API.getOffer(this.state.code);
        console.log('[Wormhole] B: Offer received:', offer.type);
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        console.log('[Wormhole] B: Public key exported:', myPublicKey.substring(0, 20) + '...');
        await API.postKey(this.state.code, myPublicKey, 2);
        console.log('[Wormhole] B: Public key posted');
        await API.postAnswer(this.state.code, { type: 'answer', sdp: 'answer' });
        console.log('[Wormhole] B: Answer posted');
        this.updateStatus('waiting');
        this.startPolling();
        this.startMessagePolling();
        this.switchToChatView();
        console.log('[Wormhole] B: Waiting for A...');
    }
    // ── Polling ──
    startPolling() {
        if (this.pollInterval)
            clearInterval(this.pollInterval);
        this.pollInterval = window.setInterval(async () => {
            if (!this.state.code)
                return;
            const state = await API.getState(this.state.code);
            console.log('[Wormhole] Poll state:', state);
            if (state.bothKeys && this.state.status === 'waiting') {
                console.log('[Wormhole] Both keys received, deriving shared key');
                const remoteParticipant = this.state.isInitiator ? 2 : 1;
                try {
                    const remotePublicKeyBase64 = await API.getKey(this.state.code, remoteParticipant);
                    console.log('[Wormhole] Remote public key received:', remotePublicKeyBase64.substring(0, 20) + '...');
                    const remotePublicKey = await CryptoModule.importPublicKey(remotePublicKeyBase64);
                    this.state.sharedKey = await CryptoModule.deriveSharedKey(remotePublicKey, this.state.keyPair.privateKey);
                    console.log('[Wormhole] Shared key derived successfully');
                    this.updateStatus('connected');
                    this.stopPolling();
                    this.showConnected();
                }
                catch (e) {
                    console.error('[Wormhole] Key derivation failed:', e);
                }
            }
        }, 1000);
    }
    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }
    startMessagePolling() {
        if (this.messagePollInterval)
            clearInterval(this.messagePollInterval);
        this.messagePollInterval = window.setInterval(async () => {
            if (!this.state.code || !this.state.sharedKey)
                return;
            try {
                const messages = await API.getMessages(this.state.code);
                if (!Array.isArray(messages)) {
                    console.error('[Wormhole] Messages is not an array:', typeof messages);
                    return;
                }
                const newMessages = messages.filter(m => !this.state.processedIds.includes(m.id));
                console.log('[Wormhole] New messages:', newMessages.length);
                for (const msg of newMessages) {
                    this.state.processedIds.push(msg.id);
                    this.saveProcessedIds();
                    const isLocal = msg.sender === this.state.participant;
                    console.log('[Wormhole] Processing message:', msg.id, 'isLocal:', isLocal);
                    try {
                        const plaintext = await CryptoModule.decrypt(msg.message, this.state.sharedKey);
                        this.addMessage(isLocal ? 'local' : 'remote', plaintext, msg.id);
                    }
                    catch (e) {
                        console.error('[Wormhole] Failed to decrypt message:', e);
                    }
                }
            }
            catch (e) {
                console.error('[Wormhole] Failed to poll messages:', e);
            }
        }, 500);
    }
    saveProcessedIds() {
        sessionStorage.setItem('wormhole_processed_ids', JSON.stringify(this.state.processedIds));
    }
    loadProcessedIds() {
        const saved = sessionStorage.getItem('wormhole_processed_ids');
        if (saved) {
            try {
                this.state.processedIds = JSON.parse(saved);
                console.log('[Wormhole] Loaded', this.state.processedIds.length, 'processed IDs');
            }
            catch (e) {
                console.error('[Wormhole] Failed to load processed IDs:', e);
            }
        }
    }
    // ── Message Handling ──
    async handleSend(input) {
        const message = input?.value.trim() ?? '';
        if (!message || !this.state.sharedKey)
            return;
        try {
            const encrypted = await CryptoModule.encrypt(message, this.state.sharedKey);
            const msgId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            await API.postMessage(this.state.code, encrypted, this.state.participant, msgId);
            this.state.processedIds.push(msgId);
            this.saveProcessedIds();
            this.addMessage('local', message, msgId);
            if (input)
                input.value = '';
        }
        catch (e) {
            this.showError(`发送失败: ${e instanceof Error ? e.message : '未知错误'}`);
        }
    }
    addMessage(sender, content, id) {
        const msg = {
            id: id || `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            timestamp: Date.now(),
            sender,
            content,
        };
        this.state.messages.push(msg);
        this.renderMessages();
    }
    // ── UI ──
    updateStatus(status) {
        this.state.status = status;
        const texts = {
            idle: '准备就绪', creating: '正在创建连接...', waiting: '等待对方加入...',
            connecting: '正在建立加密通道...', connected: '已连接', error: '连接失败',
        };
        document.getElementById('status')?.className = `status-dot status-${status}`;
        document.getElementById('status-text')?.textContent = texts[status] ?? status;
        document.getElementById('status-chat')?.className = `status-dot status-${status}`;
        document.getElementById('status-text-chat')?.textContent = texts[status] ?? status;
        const disabled = status !== 'idle' && status !== 'error';
        document.getElementById('create-btn')?.disabled = disabled;
        document.getElementById('join-btn')?.disabled = disabled;
    }
    showConnected() {
        document.getElementById('connected-indicator')?.style.setProperty('display', 'block');
    }
    showError(msg) {
        const el = document.getElementById('error-message');
        if (el) {
            el.textContent = msg;
            el.style.setProperty('display', 'block');
            setTimeout(() => { el.style.setProperty('display', 'none'); }, 3000);
        }
    }
    switchToChatView() {
        document.getElementById('connect-view')?.style.setProperty('display', 'none');
        document.getElementById('chat-view')?.style.setProperty('display', 'flex');
        document.getElementById('chat-code')?.textContent = this.state.code ?? '';
    }
    renderMessages() {
        const container = document.getElementById('messages');
        if (!container)
            return;
        container.innerHTML = this.state.messages.map(msg => {
            const time = new Date(msg.timestamp).toLocaleTimeString();
            const isLocal = msg.sender === 'local';
            return `<div class="message ${msg.sender}">
        <div class="message-content">${this.escapeHtml(msg.content)}</div>
        <div class="message-time">${time}</div>
      </div>`;
        }).join('');
        container.scrollTop = container.scrollHeight;
    }
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    handleBack() {
        this.state = {
            code: null,
            keyPair: null,
            sharedKey: null,
            isInitiator: false,
            status: 'idle',
            messages: [],
            processedIds: [],
            participant: 1,
        };
        sessionStorage.removeItem('wormhole_code');
        sessionStorage.removeItem('wormhole_initiator');
        sessionStorage.removeItem('wormhole_processed_ids');
        this.stopPolling();
        if (this.messagePollInterval) {
            clearInterval(this.messagePollInterval);
            this.messagePollInterval = null;
        }
        this.switchToConnectView();
        this.renderMessages();
    }
    switchToConnectView() {
        document.getElementById('connect-view')?.style.setProperty('display', 'flex');
        document.getElementById('chat-view')?.style.setProperty('display', 'none');
    }
    validateCode(code) {
        return /^\d{4}$/.test(code);
    }
    loadMessages() {
        const saved = sessionStorage.getItem('wormhole_messages');
        if (saved) {
            try {
                this.state.messages = JSON.parse(saved);
            }
            catch (e) {
                this.state.messages = [];
            }
        }
        this.loadProcessedIds();
    }
}
// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    window.app = new WormholeApp();
});
