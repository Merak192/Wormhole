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
// ─── Signaling Module ───────────────────────────────────────────────────────
class SignalingModule {
    /** POST /offer */
    static async postOffer(code, sdp) {
        const res = await fetch('/offer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, sdp }),
        });
        if (!res.ok)
            throw new Error(`Offer failed: ${res.status}`);
    }
    /** GET /offer?code= */
    static async getOffer(code) {
        const res = await fetch(`/offer?code=${code}`);
        if (!res.ok)
            throw new Error(`Offer not found: ${res.status}`);
        const data = await res.json();
        return data.sdp;
    }
    /** POST /answer */
    static async postAnswer(code, sdp) {
        const res = await fetch('/answer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, sdp }),
        });
        if (!res.ok)
            throw new Error(`Answer failed: ${res.status}`);
    }
    /** POST /key */
    static async postKey(code, publicKey, participant) {
        const res = await fetch('/key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, publicKey, participant }),
        });
        if (!res.ok)
            throw new Error(`Key exchange failed: ${res.status}`);
    }
    /** GET /key?code=&participant= */
    static async getKey(code, participant) {
        const res = await fetch(`/key?code=${code}&participant=${participant}`);
        if (!res.ok)
            throw new Error(`Key not found: ${res.status}`);
        const data = await res.json();
        return data.publicKey;
    }
    /** POST /candidate */
    static async postCandidate(code, candidate) {
        await fetch('/candidate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, candidate }),
        });
    }
    /** GET /state?code= */
    static async getState(code) {
        const res = await fetch(`/state?code=${code}`);
        if (!res.ok)
            return { status: 'waiting', hasOffer: false, hasAnswer: false, bothKeys: false };
        return res.json();
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
            peerConnection: null,
            dataChannel: null,
            keyPair: null,
            sharedKey: null,
            isInitiator: false,
            status: 'idle',
            messages: [],
        };
        this.pollInterval = null;
        this.initUI();
    }
    // ── UI Init ──
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
        // Restore previous session
        this.state.messages = StorageModule.load();
        const savedCode = sessionStorage.getItem('wormhole_code');
        if (savedCode) {
            // 刷新后不自动进入聊天，让用户重新建立连接
            // 仅恢复消息历史
            this.state.messages = StorageModule.load();
        }
    }
    // ── Connection Handlers ──
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
            await this.startConnection();
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
            await this.joinConnection();
        }
        catch (e) {
            this.showError(`加入房间失败: ${e instanceof Error ? e.message : '未知错误'}`);
        }
    }
    // ── Connection Logic ──
    async startConnection() {
        this.updateStatus('creating');
        this.state.keyPair = await CryptoModule.generateKeyPair();
        console.log('[Wormhole] A: Key pair generated');
        this.state.peerConnection = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }],
        });
        console.log('[Wormhole] A: PeerConnection created');
        // Create data channel
        this.state.dataChannel = this.state.peerConnection.createDataChannel('chat', { ordered: true });
        this.state.dataChannel.onopen = () => this.onChannelOpen();
        this.state.dataChannel.onmessage = (e) => this.onMessage(e.data);
        this.state.dataChannel.onclose = () => this.onChannelClose();
        this.state.dataChannel.onerror = () => this.handleError('DataChannel error');
        console.log('[Wormhole] A: DataChannel created');
        this.state.peerConnection.onicecandidate = (e) => {
            if (e.candidate) {
                console.log('[Wormhole] A: ICE candidate', e.candidate.candidate?.substring(0, 30) + '...');
                SignalingModule.postCandidate(this.state.code, e.candidate.toJSON()).catch(console.error);
            }
        };
        this.state.peerConnection.onconnectionstatechange = () => this.onConnectionStateChange();
        console.log('[Wormhole] A: Event handlers attached');
        // Generate offer
        const offer = await this.state.peerConnection.createOffer();
        console.log('[Wormhole] A: Offer created:', offer.type);
        await this.state.peerConnection.setLocalDescription(offer);
        console.log('[Wormhole] A: Local description set');
        await this.waitForGathering();
        console.log('[Wormhole] A: Gathering wait completed');
        // Post offer and public key (participant=1 for initiator)
        await SignalingModule.postOffer(this.state.code, this.state.peerConnection.localDescription);
        console.log('[Wormhole] A: Offer posted to server');
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        console.log('[Wormhole] A: Public key exported:', myPublicKey.substring(0, 20) + '...');
        await SignalingModule.postKey(this.state.code, myPublicKey, 1);
        console.log('[Wormhole] A: Public key posted to server');
        this.updateStatus('waiting');
        this.startPolling();
        this.switchToChatView();
        console.log('[Wormhole] A: Waiting for B to join...');
    }
    async joinConnection() {
        this.updateStatus('creating');
        this.state.keyPair = await CryptoModule.generateKeyPair();
        console.log('[Wormhole] B: Key pair generated');
        this.state.peerConnection = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }, { urls: 'stun:stun1.l.google.com:19302' }],
        });
        console.log('[Wormhole] B: PeerConnection created');
        this.state.peerConnection.ondatachannel = (e) => {
            console.log('[Wormhole] B: DataChannel received');
            this.state.dataChannel = e.channel;
            this.state.dataChannel.onopen = () => this.onChannelOpen();
            this.state.dataChannel.onmessage = (ev) => this.onMessage(ev.data);
            this.state.dataChannel.onclose = () => this.onChannelClose();
            this.state.dataChannel.onerror = () => this.handleError('DataChannel error');
        };
        this.state.peerConnection.onicecandidate = (e) => {
            if (e.candidate) {
                console.log('[Wormhole] B: ICE candidate', e.candidate.candidate?.substring(0, 30) + '...');
                SignalingModule.postCandidate(this.state.code, e.candidate.toJSON()).catch(console.error);
            }
        };
        this.state.peerConnection.onconnectionstatechange = () => this.onConnectionStateChange();
        console.log('[Wormhole] B: Event handlers attached');
        // Get offer
        console.log('[Wormhole] B: Fetching offer...');
        const offerSdp = await SignalingModule.getOffer(this.state.code);
        console.log('[Wormhole] B: Offer received:', offerSdp.type);
        await this.state.peerConnection.setRemoteDescription(new RTCSessionDescription(offerSdp));
        console.log('[Wormhole] B: Remote description set');
        // Generate answer
        const answer = await this.state.peerConnection.createAnswer();
        console.log('[Wormhole] B: Answer created:', answer.type);
        await this.state.peerConnection.setLocalDescription(answer);
        console.log('[Wormhole] B: Local description set');
        await this.waitForGathering();
        console.log('[Wormhole] B: Gathering wait completed');
        // Post answer and public key (participant=2 for joiner)
        await SignalingModule.postAnswer(this.state.code, this.state.peerConnection.localDescription);
        console.log('[Wormhole] B: Answer posted to server');
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        console.log('[Wormhole] B: Public key exported:', myPublicKey.substring(0, 20) + '...');
        await SignalingModule.postKey(this.state.code, myPublicKey, 2);
        console.log('[Wormhole] B: Public key posted to server');
        this.updateStatus('waiting');
        this.startPolling();
        this.switchToChatView();
        console.log('[Wormhole] B: Waiting for connection...');
    }
    waitForGathering() {
        return new Promise((resolve) => {
            // 立即 resolve，不等待 ICE 收集完成
            // ICE 候选会通过 onicecandidate 事件逐步添加
            resolve();
        });
    }
    // ── Polling ──
    startPolling() {
        if (this.pollInterval)
            clearInterval(this.pollInterval);
        this.pollInterval = window.setInterval(async () => {
            if (!this.state.code)
                return;
            const state = await SignalingModule.getState(this.state.code);
            console.log('[Wormhole] Poll state:', state);
            if (state.hasOffer && state.hasAnswer && this.state.status === 'waiting') {
                this.updateStatus('connecting');
                console.log('[Wormhole] Offer and answer received, starting key exchange');
            }
            if (state.bothKeys && this.state.status === 'connecting') {
                console.log('[Wormhole] Both keys received, deriving shared key');
                // Derive shared key from remote public key
                // Initiator (1) gets remote key from participant 2, Joiner (2) gets remote key from participant 1
                const remoteParticipant = this.state.isInitiator ? 2 : 1;
                try {
                    const remotePublicKeyBase64 = await SignalingModule.getKey(this.state.code, remoteParticipant);
                    console.log('[Wormhole] Remote public key received:', remotePublicKeyBase64.substring(0, 20) + '...');
                    const remotePublicKey = await CryptoModule.importPublicKey(remotePublicKeyBase64);
                    console.log('[Wormhole] Remote public key imported');
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
    // ── Channel Events ──
    onChannelOpen() {
        console.log('[Wormhole] DataChannel opened');
        if (this.state.status !== 'connected') {
            this.updateStatus('connected');
            this.showConnected();
        }
    }
    async onMessage(data) {
        if (!this.state.sharedKey) {
            console.warn('[Wormhole] Received message but shared key not ready');
            return;
        }
        try {
            const plaintext = await CryptoModule.decrypt(data, this.state.sharedKey);
            this.addMessage('remote', plaintext);
        }
        catch (e) {
            console.error('[Wormhole] Failed to decrypt message:', e);
        }
    }
    onChannelClose() {
        console.log('[Wormhole] DataChannel closed');
        this.updateStatus('error');
        this.showError('连接已断开');
    }
    onConnectionStateChange() {
        const state = this.state.peerConnection.connectionState;
        console.log('[Wormhole] Connection state:', state);
        if (state === 'disconnected' || state === 'failed' || state === 'closed') {
            this.updateStatus('error');
            this.showError('连接已断开');
        }
    }
    // ── Message Handling ──
    async handleSend(input) {
        const message = input?.value.trim() ?? '';
        if (!message || !this.state.dataChannel || this.state.dataChannel.readyState !== 'open' || !this.state.sharedKey)
            return;
        try {
            const encrypted = await CryptoModule.encrypt(message, this.state.sharedKey);
            this.state.dataChannel.send(encrypted);
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
    // ── UI Updates ──
    updateStatus(status) {
        this.state.status = status;
        const texts = {
            idle: '准备就绪', creating: '正在创建连接...', waiting: '等待对方加入...',
            connecting: '正在建立加密通道...', connected: '已连接', error: '连接失败',
        };
        const statusEl = document.getElementById('status');
        const statusTextEl = document.getElementById('status-text');
        const statusChatEl = document.getElementById('status-chat');
        const statusChatTextEl = document.getElementById('status-text-chat');
        if (statusEl)
            statusEl.className = `status-dot status-${status}`;
        if (statusTextEl)
            statusTextEl.textContent = texts[status] ?? status;
        if (statusChatEl)
            statusChatEl.className = `status-dot status-${status}`;
        if (statusChatTextEl)
            statusChatTextEl.textContent = texts[status] ?? status;
        const disabled = status !== 'idle' && status !== 'error';
        const createBtn = document.getElementById('create-btn');
        const joinBtn = document.getElementById('join-btn');
        if (createBtn)
            createBtn.disabled = disabled;
        if (joinBtn)
            joinBtn.disabled = disabled;
    }
    showConnected() {
        document.getElementById('connected-indicator')?.style.setProperty('display', 'block');
    }
    showError(msg) {
        const el = document.getElementById('error-message');
        if (el) {
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => { el.style.display = 'none'; }, 5000);
        }
    }
    switchToChatView() {
        document.getElementById('connect-view').style.display = 'none';
        document.getElementById('chat-view').style.display = 'flex';
        document.getElementById('chat-code').textContent = this.state.code ?? '';
    }
    async handleBack() {
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
    handleError(msg) { console.error(msg); }
}
// ─── Init ────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    window.app = new WormholeApp();
});
