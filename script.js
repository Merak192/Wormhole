/**
 * Wormhole - P2P Encrypted Chat
 *
 * Architecture:
 * - WebRTC DataChannel for P2P messaging
 * - Cloudflare Pages Functions + KV for signaling
 * - Web Crypto API for AES-256-GCM encryption
 * - SessionStorage for local message history (cleared on browser close)
 */
// ─── Encryption Module ──────────────────────────────────────────────────────
class CryptoModule {
    /** Generate ECDH key pair for key exchange */
    static async generateKeyPair() {
        return crypto.subtle.generateKey({
            name: 'ECDH',
            namedCurve: 'P-256',
        }, true, ['deriveKey']);
    }
    /** Export public key to base64 string */
    static async exportPublicKey(key) {
        const raw = await crypto.subtle.exportKey('spki', key);
        return btoa(String.fromCharCode(...new Uint8Array(raw)));
    }
    /** Import public key from base64 string */
    static async importPublicKey(base64Key) {
        const binary = new Uint8Array(Array.from(atob(base64Key)).map(c => c.charCodeAt(0)));
        return crypto.subtle.importKey('spki', binary.buffer, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    }
    /** Derive shared secret key using ECDH */
    static async deriveSharedKey(remotePublicKey, localPrivateKey) {
        return crypto.subtle.deriveKey({ name: 'ECDH', public: remotePublicKey }, localPrivateKey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }
    /** Encrypt message using AES-256-GCM */
    static async encrypt(plaintext, key) {
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
        // Combine IV + encrypted data
        const result = new Uint8Array(iv.length + encrypted.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encrypted), iv.length);
        return btoa(String.fromCharCode(...result));
    }
    /** Decrypt message using AES-256-GCM */
    static async decrypt(encryptedBase64, key) {
        const encrypted = new Uint8Array(Array.from(atob(encryptedBase64)).map(c => c.charCodeAt(0)));
        // Extract IV (first 12 bytes)
        const iv = encrypted.slice(0, 12);
        const data = encrypted.slice(12);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data.buffer);
        return new TextDecoder().decode(decrypted);
    }
}
// ─── Signaling Module ───────────────────────────────────────────────────────
class SignalingModule {
    /** Submit WebRTC offer to signaling server */
    static async postOffer(code, sdp) {
        const response = await fetch(`${this.BASE_URL}/offer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, sdp }),
        });
        if (!response.ok)
            throw new Error(`Offer failed: ${response.status}`);
        return response.json();
    }
    /** Get WebRTC offer from signaling server */
    static async getOffer(code) {
        const response = await fetch(`${this.BASE_URL}/offer?code=${code}`);
        if (!response.ok)
            throw new Error(`Offer not found: ${response.status}`);
        return response.json();
    }
    /** Submit WebRTC answer to signaling server */
    static async postAnswer(code, sdp) {
        const response = await fetch(`${this.BASE_URL}/answer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, sdp }),
        });
        if (!response.ok)
            throw new Error(`Answer failed: ${response.status}`);
        return response.json();
    }
    /** Get WebRTC answer from signaling server */
    static async getAnswer(code) {
        const response = await fetch(`${this.BASE_URL}/answer?code=${code}`);
        if (!response.ok)
            throw new Error(`Answer not found: ${response.status}`);
        return response.json();
    }
    /** Submit ICE candidate to signaling server */
    static async postCandidate(code, candidate) {
        await fetch(`${this.BASE_URL}/candidate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, candidate }),
        });
    }
    /** Get ICE candidates from signaling server */
    static async getCandidates(code) {
        const response = await fetch(`${this.BASE_URL}/candidate?code=${code}`);
        if (!response.ok)
            return [];
        const data = await response.json();
        return data.candidates || [];
    }
    /** Poll session state */
    static async getState(code) {
        const response = await fetch(`${this.BASE_URL}/state?code=${code}`);
        if (!response.ok)
            return { status: 'waiting', hasOffer: false, hasAnswer: false };
        return response.json();
    }
}
SignalingModule.BASE_URL = '';
// ─── Storage Module ─────────────────────────────────────────────────────────
class StorageModule {
    static saveMessages(messages) {
        sessionStorage.setItem(this.STORAGE_KEY, JSON.stringify(messages));
    }
    static loadMessages() {
        const data = sessionStorage.getItem(this.STORAGE_KEY);
        return data ? JSON.parse(data) : [];
    }
    static clearMessages() {
        sessionStorage.removeItem(this.STORAGE_KEY);
    }
    static addMessage(message) {
        const messages = this.loadMessages();
        messages.push(message);
        this.saveMessages(messages);
    }
}
StorageModule.STORAGE_KEY = 'wormhole_messages';
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
    // ── UI Initialization ──
    initUI() {
        // Connect view buttons
        const createBtn = document.getElementById('create-btn');
        const joinBtn = document.getElementById('join-btn');
        const codeInput = document.getElementById('code-input');
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
                    }
                    else {
                        this.handleJoin(codeInput);
                    }
                }
            });
        }
        // Chat view send button
        const sendBtn = document.getElementById('send-btn');
        const messageInput = document.getElementById('message-input');
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
    async handleCreate(input) {
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
        sessionStorage.setItem('wormhole_code', code);
        try {
            await this.joinConnection();
        }
        catch (error) {
            this.showError(`加入房间失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
    }
    validateCode(code) {
        return /^\d{4}$/.test(code);
    }
    // ── Connection Logic ──
    async startConnection() {
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
        await SignalingModule.postOffer(this.state.code, offer);
        // Exchange public keys - send our public key via the answer channel
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        await SignalingModule.postAnswer(this.state.code, { type: 'key-exchange', publicKey: myPublicKey });
        this.updateStatus('waiting');
        this.startPolling();
        this.switchToChatView();
    }
    async joinConnection() {
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
        const { sdp: offerSdp } = await SignalingModule.getOffer(this.state.code);
        await this.state.peerConnection.setRemoteDescription(new RTCSessionDescription(offerSdp));
        // Generate and submit answer
        const answer = await this.state.peerConnection.createAnswer();
        await this.state.peerConnection.setLocalDescription(answer);
        // Wait for SDP to be ready
        await this.waitForSDP();
        // Submit answer to signaling server
        await SignalingModule.postAnswer(this.state.code, answer);
        // Exchange public keys - send our public key via the candidate channel (we'll use a special candidate format)
        const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
        // Use a fake ICE candidate to carry the key exchange data
        await SignalingModule.postCandidate(this.state.code, {
            candidate: `a=fake-key:${myPublicKey}`,
            sdpMid: 'key-exchange',
            sdpMLineIndex: 0,
        });
        this.updateStatus('waiting');
        this.startPolling();
        this.switchToChatView();
    }
    handleICECandidate(candidate) {
        if (!this.state.code)
            return;
        SignalingModule.postCandidate(this.state.code, candidate.toJSON()).catch(console.error);
    }
    async waitForSDP() {
        return new Promise((resolve) => {
            if (this.state.peerConnection.localDescription) {
                resolve();
                return;
            }
            this.state.peerConnection.onicegatheringstatechange = () => {
                if (this.state.peerConnection.iceGatheringState === 'complete') {
                    resolve();
                }
            };
            // Fallback timeout
            setTimeout(resolve, 5000);
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
    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    }
    // ── Channel Handlers ──
    handleChannelOpen() {
        console.log('DataChannel opened');
        this.updateStatus('connected');
        this.showConnected();
    }
    async handleMessage(data) {
        try {
            // Check if it's a key exchange message (special format)
            if (data.startsWith('a=fake-key:')) {
                const publicKeyBase64 = data.replace('a=fake-key:', '');
                // Derive shared key
                const remotePublicKey = await CryptoModule.importPublicKey(publicKeyBase64);
                this.state.sharedKey = await CryptoModule.deriveSharedKey(remotePublicKey, this.state.keyPair.privateKey);
                console.log('Shared key derived successfully');
                // Now send our public key through the data channel
                if (this.state.dataChannel?.readyState === 'open' && this.state.keyPair) {
                    const myPublicKey = await CryptoModule.exportPublicKey(this.state.keyPair.publicKey);
                    this.state.dataChannel.send(JSON.stringify({ type: 'key-exchange', publicKey: myPublicKey }));
                }
                return;
            }
            // Try to parse as JSON (key exchange message)
            const parsed = JSON.parse(data);
            if (parsed.type === 'key-exchange' && parsed.publicKey) {
                // Derive shared key
                const remotePublicKey = await CryptoModule.importPublicKey(parsed.publicKey);
                this.state.sharedKey = await CryptoModule.deriveSharedKey(remotePublicKey, this.state.keyPair.privateKey);
                console.log('Shared key derived successfully');
                return;
            }
            // Decrypt message
            if (this.state.sharedKey) {
                const plaintext = await CryptoModule.decrypt(data, this.state.sharedKey);
                this.addMessage('remote', plaintext);
            }
        }
        catch (error) {
            console.error('Failed to process message:', error);
        }
    }
    handleChannelClose() {
        console.log('DataChannel closed');
        this.updateStatus('error');
        this.showError('连接已断开');
    }
    handleConnectionStateChange() {
        const state = this.state.peerConnection.connectionState;
        console.log('Connection state:', state);
        if (state === 'disconnected' || state === 'failed' || state === 'closed') {
            this.updateStatus('error');
            this.showError('连接已断开，请重新建立连接');
        }
    }
    handleError(message) {
        console.error(message);
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
        catch (error) {
            this.showError(`发送失败: ${error instanceof Error ? error.message : '未知错误'}`);
        }
    }
    addMessage(sender, content) {
        const message = {
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
    updateStatus(status) {
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
        const createBtn = document.getElementById('create-btn');
        const joinBtn = document.getElementById('join-btn');
        if (createBtn)
            createBtn.disabled = status !== 'idle' && status !== 'error';
        if (joinBtn)
            joinBtn.disabled = status !== 'idle' && status !== 'error';
    }
    getStatusText(status) {
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
    showConnected() {
        const connectedEl = document.getElementById('connected-indicator');
        if (connectedEl) {
            connectedEl.style.display = 'block';
        }
    }
    showError(message) {
        const errorEl = document.getElementById('error-message');
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
            setTimeout(() => {
                errorEl.style.display = 'none';
            }, 5000);
        }
    }
    switchToChatView() {
        const connectView = document.getElementById('connect-view');
        const chatView = document.getElementById('chat-view');
        const chatCode = document.getElementById('chat-code');
        if (connectView)
            connectView.style.display = 'none';
        if (chatView)
            chatView.style.display = 'flex';
        if (chatCode && this.state.code)
            chatCode.textContent = this.state.code;
    }
    async handleBack() {
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
        if (connectView)
            connectView.style.display = 'flex';
        if (chatView)
            chatView.style.display = 'none';
        // Reset UI
        this.updateStatus('idle');
        const codeDisplay = document.getElementById('code-display');
        if (codeDisplay)
            codeDisplay.style.display = 'none';
    }
    renderMessages() {
        const messagesContainer = document.getElementById('messages');
        if (!messagesContainer)
            return;
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
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}
// ─── Initialize Application ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const app = new WormholeApp();
    window.app = app;
});
