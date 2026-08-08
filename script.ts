// ── Wormhole 前端主入口 ─────────────────────────────────────────────────────
// 处理 UI 交互，协调 webrtc 模块。

import { startChat, sendChatMessage, disconnect } from './webrtc.ts';

// ── DOM ──────────────────────────────────────────────────────────────────────

const $ = (id: string) => document.getElementById(id)!;

const panelRoom    = $('panel-room');
const panelWait    = $('panel-waiting');
const panelChat    = $('panel-chat');
const roomInput    = $('room-input');
const nickInput    = $('nick-input');
const btnCreate    = $('btn-create');
const btnJoin      = $('btn-join');
const btnBack      = $('btn-back');
const roomCodeDisp = $('room-code-display');
const shareLink    = $('share-link');
const btnCopy      = $('btn-copy');
const connStatus   = $('conn-status');
const messagesDiv  = $('messages');
const msgInput     = $('msg-input');
const msgForm      = $('msg-form');

// ── 面板切换 ─────────────────────────────────────────────────────────────────

function showPanel(panel: typeof panelRoom) {
  [panelRoom, panelWait, panelChat].forEach(p => p.classList.remove('active'));
  panel.classList.add('active');
}

// ── 消息渲染 ─────────────────────────────────────────────────────────────────

function appendMessage(nick: string, text: string, dir: 'sent' | 'received'): void {
  const div = document.createElement('div');
  div.className = `msg ${dir}`;
  const t = new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  div.innerHTML = `<div>${esc(text)}</div><div class="msg-meta">${dir === 'sent' ? '你 · ' : esc(nick) + ' · '}${t}</div>`;
  messagesDiv.appendChild(div);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function appendSystem(text: string): void {
  const div = document.createElement('div');
  div.className = 'msg system';
  div.textContent = text;
  messagesDiv.appendChild(div);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function setStatus(text: string, type?: 'connected' | 'error'): void {
  connStatus.textContent = text;
  connStatus.className = 'status' + (type ? ` ${type}` : '');
}

// ── 房间链接 ─────────────────────────────────────────────────────────────────

function getRoomUrl(): string {
  return `${location.origin}${location.pathname}?room=${encodeURIComponent(roomInput.value.trim())}`;
}

function loadRoom(): string | null {
  return new URLSearchParams(location.search).get('room');
}

// ── 初始化 ───────────────────────────────────────────────────────────────────

function init() {
  const room = loadRoom();

  if (room) {
    roomInput.value = room;
    roomCodeDisp.textContent = room;
    shareLink.value = getRoomUrl();
    showPanel(panelWait);
    startChat(false, nickInput.value.trim() || '访客').then(onConnected);
  } else {
    showPanel(panelRoom);
  }

  btnCreate.addEventListener('click', () => {
    const room = roomInput.value.trim();
    if (!room) { roomInput.focus(); return; }
    roomCodeDisp.textContent = room;
    shareLink.value = getRoomUrl();
    showPanel(panelWait);
    startChat(true, nickInput.value.trim() || '我').then(onConnected);
  });

  btnJoin.addEventListener('click', () => {
    const room = roomInput.value.trim();
    if (!room) { roomInput.focus(); return; }
    roomCodeDisp.textContent = room;
    shareLink.value = getRoomUrl();
    showPanel(panelWait);
    startChat(false, nickInput.value.trim() || '访客').then(onConnected);
  });

  btnCopy.addEventListener('click', () => {
    shareLink.select();
    navigator.clipboard.writeText(shareLink.value).then(() => {
      btnCopy.textContent = '已复制 ✓';
      setTimeout(() => { btnCopy.textContent = '复制链接'; }, 1500);
    });
  });

  btnBack.addEventListener('click', () => {
    disconnect();
    messagesDiv.innerHTML = '';
    showPanel(panelRoom);
  });

  msgForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = msgInput.value.trim();
    if (!text) return;
    try {
      await sendChatMessage(text);
      appendMessage('你', text, 'sent');
    } catch (err) {
      appendSystem(`发送失败: ${err instanceof Error ? err.message : '未知错误'}`);
    }
    msgInput.value = '';
  });
}

// ── 连接成功回调 ─────────────────────────────────────────────────────────────

function onConnected(s: { onMessage: (n: string, t: string) => void; onStatus: (t: string, type?: 'connected' | 'error') => void; onDisconnect?: () => void }): void {
  s.onMessage = (nick, text) => appendMessage(nick, text, 'received');
  s.onStatus  = setStatus;
  s.onDisconnect = () => appendSystem('对方已断开连接');
}

document.addEventListener('DOMContentLoaded', init);
