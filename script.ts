// ── Wormhole 前端主入口 ─────────────────────────────────────────────────────

import { startChat, sendChatMessage, disconnect } from './webrtc.ts';

// ── DOM 查询 ─────────────────────────────────────────────────────────────────

const getById = (id: string): HTMLElement | null => document.getElementById(id);

function getPanel(id: string): HTMLDivElement {
  const el = getById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as HTMLDivElement;
}

function getInput(id: string): HTMLInputElement {
  const el = getById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as HTMLInputElement;
}

function getButton(id: string): HTMLButtonElement {
  const el = getById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as HTMLButtonElement;
}

function getForm(id: string): HTMLFormElement {
  const el = getById(id);
  if (!el) throw new Error(`Element #${id} not found`);
  return el as HTMLFormElement;
}

// ── 面板切换 ─────────────────────────────────────────────────────────────────

function showPanel(panelId: string): void {
  const panels = ['panel-room', 'panel-waiting', 'panel-chat'].map(getPanel);
  panels.forEach(p => p.classList.remove('active'));
  getPanel(panelId).classList.add('active');
}

// ── 消息渲染 ─────────────────────────────────────────────────────────────────

function appendMessage(nick: string, text: string, dir: 'sent' | 'received'): void {
  const div = document.createElement('div');
  div.className = `msg ${dir}`;
  const t = new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  div.innerHTML = `<div>${esc(text)}</div><div class="msg-meta">${dir === 'sent' ? '你 · ' : esc(nick) + ' · '}${t}</div>`;
  const messagesDiv = getById('messages') as HTMLDivElement;
  messagesDiv.appendChild(div);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function appendSystem(text: string): void {
  const div = document.createElement('div');
  div.className = 'msg system';
  div.textContent = text;
  const messagesDiv = getById('messages') as HTMLDivElement;
  messagesDiv.appendChild(div);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function setStatus(text: string, type?: 'connected' | 'error'): void {
  const connStatus = getById('conn-status') as HTMLDivElement;
  connStatus.textContent = text;
  connStatus.className = 'status' + (type ? ` ${type}` : '');
}

function getRoomUrl(room: string): string {
  return `${location.origin}${location.pathname}?room=${encodeURIComponent(room)}`;
}

function loadRoom(): string | null {
  return new URLSearchParams(location.search).get('room');
}

// ── 初始化 ───────────────────────────────────────────────────────────────────

function init(): void {
  const room = loadRoom();

  if (room) {
    getInput('room-input').value = room;
    (getById('room-code-display') as HTMLDivElement).textContent = room;
    (getInput('share-link') as HTMLInputElement).value = getRoomUrl(room);
    showPanel('panel-waiting');
    connect(room, getInput('nick-input').value.trim() || '访客');
  } else {
    showPanel('panel-room');
  }

  // 按钮事件
  getButton('btn-create').addEventListener('click', () => {
    const room = getInput('room-input').value.trim();
    if (!room) { getInput('room-input').focus(); return; }
    (getById('room-code-display') as HTMLDivElement).textContent = room;
    (getInput('share-link') as HTMLInputElement).value = getRoomUrl(room);
    showPanel('panel-waiting');
    connect(room, getInput('nick-input').value.trim() || '我');
  });

  getButton('btn-join').addEventListener('click', () => {
    const room = getInput('room-input').value.trim();
    if (!room) { getInput('room-input').focus(); return; }
    (getById('room-code-display') as HTMLDivElement).textContent = room;
    (getInput('share-link') as HTMLInputElement).value = getRoomUrl(room);
    showPanel('panel-waiting');
    connect(room, getInput('nick-input').value.trim() || '访客');
  });

  getButton('btn-copy').addEventListener('click', () => {
    const shareLink = getInput('share-link');
    shareLink.select();
    navigator.clipboard.writeText(shareLink.value).then(() => {
      getButton('btn-copy').textContent = '已复制 ✓';
      setTimeout(() => { getButton('btn-copy').textContent = '复制链接'; }, 1500);
    });
  });

  getButton('btn-back').addEventListener('click', () => {
    disconnect();
    (getById('messages') as HTMLDivElement).innerHTML = '';
    showPanel('panel-room');
  });

  getForm('msg-form').addEventListener('submit', async (e: Event) => {
    e.preventDefault();
    const text = getInput('msg-input').value.trim();
    if (!text) return;
    try {
      await sendChatMessage(text);
      appendMessage('你', text, 'sent');
    } catch (err) {
      appendSystem(`发送失败: ${err instanceof Error ? err.message : String(err)}`);
    }
    getInput('msg-input').value = '';
  });
}

function connect(room: string, nick: string): void {
  startChat(nick, room)
    .then(s => {
      s.onMessage = (n, t) => appendMessage(n, t, 'received');
      s.onStatus  = setStatus;
      s.onDisconnect = () => appendSystem('对方已断开连接');
    })
    .catch(err => {
      console.error('连接失败:', err);
      setStatus(`连接失败: ${err instanceof Error ? err.message : String(err)}`, 'error');
    });
}

document.addEventListener('DOMContentLoaded', init);
