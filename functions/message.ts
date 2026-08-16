import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/message - 发送消息
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, message, participant, id } = await context.request.json() as { code: string; message: string; participant: 1 | 2; id: string };

  console.log('[Server] POST /message - code:', code, 'participant:', participant, 'msgId:', id);

  if (!code || !message || !participant || !id) {
    console.error('[Server] Missing required fields:', { code, message, participant, id });
    return new Response(JSON.stringify({ error: 'code, message, participant and id required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `msg:${code}`;
  const existing = await WORM_HOLE.get(key);
  let messages: Array<{ id: string; timestamp: number; sender: number; message: string }> = [];

  if (existing) {
    try {
      messages = JSON.parse(existing);
    } catch (e) {
      console.error('[Server] Failed to parse messages:', e);
      messages = [];
    }
  }

  // 检查是否已存在相同 ID 的消息（防止重复）
  const exists = messages.some(m => m.id === id);
  if (exists) {
    console.log('[Server] Message already exists, skipping');
    return new Response(JSON.stringify({ status: 'exists', count: messages.length }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 限制消息数量（保留最近100条）
  if (messages.length >= 100) {
    messages = messages.slice(-99);
  }

  messages.push({
    id: id,
    timestamp: Date.now(),
    sender: participant,
    message,
  });

  await WORM_HOLE.put(key, JSON.stringify(messages), { expirationTtl: 600 });
  console.log('[Server] Message stored successfully, total:', messages.length);

  return new Response(JSON.stringify({ status: 'sent', count: messages.length }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/message?code=&since= - 获取消息
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code') as string;
  const since = url.searchParams.get('since');

  console.log('[Server] GET /message - code:', code, 'since:', since);

  if (!code) {
    return new Response(JSON.stringify({ error: 'code parameter required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `msg:${code}`;
  const data = await WORM_HOLE.get(key);

  console.log('[Server] Data from KV:', data ? `found (${data.length} bytes)` : 'not found');

  if (!data) {
    return new Response(JSON.stringify({ messages: [] }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let messages: Array<{ id: string; timestamp: number; sender: number; message: string }> = [];
  try {
    messages = JSON.parse(data);
    console.log('[Server] Parsed', messages.length, 'messages');
  } catch (e) {
    console.error('[Server] Failed to parse messages:', e);
    return new Response(JSON.stringify({ messages: [] }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  if (since) {
    messages = messages.filter(m => m.id !== since);
    console.log('[Server] After filter, remaining:', messages.length);
  }

  return new Response(JSON.stringify(messages), {
    headers: { 'Content-Type': 'application/json' },
  });
};
