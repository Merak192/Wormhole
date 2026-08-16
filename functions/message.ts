import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/message - 发送消息
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, message, participant, id } = await context.request.json() as { code: string; message: string; participant: 1 | 2; id: string };

  if (!code || !message || !participant || !id) {
    return new Response(JSON.stringify({ error: 'Missing required fields' }), {
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
      messages = [];
    }
  }

  // 检查是否已存在
  const exists = messages.some(m => m.id === id);
  if (exists) {
    return new Response(JSON.stringify({ status: 'exists' }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 限制数量
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

  return new Response(JSON.stringify({ status: 'sent' }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/message?code= - 获取所有消息
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code') as string;

  if (!code) {
    return new Response(JSON.stringify({ error: 'code required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const data = await WORM_HOLE.get(`msg:${code}`);

  if (!data) {
    return new Response(JSON.stringify([]), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  try {
    const messages = JSON.parse(data);
    return new Response(JSON.stringify(messages), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (e) {
    return new Response(JSON.stringify([]), {
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
