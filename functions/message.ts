import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/message - 发送消息
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, message } = await context.request.json() as { code: string; message: string };

  if (!code || !message) {
    return new Response(JSON.stringify({ error: 'code and message required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `msg:${code}`;
  const existing = await WORM_HOLE.get(key);
  const messages: Array<{ id: string; timestamp: number; sender: string; message: string }> = existing ? JSON.parse(existing) : [];

  // 限制消息数量（保留最近100条）
  if (messages.length >= 100) {
    messages.shift();
  }

  messages.push({
    id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    timestamp: Date.now(),
    sender: 'remote',
    message,
  });

  await WORM_HOLE.put(key, JSON.stringify(messages), { expirationTtl: 600 });

  return new Response(JSON.stringify({ status: 'sent' }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/message?code=&since= - 获取消息
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code') as string;
  const since = url.searchParams.get('since');

  if (!code) {
    return new Response(JSON.stringify({ error: 'code parameter required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `msg:${code}`;
  const data = await WORM_HOLE.get(key);

  if (!data) {
    return new Response(JSON.stringify({ messages: [] }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let messages = JSON.parse(data) as Array<{ id: string; timestamp: number; sender: string; message: string }>;

  if (since) {
    messages = messages.filter(m => m.id !== since);
  }

  return new Response(JSON.stringify(messages), {
    headers: { 'Content-Type': 'application/json' },
  });
};
