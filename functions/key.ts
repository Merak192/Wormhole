import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/key - 交换公钥
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, publicKey, participant } = await context.request.json() as { code: string; publicKey: string; participant: 1 | 2 };

  if (!code || !publicKey || !participant) {
    return new Response(JSON.stringify({ error: 'code, publicKey and participant required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `key:${code}:${participant}`;
  await WORM_HOLE.put(key, publicKey, { expirationTtl: 600 });

  return new Response(JSON.stringify({ status: 'stored' }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/key?code=1234&participant=1 - 获取指定参与者的公钥
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code') as string;
  const participant = url.searchParams.get('participant') as string;

  if (!code || !participant) {
    return new Response(JSON.stringify({ error: 'code and participant parameters required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `key:${code}:${participant}`;
  const publicKey = await WORM_HOLE.get(key);

  if (!publicKey) {
    return new Response(JSON.stringify({ error: 'key not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ publicKey }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
