import type { PagesFunction } from '@cloudflare/workers-types';

// GET /functions/state?code=1234 - 查询会话状态
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const url = new URL(context.request.url);
  const code = url.searchParams.get('code') as string;

  if (!code) {
    return new Response(JSON.stringify({ error: 'code parameter required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const hasOffer = await WORM_HOLE.get(`offer:${code}`);
  const hasAnswer = await WORM_HOLE.get(`answer:${code}`);
  const hasKey1 = await WORM_HOLE.get(`key:${code}:1`);
  const hasKey2 = await WORM_HOLE.get(`key:${code}:2`);
  const bothKeys = hasKey1 && hasKey2;

  let status = 'waiting';
  if (hasOffer && hasAnswer) {
    status = 'ready';
  }
  if (bothKeys) {
    status = 'connected';
  }

  return new Response(JSON.stringify({
    status,
    hasOffer: !!hasOffer,
    hasAnswer: !!hasAnswer,
    hasKey1: !!hasKey1,
    hasKey2: !!hasKey2,
    bothKeys: !!bothKeys,
  }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
