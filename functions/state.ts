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
  const candidatesData = await WORM_HOLE.get(`candidates:${code}`);
  const candidates = candidatesData ? JSON.parse(candidatesData) as RTCIceCandidateInit[] : [];

  let status = 'waiting';
  if (hasOffer && hasAnswer) {
    status = 'ready';
  }
  if (candidates.length >= 2) {
    status = 'connected';
  }

  return new Response(JSON.stringify({ status, hasOffer: !!hasOffer, hasAnswer: !!hasAnswer }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
