import type { PagesFunction } from '@cloudflare/workers-types';

// GET /functions/state/:code - 查询会话状态
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const code = context.params.code as string;

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
