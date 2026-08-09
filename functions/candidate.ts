import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/candidate - 交换 ICE 候选
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, candidate } = await context.request.json() as { code: string; candidate: RTCIceCandidateInit };

  if (!code || !candidate) {
    return new Response(JSON.stringify({ error: 'code and candidate required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // 获取现有候选列表或创建新数组
  const existing = await WORM_HOLE.get(`candidates:${code}`);
  const candidates: RTCIceCandidateInit[] = existing ? JSON.parse(existing) : [];
  candidates.push(candidate);

  await WORM_HOLE.put(`candidates:${code}`, JSON.stringify(candidates), { expirationTtl: 600 });

  return new Response(JSON.stringify({ status: 'stored', count: candidates.length }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/candidate?code=1234 - 获取 ICE 候选
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

  const candidates = await WORM_HOLE.get(`candidates:${code}`);

  if (!candidates) {
    return new Response(JSON.stringify({ candidates: [] }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ candidates: JSON.parse(candidates) }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
