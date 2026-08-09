import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/candidate - 交换 ICE 候选
export const onRequestPost: PagesFunction = async (context) => {
  const { SIGNALING_KV } = context.env as unknown as { SIGNALING_KV: KVNamespace };
  const { code, candidate } = await context.request.json() as { code: string; candidate: RTCIceCandidateInit };

  // 获取现有候选列表或创建新数组
  const existing = await SIGNALING_KV.get(`candidates:${code}`);
  const candidates: RTCIceCandidateInit[] = existing ? JSON.parse(existing) : [];
  candidates.push(candidate);

  await SIGNALING_KV.put(`candidates:${code}`, JSON.stringify(candidates), { expirationTtl: 600 });

  return new Response(JSON.stringify({ status: 'stored', count: candidates.length }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/candidate/:code - 获取 ICE 候选
export const onRequestGet: PagesFunction = async (context) => {
  const { SIGNALING_KV } = context.env as unknown as { SIGNALING_KV: KVNamespace };
  const code = context.params.code as string;

  const candidates = await SIGNALING_KV.get(`candidates:${code}`);

  if (!candidates) {
    return new Response(JSON.stringify({ candidates: [] }), {
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ candidates: JSON.parse(candidates) }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
