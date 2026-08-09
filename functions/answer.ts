import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/answer - 创建 answer
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, sdp } = await context.request.json() as { code: string; sdp: RTCSessionDescriptionInit };

  const key = `answer:${code}`;
  const existing = await WORM_HOLE.get(key);

  if (existing) {
    return new Response(JSON.stringify({ error: 'answer exists' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  await WORM_HOLE.put(key, JSON.stringify(sdp), { expirationTtl: 600 });

  return new Response(JSON.stringify({ status: 'created' }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/answer/:code - 获取 answer
export const onRequestGet: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const code = context.params.code as string;

  const sdp = await WORM_HOLE.get(`answer:${code}`);

  if (!sdp) {
    return new Response(JSON.stringify({ error: 'answer not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ sdp: JSON.parse(sdp) }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
