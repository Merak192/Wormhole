import type { PagesFunction } from '@cloudflare/workers-types';

// POST /functions/offer - 创建 offer
export const onRequestPost: PagesFunction = async (context) => {
  const { WORM_HOLE } = context.env as unknown as { WORM_HOLE: KVNamespace };
  const { code, sdp } = await context.request.json() as { code: string; sdp: RTCSessionDescriptionInit };

  if (!code || !sdp) {
    return new Response(JSON.stringify({ error: 'code and sdp required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const key = `offer:${code}`;
  const existing = await WORM_HOLE.get(key);

  if (existing) {
    return new Response(JSON.stringify({ error: 'offer exists, use code already in use' }), {
      status: 409,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  await WORM_HOLE.put(key, JSON.stringify(sdp), { expirationTtl: 600 });

  return new Response(JSON.stringify({ status: 'created' }), {
    headers: { 'Content-Type': 'application/json' },
  });
};

// GET /functions/offer?code=1234 - 获取 offer
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

  const sdp = await WORM_HOLE.get(`offer:${code}`);

  if (!sdp) {
    return new Response(JSON.stringify({ error: 'offer not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ sdp: JSON.parse(sdp) }), {
    headers: { 'Content-Type': 'application/json' },
  });
};
