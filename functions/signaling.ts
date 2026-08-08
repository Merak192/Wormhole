// ── Pages Function：信令服务器（HTTP 长轮询）─────────────────────────────────
// 握手协议：
//   1. 双方 POST join（携带 SDP offer）
//   2. 先到的为 host，后到的为 guest
//   3. guest 直接拿到 host 的 offer，发 answer
//   4. host 通过 long poll 拿到 guest 的 answer
//   5. ICE 候选通过 POST ice 中转
//   服务器仅中转 SDP/ICE，不碰聊天内容。

interface PendingClient {
  sdp?: RTCSessionDescriptionInit;
  iceCandidates: RTCIceCandidateInit[];
  role: 'host' | 'guest';
  timestamp: number;
}

const ROOMS = new Map<string, { host?: PendingClient; guest?: PendingClient }>();
const ROOM_TTL = 300_000; // 5 分钟过期

export async function onRequest(context: { request: Request }): Promise<Response> {
  const { request } = context;
  const url = new URL(request.url);
  const room = url.searchParams.get('room');
  const action = url.searchParams.get('action');
  const method = request.method;

  if (!room) return json({ error: '缺少 room 参数' }, 400);
  pruneStale();

  if (method === 'POST') return await handlePost(room, request);
  if (method === 'GET' && action === 'poll') return await handlePoll(room, url);
  if (method === 'GET') return json({ ok: true });
  return json({ error: 'Method not allowed' }, 405);
}

async function handlePost(room: string, request: Request): Promise<Response> {
  let body: { type?: string; sdp?: RTCSessionDescriptionInit; iceCandidates?: RTCIceCandidateInit[]; role?: string; candidate?: RTCIceCandidateInit };
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  if (!ROOMS.has(room)) ROOMS.set(room, {});
  const r = ROOMS.get(room)!;

  switch (body.type) {
    case 'join': {
      if (r.host) {
        // 已有 host，当前为 guest
        r.guest = { sdp: body.sdp, iceCandidates: body.iceCandidates || [], role: 'guest', timestamp: Date.now() };
        // 立即把 host 的信息返回给 guest
        return json({
          role: 'guest',
          peerSdp: r.host.sdp,
          peerIce: r.host.iceCandidates,
        });
      }
      r.host = { sdp: body.sdp, iceCandidates: body.iceCandidates || [], role: 'host', timestamp: Date.now() };
      // host 先等，返回 waiting
      return json({ role: 'host', waiting: true });
    }

    case 'answer': {
      if (body.role === 'host') {
        r.host = { ...r.host!, sdp: body.sdp, iceCandidates: body.iceCandidates || [], timestamp: Date.now() };
        // guest 在 long poll 等待，立即返回
        if (r.guest) {
          const d = r.guest;
          r.guest = undefined;
          return json({ type: 'ready', sdp: d.sdp, iceCandidates: d.iceCandidates });
        }
      } else {
        r.guest = { ...r.guest!, sdp: body.sdp, iceCandidates: body.iceCandidates || [], timestamp: Date.now() };
        // host 在 long poll 等待，立即返回
        if (r.host) {
          const d = r.host;
          r.host = undefined;
          return json({ type: 'ready', sdp: d.sdp, iceCandidates: d.iceCandidates });
        }
      }
      return json({ queued: true });
    }

    case 'ice': {
      const senderRole = body.role as 'host' | 'guest';
      const targetRole = senderRole === 'host' ? 'guest' : 'host';
      const target = targetRole === 'host' ? r.host : r.guest;
      if (target) {
        // 对方在线，立即返回
        if (targetRole === 'host') r.host = undefined; else r.guest = undefined;
        return json({ type: 'ice', role: targetRole, candidate: body.candidate });
      }
      // 暂存
      if (senderRole === 'host') {
        r.host = { ...r.host!, iceCandidates: [...(r.host!.iceCandidates || []), body.candidate], timestamp: Date.now() };
      } else {
        r.guest = { ...r.guest!, iceCandidates: [...(r.guest!.iceCandidates || []), body.candidate], timestamp: Date.now() };
      }
      return json({ queued: true });
    }

    default:
      return json({ error: `Unknown type: ${body.type}` }, 400);
  }
}

async function handlePoll(room: string, url: URL): Promise<Response> {
  const timeout = Math.min(parseInt(url.searchParams.get('timeout') || '55000', 10), 60_000);
  const role = url.searchParams.get('role') as 'host' | 'guest';
  const r = ROOMS.get(room);
  if (!r) return json({ error: 'Room not found' }, 404);

  // host 等 guest，guest 等 host
  const targetKey = role === 'host' ? 'guest' : 'host';
  const target = r[targetKey as 'host' | 'guest'];

  if (target && target.sdp) {
    r[targetKey as 'host' | 'guest'] = undefined;
    return json({ type: 'ready', sdp: target.sdp, iceCandidates: target.iceCandidates });
  }

  const started = Date.now();
  while (Date.now() - started < timeout) {
    await sleep(1000);
    const fresh = r[targetKey as 'host' | 'guest'];
    if (fresh && fresh.sdp) {
      r[targetKey as 'host' | 'guest'] = undefined;
      return json({ type: 'ready', sdp: fresh.sdp, iceCandidates: fresh.iceCandidates });
    }
  }
  return json({ error: 'timeout' }, 408);
}

function pruneStale(): void {
  const now = Date.now();
  for (const [room, data] of ROOMS) {
    if (data.host && now - data.host.timestamp > ROOM_TTL) data.host = undefined;
    if (data.guest && now - data.guest.timestamp > ROOM_TTL) data.guest = undefined;
    if (!data.host && !data.guest) ROOMS.delete(room);
  }
}

function sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
    status,
  });
}
