// ── Pages Function：信令服务器（长轮询）───────────────────────────────────────
// 仅中转 SDP/ICE 元数据，不存储也不解密任何聊天内容。
// 使用 Memory 存储活跃信令队列（生产环境可换 Durable Objects / KV）。

interface Pending {
  sdp?: RTCSessionDescriptionInit;
  candidate?: RTCIceCandidateInit;
  timestamp: number;
}

// room → { host: Pending | undefined, guest: Pending | undefined }
const rooms = new Map<string, { host?: Pending; guest?: Pending }>();

const SIGNAL_TTL = 120_000; // 2 分钟过期
const POLL_TIMEOUT = 55_000; // 长轮询最长等待

export async function onRequest(context): Promise<Response> {
  const { request } = context;
  const url = new URL(request.url);
  const room = url.searchParams.get('room');
  const method = request.method;

  if (!room) return json({ error: '缺少 room 参数' }, 400);

  pruneStale();

  if (method === 'POST') return await postSignal(url, room, request);
  if (method === 'GET') return await longPoll(room, url);
  return json({ error: 'Method not allowed' }, 405);
}

// ── POST：接收信号，匹配对方并返回，否则暂存 ──────────────────────────────────

async function postSignal(_url: URL, room: string, request: Request): Promise<Response> {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }

  if (!rooms.has(room)) rooms.set(room, {});
  const r = rooms.get(room)!;

  switch (body.type) {
    case 'offer': {
      // 访客发送 offer → 存 guest，若 host 在等待则立即返回
      r.guest = { sdp: body.sdp, timestamp: Date.now() };
      if (r.host) { const d = r.host; r.host = undefined; return json(d); }
      return json({ queued: true });
    }
    case 'answer': {
      // 主机发送 answer → 存 host，若 guest 在等待则立即返回
      r.host = { sdp: body.sdp, timestamp: Date.now() };
      if (r.guest) { const d = r.guest; r.guest = undefined; return json(d); }
      return json({ queued: true });
    }
    case 'ice': {
      // ICE 候选：双向立即投递或暂存
      const target = body.from === 'host' ? 'guest' : 'host';
      const other = target === 'guest' ? r.guest : r.host;
      if (other) {
        if (target === 'guest') r.guest = undefined; else r.host = undefined;
        return json({ candidate: body.candidate });
      }
      if (target === 'guest') r.guest = { candidate: body.candidate, timestamp: Date.now() };
      else r.host = { candidate: body.candidate, timestamp: Date.now() };
      return json({ queued: true });
    }
    default:
      return json({ error: `Unknown type: ${body.type}` }, 400);
  }
}

// ── GET：长轮询，等待对方信号或超时 ───────────────────────────────────────────

async function longPoll(room: string, url: URL): Promise<Response> {
  const timeout = Math.min(parseInt(url.searchParams.get('timeout') || '55000', 10), 60_000);
  const r = rooms.get(room);
  if (!r) return json({ error: 'Room not found' }, 404);

  // 有现成数据立即返回
  if (r.host) { const d = r.host; r.host = undefined; return json(d); }
  if (r.guest) { const d = r.guest; r.guest = undefined; return json(d); }

  // 轮询等待
  const started = Date.now();
  while (Date.now() - started < timeout) {
    await sleep(1000);
    if (r.host) { const d = r.host; r.host = undefined; return json(d); }
    if (r.guest) { const d = r.guest; r.guest = undefined; return json(d); }
  }
  return json({ error: 'timeout' }, 408);
}

// ── 清理过期房间 ─────────────────────────────────────────────────────────────

function pruneStale(): void {
  const now = Date.now();
  for (const [room, data] of rooms) {
    if ((!data.host || now - data.host.timestamp > SIGNAL_TTL) &&
        (!data.guest || now - data.guest.timestamp > SIGNAL_TTL) &&
        !data.host && !data.guest) {
      rooms.delete(room);
    }
  }
}

function sleep(ms: number): Promise<void> { return new Promise(r => setTimeout(r, ms)); }

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    headers: { 'Content-Type': 'application/json' },
    status,
  });
}
