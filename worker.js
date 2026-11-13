// cf-egress v2: private ?url= fetch proxy with per-user tokens + opt-in KV cache.
//
// Auth: X-Proxy-Key header.
//   - Master key = PROXY_KEY Worker secret (admin: fetch + list tokens + revoke).
//   - User tokens: minted by POST /register (open, self-serve, like a mail
//     worker: pick a name, get a token, the token re-opens your list).
//     A token only sees its own cached entries; revoke it and its cache
//     goes with it. Tokens never expire; cached data does (max 1 day).
//
// Cache: default is ALWAYS FRESH fetch. Add ?cache=<seconds> to cache the
//   response in KV for that long (1..86400, clamped; 0 or absent = fresh).
//   ?cache=0 explicitly forces a fresh fetch. On upstream failure (RTO /
//   timeout) a cached copy is served instead (X-Cache: STALE) when one
//   exists, so a request can be re-fetched from KV after a timeout.
//   Only GET 2xx responses <= 10 MB, without Set-Cookie, are cached.
//   Cache is per-token (keyed by a hash of the token), never shared.
//
// Endpoints: GET /health (open), POST /register (open), GET /list (auth),
//   POST /revoke (admin), GET /?url=<target>[&cache=<s>] (auth).
// SSRF guard + 30s upstream timeout, as v1.
const BLOCKED_HOSTS = new Set(['localhost', 'metadata.google.internal', 'metadata', 'metadata.google']);
const PRIVATE_RE = /^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|\[::1\]|\[fe80:|\[fc00:|\[fd00:)/i;
const MAX_CACHE_S = 86400; // 1 day, hard cap — entries are pruned by KV after this
const MAX_CACHE_BYTES = 10 * 1024 * 1024; // KV value limit is 25 MB; stay well under

function blocked(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'scheme not allowed';
  const h = url.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(h) || h.endsWith('.local') || PRIVATE_RE.test(h)) return 'target blocked';
  return null;
}

function json(obj, status = 200, extra = {}) {
  const headers = { 'content-type': 'application/json', ...extra };
  return new Response(JSON.stringify(obj), { status, headers });
}

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function b64ToBytes(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

function parseCache(v) {
  const n = parseInt(v ?? '', 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(n, MAX_CACHE_S);
}

// Returns { kind: 'admin', tokenId: 'admin' } or { kind: 'user', tokenId, name }, else null.
async function auth(req, env) {
  const k = req.headers.get('x-proxy-key');
  if (!k) return null;
  if (env.PROXY_KEY && k === env.PROXY_KEY) return { kind: 'admin', tokenId: 'admin' };
  if (!env.KV) return null;
  const id = await sha256Hex(k);
  const rec = await env.KV.get('token:' + id, 'json');
  if (!rec) return null;
  return { kind: 'user', tokenId: id, name: rec.name };
}

function cacheKey(tokenId, urlSha) {
  return 'cache:' + tokenId.slice(0, 16) + ':' + urlSha;
}

function serveCached(entry, state) {
  const headers = new Headers();
  for (const h of ['content-type', 'content-encoding', 'content-disposition']) {
    if (entry.headers[h]) headers.set(h, entry.headers[h]);
  }
  headers.set('x-request-id', crypto.randomUUID());
  headers.set('x-cache', state);
  headers.set('x-cache-age', String(Math.max(0, Math.floor((Date.now() - entry.cachedAt) / 1000))));
  headers.set('x-cache-expires', new Date(entry.expiresAt).toISOString());
  return new Response(b64ToBytes(entry.body), { status: entry.status, headers });
}

async function handleRegister(req, env) {
  if (!env.KV) return json({ error: 'kv not configured' }, 500);
  let name = new URL(req.url).searchParams.get('name') || '';
  try {
    const body = await req.json().catch(() => null);
    if (body && typeof body.name === 'string' && body.name) name = body.name;
  } catch { /* empty body is fine */ }
  name = (name || 'user').slice(0, 64);
  const raw = new Uint8Array(24);
  crypto.getRandomValues(raw);
  const token = bytesToB64(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const id = await sha256Hex(token);
  await env.KV.put('token:' + id, JSON.stringify({ name, createdAt: Date.now() }));
  return json({ token, name, createdAt: Date.now(), note: 'keep this token — it cannot be recovered, only revoked' });
}

async function handleList(req, env) {
  const who = await auth(req, env);
  if (!who) return json({ error: 'unauthorized' }, 401);
  if (!env.KV) return json({ error: 'kv not configured' }, 500);
  if (who.kind === 'admin') {
    const keys = await env.KV.list({ prefix: 'token:' });
    const tokens = [];
    for (const k of keys.keys) {
      const rec = await env.KV.get(k.name, 'json');
      tokens.push({ id: k.name.slice(6, 22), name: rec ? rec.name : null, createdAt: rec ? rec.createdAt : null });
    }
    return json({ count: tokens.length, tokens });
  }
  const prefix = 'cache:' + who.tokenId.slice(0, 16) + ':';
  const keys = await env.KV.list({ prefix });
  const entries = keys.keys.map(k => ({
    url: k.metadata ? k.metadata.url : null,
    status: k.metadata ? k.metadata.status : null,
    cachedAt: k.metadata ? k.metadata.cachedAt : null,
    expiresAt: k.metadata ? k.metadata.expiresAt : null,
    bytes: k.metadata ? k.metadata.bytes : null,
  }));
  return json({ count: entries.length, entries });
}

async function handleRevoke(req, env) {
  const who = await auth(req, env);
  if (!who || who.kind !== 'admin') return json({ error: 'unauthorized' }, 401);
  if (!env.KV) return json({ error: 'kv not configured' }, 500);
  let token = new URL(req.url).searchParams.get('token') || '';
  try {
    const body = await req.json().catch(() => null);
    if (body && typeof body.token === 'string' && body.token) token = body.token;
  } catch { /* empty body is fine */ }
  if (!token) return json({ error: 'missing token' }, 400);
  const id = await sha256Hex(token);
  const rec = await env.KV.get('token:' + id, 'json');
  if (!rec) return json({ error: 'unknown token' }, 404);
  await env.KV.delete('token:' + id);
  const prefix = 'cache:' + id.slice(0, 16) + ':';
  const keys = await env.KV.list({ prefix });
  for (const k of keys.keys) await env.KV.delete(k.name);
  return json({ revoked: true, name: rec.name, entriesDeleted: keys.keys.length });
}

async function handleProxy(req, env) {
  const who = await auth(req, env);
  if (!who) return json({ error: 'unauthorized' }, 401);
  const u = new URL(req.url);
  const target = u.searchParams.get('url');
  if (!target) return json({ error: 'missing ?url=' }, 400);
  let t;
  try { t = new URL(target); } catch {
    return json({ error: 'invalid url' }, 400);
  }
  const why = blocked(t);
  if (why) return json({ error: why }, 403);

  const cacheS = parseCache(u.searchParams.get('cache'));
  const wantCache = req.method === 'GET' && cacheS > 0 && !!env.KV;
  let ckey = null;
  if (env.KV && req.method === 'GET') ckey = cacheKey(who.tokenId, await sha256Hex(t.toString()));

  if (wantCache) {
    const hit = await env.KV.get(ckey, 'json');
    if (hit) return serveCached(hit, 'HIT');
  }

  const fwd = new Headers(req.headers);
  fwd.delete('x-proxy-key');
  try {
    const res = await fetch(t.toString(), {
      method: req.method,
      headers: fwd,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
      redirect: 'follow',
      signal: AbortSignal.timeout(30000),
    });
    const headers = new Headers();
    for (const [k, v] of res.headers) {
      const lk = k.toLowerCase();
      if (lk === 'set-cookie' || lk === 'x-forwarded-for' || lk === 'x-real-ip' || lk.startsWith('cf-')) continue;
      headers.set(k, v);
    }
    headers.set('x-request-id', crypto.randomUUID());
    if (wantCache && res.status >= 200 && res.status < 300) {
      const buf = await res.arrayBuffer();
      if (buf.byteLength <= MAX_CACHE_BYTES && !res.headers.has('set-cookie')) {
        const now = Date.now();
        const kept = {};
        for (const h of ['content-type', 'content-encoding', 'content-disposition']) {
          if (res.headers.get(h)) kept[h] = res.headers.get(h);
        }
        await env.KV.put(ckey, JSON.stringify({
          status: res.status, headers: kept, body: bytesToB64(new Uint8Array(buf)),
          cachedAt: now, expiresAt: now + cacheS * 1000,
        }), {
          expirationTtl: cacheS,
          metadata: { url: t.toString().slice(0, 200), status: res.status, cachedAt: now, expiresAt: now + cacheS * 1000, bytes: buf.byteLength },
        });
        headers.set('x-cache', 'MISS');
        headers.set('x-cache-expires', new Date(now + cacheS * 1000).toISOString());
        return new Response(buf, { status: res.status, headers });
      }
      headers.set('x-cache', 'BYPASS');
      return new Response(buf, { status: res.status, headers });
    }
    headers.set('x-cache', wantCache ? 'BYPASS' : 'OFF');
    return new Response(res.body, { status: res.status, headers });
  } catch (e) {
    // RTO / network failure: serve the cached copy when one exists.
    if (ckey) {
      const stale = await env.KV.get(ckey, 'json');
      if (stale) return serveCached(stale, 'STALE');
    }
    return json({ error: 'upstream fetch failed', detail: String(e).slice(0, 120) }, 502);
  }
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (u.pathname === '/health') {
      return json({ ok: true });
    }
    if (u.pathname === '/register' && req.method === 'POST') {
      return handleRegister(req, env);
    }
    if (u.pathname === '/list' && req.method === 'GET') {
      return handleList(req, env);
    }
    if (u.pathname === '/revoke' && req.method === 'POST') {
      return handleRevoke(req, env);
    }
    if (u.pathname === '/' && u.searchParams.has('url')) {
      return handleProxy(req, env);
    }
    return json({ error: 'not found' }, 404);
  },
};
