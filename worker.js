// cf-egress v3: private ?url= fetch proxy with JWT tokens + Cache API cache.
//
// Auth: X-Proxy-Key header.
//   - Master key = PROXY_KEY Worker secret (admin: fetch + list + revoke).
//   - User tokens: JWTs minted by POST /register (open, self-serve).
//     JWT payload {sub: tokenId, name, iat, exp} (exp = 1 year), signed
//     HMAC-SHA256 with a key derived from PROXY_KEY (WebCrypto, no deps).
//     A token only sees its own cache. Revocation: POST /revoke writes
//     the tokenId to a KV denylist (revoked:<tokenId>), checked on auth.
//     KV is eventually consistent (~60s), so a revoked token may work for
//     up to ~60s — acceptable for this proxy's threat model (see
//     docs/decisions.md). Legacy tokens (pre-JWT, stored in KV as
//     token:<sha256>) still work as a fallback until revoked/re-registered.
//   - Cached data expires per ?cache=.
//
// Cache: default is ALWAYS FRESH fetch. Add ?cache=<seconds> to cache the
//   response in the Workers Cache API (caches.default) for that long
//   (1..86400, clamped; 0 or absent = fresh). ?cache=0 forces fresh.
//   Only GET 2xx responses <= 50 MB, without Set-Cookie, are cached.
//   Cache is per-token (keyed by token hash), never shared.
//   On upstream failure (RTO/timeout) a cached copy is served instead
//   (X-Cache: STALE) when one exists. A lightweight KV metadata index
//   (cachemeta:<tokenId16>:<urlSha>) keeps /list working (the Cache API
//   cannot enumerate entries). Old v2 KV cache bodies (cache:<...>) are
//   orphaned and expire on their own; they are never read by v3.
//
// Endpoints: GET /health (open), POST /register (open), GET /list (auth),
//   POST /revoke (admin), GET /?url=<target>[&cache=<s>] (auth).
// SSRF guard + 30s upstream timeout, as v1/v2.
const BLOCKED_HOSTS = new Set(['localhost', 'metadata.google.internal', 'metadata', 'metadata.google']);
const PRIVATE_RE = /^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|\[::1\]|\[fe80:|\[fc00:|\[fd00:)/i;
const MAX_CACHE_S = 86400; // 1 day, hard cap — entries are pruned by KV after this
const MAX_CACHE_BYTES = 50 * 1024 * 1024; // Cache API policy cap (platform limit is much higher); >this returns BYPASS
const CACHE_API_MAX_AGE = 86400; // retained in Cache API up to 1 day; our own expiresAt metadata controls freshness
const JWT_EXP_S = 365 * 24 * 3600; // 1 year
const CACHE_KEY_HOST = 'https://cf-egress-cache.local'; // synthetic host: Cache API key namespace (never fetched)

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

// base64url (no padding) for JWT
function b64urlEncode(u8) {
  return bytesToB64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64ToBytes(s);
}
function b64urlEncodeStr(s) {
  return b64urlEncode(new TextEncoder().encode(s));
}
function b64urlDecodeStr(s) {
  return new TextDecoder().decode(b64urlDecode(s));
}

function parseCache(v) {
  const n = parseInt(v ?? '', 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(n, MAX_CACHE_S);
}

// --- JWT (HMAC-SHA256, WebCrypto, no deps) ---
// Signing key is derived from PROXY_KEY so no second secret is needed.
// Domain-separated so the JWT key is distinct from the admin key.
function jwtKeyBytes(env) {
  return new TextEncoder().encode('cf-egress-jwt-v1:' + (env.PROXY_KEY || ''));
}

async function hmacSign(keyBytes, dataStr) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(dataStr));
  return b64urlEncode(new Uint8Array(sig));
}

async function hmacVerify(keyBytes, dataStr, sigB64) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  let sig;
  try { sig = b64urlDecode(sigB64); } catch { return false; }
  try { return await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(dataStr)); }
  catch { return false; }
}

async function mintJwt(env, tokenId, name) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { sub: tokenId, name, iat: now, exp: now + JWT_EXP_S };
  const enc = b64urlEncodeStr(JSON.stringify(header)) + '.' + b64urlEncodeStr(JSON.stringify(payload));
  const sig = await hmacSign(jwtKeyBytes(env), enc);
  return { token: enc + '.' + sig, payload };
}

async function verifyJwt(env, token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;
  if (!h || !p || !s) return null;
  const ok = await hmacVerify(jwtKeyBytes(env), h + '.' + p, s);
  if (!ok) return null;
  let payload;
  try { payload = JSON.parse(b64urlDecodeStr(p)); } catch { return null; }
  if (!payload || typeof payload.sub !== 'string' || !payload.sub) return null;
  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

// Returns { kind: 'admin', tokenId: 'admin' } or { kind: 'user', tokenId, name, via }, else null.
// via is 'jwt' or 'legacy' (KV token record, pre-JWT fallback).
async function auth(req, env) {
  const k = req.headers.get('x-proxy-key');
  if (!k) return null;
  if (env.PROXY_KEY && k === env.PROXY_KEY) return { kind: 'admin', tokenId: 'admin', via: 'admin' };
  // JWT path (stateless; no KV read except the revocation denylist).
  const payload = await verifyJwt(env, k);
  if (payload) {
    if (env.KV) {
      const revoked = await env.KV.get('revoked:' + payload.sub);
      if (revoked) return null;
    }
    return { kind: 'user', tokenId: payload.sub, name: payload.name || null, via: 'jwt' };
  }
  // Legacy fallback: pre-JWT tokens stored in KV as token:<sha256(token)>.
  if (env.KV) {
    const id = await sha256Hex(k);
    const rec = await env.KV.get('token:' + id, 'json');
    if (rec) return { kind: 'user', tokenId: id, name: rec.name || null, via: 'legacy' };
  }
  return null;
}

// --- Cache API (response bodies) + KV metadata index (for /list) ---
function cacheRequest(tokenId, urlSha) {
  return new Request(CACHE_KEY_HOST + '/' + tokenId.slice(0, 16) + '/' + urlSha);
}
function metaKey(tokenId, urlSha) {
  return 'cachemeta:' + tokenId.slice(0, 16) + ':' + urlSha;
}

// Read the freshness metadata we stored on a cached response.
// Returns { cachedAt, expiresAt } (epoch ms) or null if absent/unparseable.
function readCacheMeta(cachedRes) {
  const ca = cachedRes.headers.get('x-cf-egress-cached-at');
  const ex = cachedRes.headers.get('x-cf-egress-expires-at');
  if (!ca || !ex) return null;
  const cachedAt = parseInt(ca, 10);
  const expiresAt = parseInt(ex, 10);
  if (!Number.isFinite(cachedAt) || !Number.isFinite(expiresAt)) return null;
  return { cachedAt, expiresAt };
}

// Serve a cached response body, stripping our internal metadata headers.
function serveCached(cachedRes, state, meta) {
  const headers = new Headers();
  for (const h of ['content-type', 'content-encoding', 'content-disposition']) {
    if (cachedRes.headers.get(h)) headers.set(h, cachedRes.headers.get(h));
  }
  headers.set('x-request-id', crypto.randomUUID());
  headers.set('x-cache', state);
  if (meta) {
    headers.set('x-cache-age', String(Math.max(0, Math.floor((Date.now() - meta.cachedAt) / 1000))));
    headers.set('x-cache-expires', new Date(meta.expiresAt).toISOString());
  }
  return new Response(cachedRes.body, { status: cachedRes.status, headers });
}

async function handleRegister(req, env) {
  let name = new URL(req.url).searchParams.get('name') || '';
  try {
    const body = await req.json().catch(() => null);
    if (body && typeof body.name === 'string' && body.name) name = body.name;
  } catch { /* empty body is fine */ }
  name = (name || 'user').slice(0, 64);
  const tokenId = crypto.randomUUID();
  const { token, payload } = await mintJwt(env, tokenId, name);
  // Stateless: no KV write. (Legacy path kept only as an auth fallback.)
  return json({ token, name, createdAt: Date.now(), expiresAt: payload.exp * 1000, note: 'keep this token — it cannot be recovered, only revoked' });
}

async function handleList(req, env) {
  const who = await auth(req, env);
  if (!who) return json({ error: 'unauthorized' }, 401);
  if (!env.KV) return json({ error: 'kv not configured' }, 500);
  const cursor = new URL(req.url).searchParams.get('cursor') || undefined;
  if (who.kind === 'admin') {
    // JWTs are stateless, so there is no token registry to list.
    // Admin sees the revocation denylist + cache-entry counts.
    const revoked = await env.KV.list({ prefix: 'revoked:', cursor });
    const tokens = [];
    for (const k of revoked.keys) {
      const rec = await env.KV.get(k.name, 'json');
      tokens.push({ id: k.name.slice(8, 24), name: rec ? rec.name : null, revokedAt: rec ? rec.revokedAt : null });
    }
    const metas = await env.KV.list({ prefix: 'cachemeta:' });
    return json({ revokedCount: tokens.length, revoked: tokens, cacheEntries: metas.keys.length, list_complete: revoked.list_complete, cursor: revoked.cursor || null, note: 'tokens are stateless JWTs; only revoked tokens are listed' });
  }
  const prefix = 'cachemeta:' + who.tokenId.slice(0, 16) + ':';
  const keys = await env.KV.list({ prefix, cursor });
  const entries = keys.keys.map(k => ({
    url: k.metadata ? k.metadata.url : null,
    status: k.metadata ? k.metadata.status : null,
    cachedAt: k.metadata ? k.metadata.cachedAt : null,
    expiresAt: k.metadata ? k.metadata.expiresAt : null,
    bytes: k.metadata ? k.metadata.bytes : null,
  }));
  return json({ count: entries.length, entries, list_complete: keys.list_complete, cursor: keys.cursor || null });
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

  // JWT token: denylist its sub, delete its cache entries.
  const payload = await verifyJwt(env, token);
  if (payload) {
    const ttl = Math.max(1, (payload.exp || 0) - Math.floor(Date.now() / 1000));
    // Denylist entry lives until the token would have expired (KV needs >= 60s).
    await env.KV.put('revoked:' + payload.sub, JSON.stringify({ name: payload.name || null, revokedAt: Date.now() }), { expirationTtl: Math.max(60, ttl) });
    // Delete its cached bodies (via the KV metadata index) + the index.
    const prefix = 'cachemeta:' + payload.sub.slice(0, 16) + ':';
    const keys = await env.KV.list({ prefix });
    let deleted = 0;
    const cache = caches.default;
    for (const k of keys.keys) {
      const urlSha = k.name.slice(prefix.length);
      try { await cache.delete(cacheRequest(payload.sub, urlSha)); } catch { /* best effort */ }
      await env.KV.delete(k.name);
      deleted++;
    }
    return json({ revoked: true, via: 'jwt', name: payload.name || null, entriesDeleted: deleted, note: 'denylist propagates via KV (~60s); token may work until then' });
  }

  // Legacy token: delete its KV record + cache entries (old KV bodies + new Cache API bodies).
  const id = await sha256Hex(token);
  const rec = await env.KV.get('token:' + id, 'json');
  if (!rec) return json({ error: 'unknown token' }, 404);
  await env.KV.delete('token:' + id);
  let deleted = 0;
  const prefix = 'cachemeta:' + id.slice(0, 16) + ':';
  const keys = await env.KV.list({ prefix });
  const cache = caches.default;
  for (const k of keys.keys) {
    const urlSha = k.name.slice(prefix.length);
    try { await cache.delete(cacheRequest(id, urlSha)); } catch { /* best effort */ }
    await env.KV.delete(k.name);
    deleted++;
  }
  // Also sweep any v2 KV cache bodies for this token.
  const oldKeys = await env.KV.list({ prefix: 'cache:' + id.slice(0, 16) + ':' });
  for (const k of oldKeys.keys) { await env.KV.delete(k.name); deleted++; }
  return json({ revoked: true, via: 'legacy', name: rec.name, entriesDeleted: deleted });
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
  const wantCache = req.method === 'GET' && cacheS > 0;
  const urlSha = await sha256Hex(t.toString());
  const cReq = cacheRequest(who.tokenId, urlSha);
  const cache = caches.default;

  // Freshness check against the Cache API copy (if any).
  let staleRes = null;
  let staleMeta = null;
  if (wantCache) {
    const hit = await cache.match(cReq);
    if (hit) {
      const meta = readCacheMeta(hit);
      if (meta && Date.now() < meta.expiresAt) return serveCached(hit, 'HIT', meta);
      // Stale copy: keep it in hand — it becomes STALE if the fresh fetch fails.
      staleRes = hit;
      staleMeta = meta;
    }
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
        // Store the body in the Cache API (edge-local). Our own
        // expiresAt metadata controls freshness; Cache-Control max-age
        // only governs retention (up to 1 day) so a stale copy survives
        // long enough to be served as STALE on a later failure.
        const storeHeaders = new Headers();
        for (const h of ['content-type', 'content-encoding', 'content-disposition']) {
          if (kept[h]) storeHeaders.set(h, kept[h]);
        }
        storeHeaders.set('cache-control', 'max-age=' + CACHE_API_MAX_AGE);
        storeHeaders.set('x-cf-egress-cached-at', String(now));
        storeHeaders.set('x-cf-egress-expires-at', String(now + cacheS * 1000));
        try {
          await cache.put(cReq, new Response(buf, { status: res.status, headers: storeHeaders }));
        } catch { /* cache put is best-effort; the live response still goes out */ }
        // KV metadata index (for /list only — the Cache API cannot enumerate).
        if (env.KV) {
          try {
            await env.KV.put(metaKey(who.tokenId, urlSha), JSON.stringify({ v: 1 }), {
              expirationTtl: cacheS,
              metadata: { url: t.toString().slice(0, 200), status: res.status, cachedAt: now, expiresAt: now + cacheS * 1000, bytes: buf.byteLength },
            });
          } catch { /* index is best-effort */ }
        }
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
    if (staleRes) return serveCached(staleRes, 'STALE', staleMeta);
    // No Cache API copy: fall back to a v2 KV body if one still exists
    // (migration window only — v3 never writes KV bodies).
    if (env.KV) {
      const old = await env.KV.get('cache:' + who.tokenId.slice(0, 16) + ':' + urlSha, 'json');
      if (old) {
        const headers = new Headers();
        for (const h of ['content-type', 'content-encoding', 'content-disposition']) {
          if (old.headers[h]) headers.set(h, old.headers[h]);
        }
        headers.set('x-request-id', crypto.randomUUID());
        headers.set('x-cache', 'STALE');
        headers.set('x-cache-age', String(Math.max(0, Math.floor((Date.now() - old.cachedAt) / 1000))));
        headers.set('x-cache-expires', new Date(old.expiresAt).toISOString());
        return new Response(b64ToBytes(old.body), { status: old.status, headers });
      }
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
