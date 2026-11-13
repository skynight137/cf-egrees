// cf-egress: private ?url= fetch proxy.
// Auth: X-Proxy-Key header must equal the PROXY_KEY Worker secret.
// SSRF guard: http(s) only; blocks loopback, private ranges, link-local,
// .local and cloud metadata hosts. 30s upstream timeout.
const BLOCKED_HOSTS = new Set(['localhost', 'metadata.google.internal', 'metadata', 'metadata.google']);
const PRIVATE_RE = /^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|\[::1\]|\[fe80:|\[fc00:|\[fd00:)/i;

function blocked(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'scheme not allowed';
  const h = url.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(h) || h.endsWith('.local') || PRIVATE_RE.test(h)) return 'target blocked';
  return null;
}

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    if (u.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true }), { headers: { 'content-type': 'application/json' } });
    }
    if (!env.PROXY_KEY || req.headers.get('x-proxy-key') !== env.PROXY_KEY) {
      return new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401, headers: { 'content-type': 'application/json' } });
    }
    const target = u.searchParams.get('url');
    if (!target) {
      return new Response(JSON.stringify({ error: 'missing ?url=' }), { status: 400, headers: { 'content-type': 'application/json' } });
    }
    let t;
    try { t = new URL(target); } catch {
      return new Response(JSON.stringify({ error: 'invalid url' }), { status: 400, headers: { 'content-type': 'application/json' } });
    }
    const why = blocked(t);
    if (why) {
      return new Response(JSON.stringify({ error: why }), { status: 403, headers: { 'content-type': 'application/json' } });
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
      return new Response(res.body, { status: res.status, headers });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'upstream fetch failed', detail: String(e).slice(0, 120) }), { status: 502, headers: { 'content-type': 'application/json' } });
    }
  },
};
