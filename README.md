# cf-egress — private `?url=` fetch proxy (Cloudflare Worker)

## 1. Explain

One domain fronts all shell HTTP egress. A client asks the Worker for a
target URL; the Worker fetches it server-side and streams the response
back. Default is a fresh fetch every time; `?cache=` opts into caching.

Live URL: `https://<your-domain>` (the Worker `https://<your-worker>.workers.dev`
also works). Replace both placeholders with your own domain / Worker name.

Two deployments share one codebase (`worker.js`), one KV namespace, and
one master key (`PROXY_KEY`) — so one token works on both, the cache is
shared, and a revocation applies to both. Only the CORS behaviour differs:

| Variant | Config | CORS | Use for |
|---|---|---|---|
| `cf-egress` | `wrangler.toml` (`CORS_ENABLED=false`) | none | server-side: shell, curl, tools, Muse |
| `cf-egress-cors` | `wrangler-cors.toml` (`CORS_ENABLED=true`) | OPTIONS preflight (204) + `Access-Control-Allow-Origin` (Origin echoed, `Vary: Origin`) | browser apps |

They are separate on purpose: a browser needs preflight + CORS headers,
a server-side client must never get them. Auth is the `X-Proxy-Key`
header in **both** variants — never a query param (a key in the URL shows
up in history, logs, and Referer).

## 2. How it Works

Endpoints (`worker.js`):

| Endpoint | Auth | What it does |
|---|---|---|
| `GET /health` | none | liveness check |
| `POST /register?name=<name>` | none (open, self-serve) | mints a per-user JWT token |
| `GET /?url=<target>[&cache=<seconds>]` | token or master key | fetches the target, streams it back |
| `GET /list[?cursor=]` | token or master key | lists your cached entries (cursor pagination) |
| `POST /revoke` | master key only | revokes a token (body `{"token":"<jwt>"}`) |

Auth — per-user JWT tokens, not one shared key. Tokens are stateless
JWTs (`{sub, name, iat, exp}`, exp = 1 year), signed HMAC-SHA256 with a
key derived from `PROXY_KEY` (WebCrypto, no dependencies). No token
record is stored — register is stateless. Each token only sees its own
cached entries. Revocation writes the token id to a KV denylist, checked
on every request; KV is eventually consistent (~60s), so a revoked token
may work for up to ~60s. The master key is admin: it fetches, lists
revoked tokens, and revokes. See `docs/decisions.md` for the full
reasoning (including why Durable Objects and R2 were NOT used).

Cache — fresh by default, opt-in per request. Add `?cache=<seconds>` to
cache the response in the Workers Cache API (`caches.default`,
edge-local) for that long. `?cache=0` (or omitting it) forces fresh.

- `?cache=` is clamped to **1..86400** (max 1 day, hard cap). Invalid
  values behave as fresh.
- Only `GET` 2xx responses `<= 50 MB` without `Set-Cookie` are cached.
- `X-Cache` tells what happened: `HIT`, `MISS`, `OFF` (fresh, no cache
  requested), `BYPASS` (not cacheable), `STALE` (see below).
- Cache is per-token (keyed by a hash of the token), never shared
  between tokens. A lightweight KV metadata index keeps `/list` working
  (the Cache API cannot enumerate entries).
- **RTO fallback:** if the upstream fetch fails (timeout / network
  error) and a cached copy exists for that token+URL, the cached copy
  is served (`X-Cache: STALE`) instead of a 502. Proven live 2026-11-14
  (see `docs/stale-proof.md`).

Other behaviour: SSRF guard (http(s) only; localhost, loopback, private
ranges, link-local, `.local`, cloud metadata hosts blocked, 403), 30s
upstream timeout, `X-Request-ID` on every response, `Set-Cookie` and
forwarding headers stripped. CORS headers are added per-request **after**
cache retrieval, so an echoed Origin is never baked into a cached entry.
The preflight handler answers OPTIONS with
`Access-Control-Allow-Headers: x-proxy-key, content-type, authorization,
accept, accept-language` (fixed list, not an echo) and
`Access-Control-Max-Age: 86400`.

Limits: some hosts block Cloudflare Workers IPs (HTTP 403/419, or a
timeout) while a direct fetch passes. HTTPS-via-SOCKS5 is not possible
from a Worker, so the fix for CF-IP-blocked HTTPS destinations is a
relay, not a SOCKS5 header — not yet wired in. Shell `curl` through a
platform proxy never triggers approval cards for any host; approvals are
per-tool/binary (`node fetch` to a fresh host raised one; curl/python/wget
did not). Reference docs: `docs/corsproxy-io-how-it-works.md`,
`docs/decisions.md`, `docs/stale-proof.md`.

## 3. What's to Prepare

- A Cloudflare account with Workers enabled, and a Workers subdomain
  (`<your-worker>.workers.dev`).
- Node.js + `npx wrangler` (wrangler is the only deploy tool; no build
  step, `worker.js` deploys as-is).
- A KV namespace: `wrangler kv namespace create KV` — put the id in
  `wrangler.toml` (and `wrangler-cors.toml`; both share the same one).
- A master key (`PROXY_KEY`): a long random secret, stored only as a
  Worker secret (`wrangler secret put PROXY_KEY`) and in your own
  secrets store. Never commit it (`.gitignore` covers `.proxy-key`,
  `.dev.vars`, `.wrangler/`); never leave it in `/tmp` (wiped on
  redeploy). Rotate with `wrangler secret put PROXY_KEY` if it leaks.
- (Optional) A custom domain `<your-domain>`: uncomment the `routes`
  block in `wrangler.toml` / `wrangler-cors.toml` and set your pattern.

## 4. Quick Start

```sh
git clone https://github.com/<your-name>/cf-egrees.git
cd cf-egrees
wrangler kv namespace create KV        # put the id in wrangler.toml
wrangler secret put PROXY_KEY          # master key (admin)
wrangler deploy                        # cf-egress (server-side)
wrangler deploy --config wrangler-cors.toml   # cf-egress-cors (browser)
wrangler secret put PROXY_KEY --config wrangler-cors.toml  # same key as main
```

Then mint a token and fetch through it (auth is the `X-Proxy-Key`
header, never in the URL):

```sh
curl -s -X POST "https://<your-domain>/register?name=alice"
# {"token":"<jwt>","name":"alice",...} — keep the token, it cannot be recovered
curl -s -H "X-Proxy-Key: <token>" "https://<your-domain>/?url=https://example.com"
```

## 5. Example live

Operator `<your-name>`, domain `<your-domain>`, token minted for `alice`:

```sh
# 1. Mint a token (open, self-serve)
curl -s -X POST "https://<your-domain>/register?name=alice"
# -> {"token":"<jwt>","name":"alice",...}

# 2. Fresh fetch (default, no cache)
curl -s -H "X-Proxy-Key: <token>" \
  "https://<your-domain>/?url=https://example.com"
# -> response body, X-Cache: OFF

# 3. Cache 600s: first call MISS, next calls HIT until 600s pass
curl -s -H "X-Proxy-Key: <token>" \
  "https://<your-domain>/?url=https://example.com&cache=600"
# -> X-Cache: MISS, then X-Cache: HIT

# 4. List your cached entries
curl -s -H "X-Proxy-Key: <token>" "https://<your-domain>/list"

# 5. Admin: revoke the token (master key only)
curl -s -X POST -H "X-Proxy-Key: <master>" \
  -d '{"token":"<token>"}' "https://<your-domain>/revoke"
# -> token denylisted in KV; its cache goes with it
```
