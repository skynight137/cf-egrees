# cf-egress — private `?url=` fetch proxy (Cloudflare Worker)

One domain fronts all shell HTTP egress: clients ask the Worker for a
target, the Worker fetches it server-side and streams the response back.
Default is a fresh fetch every time; `?cache=` opts into KV caching.

Live URL: `https://<your-domain>` (Worker `https://<your-worker>.workers.dev`
also works). Replace both placeholders with your own domain / Worker name.

## Setup

1. `wrangler kv namespace create KV` — put the id in `wrangler.toml`.
2. `wrangler secret put PROXY_KEY` — the master key (admin).
3. Attach your domain: `routes = [{ pattern = "<your-domain>", custom_domain = true }]` in `wrangler.toml`.
4. `wrangler deploy` (or `bash deploy.sh`, which installs wrangler, generates `.proxy-key` if missing, sets `PROXY_KEY`, deploys).

## Auth — per-user tokens, not one shared key

Like a mail worker: a user creates their own entry, gets a token, and the
token re-opens their list. Tokens are minted open and self-serve; each
token only sees its own cached entries, and revoking a token deletes its
cache with it. Tokens never expire. The master key (`PROXY_KEY`) is admin:
it fetches, lists tokens, and revokes.

```sh
# mint a token (open, self-serve)
curl -s -X POST "https://<your-domain>/register?name=alice"
# {"token":"...","name":"alice",...} — keep the token, it cannot be recovered

# fetch with it (X-Proxy-Key header, never in the URL)
curl -s -H "X-Proxy-Key: <token>" \
  "https://<your-domain>/?url=https://example.com"

# list your cached entries
curl -s -H "X-Proxy-Key: <token>" "https://<your-domain>/list"

# admin: list tokens / revoke one (master key only)
curl -s -H "X-Proxy-Key: <master>" "https://<your-domain>/list"
curl -s -X POST -H "X-Proxy-Key: <master>" \
  -d '{"token":"<token>"}' "https://<your-domain>/revoke"
```

## Cache — fresh by default, opt-in per request

Add `?cache=<seconds>` to cache the response in KV for that long, then it
is pruned (`expiration_ttl`).

```sh
# cache 600s: first call MISS, next calls HIT until 600s pass
curl -s -H "X-Proxy-Key: <token>" \
  "https://<your-domain>/?url=https://example.com&cache=600"

# force fresh (same as default): ?cache=0 or omit it
curl -s -H "X-Proxy-Key: <token>" \
  "https://<your-domain>/?url=https://example.com&cache=0"
```

- `?cache=` is clamped to **1..86400** (max 1 day, hard cap). Invalid
  values behave as fresh.
- Only `GET` 2xx responses `<= 10 MB` without `Set-Cookie` are cached.
- `X-Cache` tells what happened: `HIT`, `MISS`, `OFF` (fresh, no cache
  requested), `BYPASS` (not cacheable), `STALE` (see below).
- **RTO fallback:** if the upstream fetch fails (timeout / network
  error) and a cached copy exists for that token+URL, the cached copy
  is served (`X-Cache: STALE`) instead of a 502 — the request can be
  re-fetched from KV after a timeout.
- Cache is per-token (keyed by a hash of the token), never shared
  between tokens. `GET /health` needs no key.

Other behaviour: SSRF guard (http(s) only; localhost, loopback, private
ranges, link-local, `.local`, cloud metadata hosts blocked, 403), 30s
upstream timeout, `X-Request-ID` on every response, `Set-Cookie` and
forwarding headers stripped.

## Security

- The master key is the admin credential. Anyone holding it can use the
  Worker and revoke tokens. Keep it out of the repo (`.gitignore` covers
  `.proxy-key`), out of `/tmp` (wiped on redeploy), and rotate it with
  `wrangler secret put PROXY_KEY` if it leaks.
- User tokens are minted open — the Worker URL itself is the only
  obscurity, so keep it unlisted; revoke any token that gets abused.
- Never put a key or token in the URL — auth is the `X-Proxy-Key`
  header only.

## Limits & roadmap

- Some hosts block Cloudflare Workers IPs (HTTP 403/419, or a timeout)
  while a direct fetch passes. HTTPS-via-SOCKS5 is not possible from a
  Worker (`startTls()` takes no arguments; SNI is pinned to the proxy
  socket), so the fix for CF-IP-blocked HTTPS destinations is a relay,
  not a SOCKS5 header: the Worker fetches through a relay on a clean IP
  and caches the result in KV. The intended relay is your own VLESS VPN
  on a VPS; that is the next step, not yet wired in.
- Shell `curl` through a platform proxy never triggers approval cards
  for any host; approvals are per-tool/binary (`node fetch` to a fresh
  host raised one; curl/python/wget did not).
