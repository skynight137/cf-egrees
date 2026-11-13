# cf-egrees — private ?url= fetch proxy (Cloudflare Worker)

A private `?url=` fetch proxy running on Cloudflare Workers. One domain
fronts all shell HTTP egress: clients ask the Worker for a target, the
Worker fetches it server-side and streams the response back.

Live: `https://cf-egress.skae.workers.dev` (Worker name `cf-egress`)

## Auth — per-user tokens, not one shared key

Like a mail worker: a user creates their own entry, gets a token, and the
token re-opens their list. Tokens are minted open and self-serve; each
token only sees its own cached entries, and revoking a token deletes its
cache with it. Tokens never expire. The master key (`PROXY_KEY` Worker
secret) is admin: it fetches, lists tokens, and revokes.

```sh
# mint a token (open, self-serve)
curl -s -X POST "https://cf-egress.skae.workers.dev/register?name=alice"
# {"token":"...","name":"alice",...} — keep the token, it cannot be recovered

# fetch with it (X-Proxy-Key header, never in the URL)
curl -s -H "X-Proxy-Key: <token>" \
  "https://cf-egress.skae.workers.dev/?url=https://example.com"

# list your cached entries
curl -s -H "X-Proxy-Key: <token>" "https://cf-egress.skae.workers.dev/list"

# admin: list tokens / revoke one (master key only)
curl -s -H "X-Proxy-Key: <master>" "https://cf-egress.skae.workers.dev/list"
curl -s -X POST -H "X-Proxy-Key: <master>" \
  -d '{"token":"<token>"}' "https://cf-egress.skae.workers.dev/revoke"
```

## Cache — fresh by default, opt-in per request

Default is **always a fresh fetch**. Add `?cache=<seconds>` to cache the
response in KV for that long, then it is pruned (`expiration_ttl`).

```sh
# cache 600s: first call MISS, next calls HIT until 600s pass
curl -s -H "X-Proxy-Key: <token>" \
  "https://cf-egress.skae.workers.dev/?url=https://example.com&cache=600"

# force fresh (same as default): ?cache=0 or omit it
curl -s -H "X-Proxy-Key: <token>" \
  "https://cf-egress.skae.workers.dev/?url=https://example.com&cache=0"
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

Other behaviour, as before: SSRF guard (http(s) only; localhost,
loopback, private ranges, link-local, `.local`, cloud metadata hosts
blocked, 403), 30s upstream timeout, `X-Request-ID` on every response,
`Set-Cookie` and forwarding headers stripped.

## Deploy

Secrets live in Replit Secrets on repl-14 (`CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID`). The `replit` CLI is at
`/nix/store/*-replit-cli-*/bin/replit` (not on PATH). Re-stage this dir
to repl-14, then:

```sh
# once: create the KV namespace (tokens + cache), put its id in wrangler.toml
replit secrets exec --keys CLOUDFLARE_API_TOKEN,CLOUDFLARE_ACCOUNT_ID -- npx wrangler kv namespace create KV

replit secrets exec --keys CLOUDFLARE_API_TOKEN,CLOUDFLARE_ACCOUNT_ID -- bash deploy.sh
```

`deploy.sh` installs wrangler, generates `.proxy-key` if missing
(600, never printed), sets it as the Worker secret `PROXY_KEY`,
and deploys.

## Key

The master key is the admin credential. Anyone holding it can use the
Worker and revoke tokens. Keep it out of the repo (`.gitignore` covers
`.proxy-key`), out of `/tmp` (wiped on redeploy), and rotate it with
`wrangler secret put PROXY_KEY` if it leaks. User tokens are minted
open — the Worker URL itself is the only obscurity, so keep it
unlisted; revoke any token that gets abused.

## Notes (verified 2026-11-13)

- Shell `curl` through the platform proxy never triggers approval
  cards — for any host, fresh or not. Approvals are per-tool/binary:
  `node fetch` to a fresh host raised a card; curl/python/wget did not.
- Some hosts block Cloudflare Workers IPs (news.ycombinator.com 419,
  api.github.com 403, gnu.org 502/timeout) while direct curl passes.
- HTTPS-via-SOCKS5 is not possible from a Worker (`startTls()` takes no
  arguments; SNI is pinned to the proxy socket), so the fix for
  CF-IP-blocked HTTPS destinations is a relay, not a SOCKS5 header.
- Custom domain `<your-domain>` not attached yet.
