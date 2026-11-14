# STALE proof — live reproduction (2026-11-14)

The `X-Cache: STALE` fallback (serve a cached copy when the upstream
fetch fails) was implemented in v2 but a live STALE response had never
been reproduced. This document records the first live reproduction,
against the deployed v3 worker.

## Why it was hard

Workers `fetch()` turns edge failures (DNS fail, connection refused,
TLS error) into HTTP error responses (1002/1003/1016/530) instead of
throwing — so the `catch` block that serves STALE never runs. Only a
genuine >30s hang throws (`AbortSignal.timeout(30000)`), and no public
host hangs that long from Cloudflare IPs. The fix is to *create* a
hanging upstream.

A second, subtler blocker was found during this work: in v2 the KV
cache entry expired at the freshness boundary (`expirationTtl =
cacheS`), so a cached copy could never be *stale* — if it existed it
was a HIT, and if it did not exist there was nothing to serve as
STALE. v3 fixes this by separating freshness (our own `expiresAt`
metadata) from retention (Cache API `max-age=86400`, KV body copy
retained 1 day). See `docs/decisions.md` §1.

## Method

- Upstream: a Node HTTP server on repl-14 port 3000, reachable via the
  repl-14 dev domain
  (`https://510e853a-51b3-4a11-abf2-bca2b08a6890-00-3ggzjq7bzfpa0.pike.replit.dev:3000/stale-test`).
  The server reads a mode file (`/tmp/stale-mode`): `fast` responds
  immediately with `stale-test body v1`; `hang` sleeps 35s before
  responding (longer than the Worker's 30s timeout).
- Token: a fresh JWT minted via `POST /register?name=staleproof2`.
- Step 1 (fast mode): `GET /?url=<dev-domain>:3000/stale-test&cache=60`
  → `X-Cache: MISS`, body `stale-test body v1`, cached at 14:00:02 WIB,
  `x-cache-expires: 2026-11-14T14:01:03.536Z`.
- Step 2: server flipped to `hang`, waited until 14:01:32 WIB (entry
  age ~90s, past the 60s freshness window), then `GET` the same URL.

## Result (the proof)

```
elapsed: 31s
HTTP/1.1 200 OK
Content-Type: text/plain
x-cache: STALE
x-cache-age: 120
x-cache-expires: 2026-11-14T14:01:03.536Z
x-request-id: 861be058-31b9-4d9f-b6ff-76cac51d2099

stale-test body v1
```

- **31s elapsed** — the Worker's 30s upstream timeout fired, then the
  cached copy was served (not a fast HIT, not a 502).
- **`x-cache: STALE`** — the fallback path ran.
- **`x-cache-age: 120`** — the served copy is 120s old, past the 60s
  freshness window (genuinely stale, not a fresh HIT).
- **Body is `stale-test body v1`** — the cached copy. The hanging
  server would not have responded within the timeout (it sleeps 35s).
- **HTTP 200** — the client got a usable response instead of a 502.

## Cleanup

The test server was stopped and removed from repl-14 after the proof
(no `stale-server` process, port 3000 closed). The test token
(`staleproof2`) was revoked. Nothing from the proof remains running.

## Reproducing

1. Start a server on a repl declared port that can hang >30s on demand.
2. Cache its URL through cf-egress with `?cache=<s>`.
3. Wait past `<s>` seconds, flip the server to hang, request the same
   URL. Expect `X-Cache: STALE` after ~30s with the cached body.
