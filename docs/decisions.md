# cf-egress architecture decisions (v3, 2026-11-14)

Decisions made during the cf-egress improvement + optimization work.
Each entry: the decision, the reasoning, and what would change it.

## 1. Response cache: Workers Cache API (caches.default), NOT KV

**Decision:** response bodies live in the Cache API; KV keeps only a
small metadata index (for `/list`, which the Cache API cannot enumerate).

**Why:**
- Edge-local (the body is served from the colo that cached it) instead
  of a KV read that may hit another region.
- No 10 MB KV value cap; the platform limit for `cache.put()` is far
  higher (we keep a 50 MB *policy* cap — see §4).
- Native HTTP-cache semantics: we store `Cache-Control: max-age=86400`
  for retention and track our own freshness (`x-cf-egress-expires-at`)
  so a stale copy survives long enough to be served as `STALE` on an
  upstream failure.
- KV is eventually consistent (~60s); a cache write followed by a read
  from another colo could miss. The Cache API is per-colo, so a write
  followed by a read on the same colo is consistent.

**Trade-off:** the Cache API is per-colo, not global — a cache MISS on a
different colo re-fetches. For a personal proxy this is fine (traffic
comes from a few colos). The KV metadata index is still a KV write per
cache-store (metadata only, ~200 bytes), so `/list` keeps working.

**What would change it:** if cache hit rate across colos proves too low
(measured — see the v3 report), move the metadata index to a global
store or accept KV for bodies again.

## 2. Tokens: stateless JWT (HMAC-SHA256, WebCrypto), NOT KV records

**Decision:** `POST /register` mints a JWT (`{sub, name, iat, exp}`,
exp = 1 year), signed with a key derived from `PROXY_KEY`
(`cf-egress-jwt-v1:` + PROXY_KEY, WebCrypto HMAC-SHA256, no npm deps).
No KV record is written on register. Auth verifies the signature and
expiry, then checks a KV denylist (`revoked:<tokenId>`) for revocation.

**Why:**
- No per-token KV record: register is stateless, no storage to manage.
- The token carries its own identity + expiry; verification is pure
  crypto (fast, no KV read for the token itself).
- Revocation still works via the denylist (see §3).

**Trade-off:** every authenticated request still does ONE KV read (the
denylist check). So JWT does not eliminate KV reads entirely — it
eliminates KV *writes* on register and KV *storage* for tokens. The
denylist is small (only revoked tokens) and each entry auto-expires
when the token would have expired, so it does not grow forever.

**Legacy:** tokens minted before v3 (stored in KV as `token:<sha256>`)
still authenticate as a fallback until revoked/re-registered. New
registrations get JWTs. There are no pre-v3 tokens in the current KV
namespace (it was wiped on the account change), so the fallback is
defensive only.

## 3. Durable Objects for instant token revocation: NOT implemented

**Decision:** do NOT use Durable Objects. JWT + KV denylist is enough.

**Why:**
- The only thing DO would buy is *instant* revocation (strong
  consistency). KV's denylist propagates in ~60s, so a revoked token
  may work for up to ~60s after revocation.
- Threat model: this is a personal fetch proxy. A 60s revocation
  window is acceptable — the damage from a revoked token being usable
  for one more minute is negligible (the proxy only fetches URLs; it
  holds no user data and the SSRF guard still applies).
- DO would add a DO class, a binding, per-request DO calls (extra
  latency + cost) and another thing to operate, for a benefit that
  does not matter here.

**What would change it:** if the proxy ever serves untrusted/multiple
tenants where a revoked token must die *immediately* (e.g. a token is
leaked publicly), move the denylist to a Durable Object. The code is
structured so the denylist check is a single function call — swapping
the backend is a small change.

## 4. R2 for >10 MB cached responses: NOT implemented

**Decision:** do NOT use R2. Keep a 50 MB policy cap on cached
responses; larger responses return `X-Cache: BYPASS` (fetched live,
never stored).

**Why:**
- This proxy fetches APIs. API responses are overwhelmingly small
  JSON (<1 MB). The 10 MB KV cap never bound in practice, and the
  50 MB Cache API policy cap is generous for this use.
- Caching large files through a fetch proxy is a bad fit: large
  downloads are usually one-off (a cached copy is rarely re-used),
  and storing them costs egress + storage for no benefit.
- R2 would add a bucket, bindings, and a second storage path for a
  case that does not occur.

**What would change it:** if a real use case needs >50 MB cache
entries (e.g. caching a large static asset that is fetched repeatedly),
add R2 as the overflow store (Cache API for <=50 MB, R2 above it).
The `BYPASS` branch is the single place to hook that in.

## 5. KV: what remains, and how it is tuned

KV is still used for three small things:
- `revoked:<tokenId>` — the revocation denylist (auto-expires at the
  token's expiry; see §2).
- `cachemeta:<tokenId16>:<urlSha>` — the cache metadata index for
  `/list` (auto-expires at the cache TTL).
- `token:<sha256>` — legacy token records (v2 fallback only; no new
  writes).

Tuning applied:
- Every KV write carries an `expirationTtl` (no orphaned keys).
- `/list` uses key metadata (no per-key `get`) and supports cursor
  pagination (`?cursor=`, returns `list_complete` + `cursor`).
- Cache bodies are NOT in KV (they are in the Cache API), so KV
  values stay tiny and KV reads on the hot path are limited to the
  single denylist check.
