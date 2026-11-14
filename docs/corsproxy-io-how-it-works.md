# corsproxy.io — How It Works (research for a private Cloudflare Worker clone)

**Researched 2026-11-13.** Docs and homepage read live in the research browser and via the web index the same day; the live endpoint was tested without an API key. Every claim below carries its source link. Where the primary docs are silent or contradict each other, that is stated explicitly rather than filled in by guessing — this matters most for header/credential forwarding, redirects, preflight, and streaming, which are exactly the places a private clone can go wrong.

## Summary

- **What it is:** a hosted, commercial CORS proxy. A browser app prefixes a target URL with `https://corsproxy.io/?key=YOUR_API_KEY&url=<percent-encoded target>`; the service fetches the target server-side (where browser CORS does not apply), then re-serves the response with CORS headers added. Homepage: "CORSPROXY makes the request server-side, adds the CORS response headers your browser needs, and returns the API response to your app." — https://corsproxy.io/
- **Not open source, not self-hostable.** No repository, source download, or self-host path is linked anywhere on the site or in the docs (independent check 2026-09-17: https://corx.envx.cn/en/compare/corsproxy-io). It is a closed, hosted-only service. Several same-named open-source projects exist and are **not** corsproxy.io (see §1).
- **Auth is mandatory now.** A request without a key was tested live on 2026-11-13 and returned `{"error":"A valid API key is required. Get one at https://console.corsproxy.io/"}`. Older blog posts/snippets showing keyless `?url=` use are stale. Docs FAQ: "Can I use CorsProxy on all subdomains…" / "Can I use corsproxy.io directly without an account? — No." — https://corsproxy.io/docs/faq/
- **Stack (as claimed by the operator):** Cloudflare edge network (330+ data centres, 50+ countries), per-request isolated ephemeral containers, TLS end-to-end. No language/framework is disclosed — there is no code to inspect.
- **Security posture worth copying:** API key + registered caller domains/referrers, SSRF blocking of localhost/private/link-local/metadata hosts, only `http/https/ws/wss` schemes, 30-second upstream timeout, 1 MB response cap on Free/Hobby (1 GB on Production), stripping of forwarding headers and `Set-Cookie`, no caching of authenticated responses, per-plan rate limits (60 / 300 / 3,000 RPM), and a keyword blocklist for streaming/piracy/IPTV abuse. Source: https://corsproxy.io/abuse/ and https://corsproxy.io/pricing/
- **Biggest weaknesses to *not* copy:** (1) the proxy key **and** any upstream credential supplied via `reqHeaders=authorization:Bearer …` both travel in the URL query string — visible in browser history, server logs, `Referer`, and the operator's own URL logging; (2) the docs are internally inconsistent on whether `Authorization`/`Cookie` headers sent to the proxy are forwarded upstream, so the real behaviour cannot be established from documentation alone; (3) the exact CORS headers it adds, redirect handling, preflight handling, and streaming/SSE behaviour are **not documented** in the docs pages read — a clone must decide these explicitly instead of assuming corsproxy.io's behaviour.
- **For the private clone:** copy the *shape* (`?url=`, key auth, domain allowlist, SSRF checks on every redirect hop, size/time caps, cache-safety rules, `X-Request-ID`-style tracing) and harden the rest: server-side secret storage bound per-host (never credentials in the URL), a target-host allowlist (the requester wants *all* his traffic through one domain, so allowlisting is feasible and is the single highest-value control), stripping credentials by default, and no shared cache for authenticated responses. Full checklist in §7.

---

## 1. What is corsproxy.io, who runs it, and is it open source?

### What it is
A hosted CORS / cross-origin proxy for browser apps. From the docs index: "CorsProxy allows web applications to securely access resources from different domains, overcoming browser restrictions. It simplifies API integration, enhances security, and improves user experience by enabling seamless interaction with third-party services." — https://corsproxy.io/docs/

The homepage pitch is the same: "Stop being blocked by `Access-Control-Allow-Origin` errors. Proxy any API or domain in seconds — no config needed." and "Free for development: up to 10,000 requests and 1 GB/month." — https://corsproxy.io/

Beyond plain proxying it is now a small platform: dynamic edge caching, request/response header overrides, web-content extraction ("web scraping API"), CSV/XML/RSS → JSON conversion, and image transformation (beta). Those are Production-plan features in most cases; see §3.

### Who runs it
**Not publicly named.** No company name, legal entity, founder, or person is stated on the homepage, docs, privacy policy, or DMCA page — only contact emails `support@corsproxy.io` and `abuse@corsproxy.io`. Sources: https://corsproxy.io/privacy/ (contact: support@corsproxy.io), https://corsproxy.io/abuse/ (abuse@corsproxy.io), https://corsproxy.io/dmca/ (support@corsproxy.io).

What can be established about the operator/infrastructure:
- Hosted behind Cloudflare: Netcraft site report lists hosting company Cloudflare, netblock owner Cloudflare, Inc., first seen May 2022, organisation "Unknown" — https://sitereport.netcraft.com/?url=https%3A%2F%2Fcorsproxy.io
- WHOIS (via a third-party mirror): registrar NameCheap, Inc.; registrant "REDACTED FOR PRIVACY", organisation "Privacy service provided by Withheld for Privacy ehf" — http://corsproxy.io.siterate.org
- The homepage displays a "Cloudflare Partner Network" badge and claims "a global edge network of **330+ data centers in over 50 countries**", "~25 ms Added Latency, measured median", "~1.5 million IP Addresses", "99.99% Uptime the last 90 days" — https://corsproxy.io/
- It claims each request runs in "its own isolated, ephemeral container — spun up on demand and gone the moment it completes… No shared memory, no persistent state… Every connection between client, proxy, and origin is encrypted end-to-end with TLS… Requests are handled at the edge" — https://corsproxy.io/ ("Secure by Architecture" section). This is a marketing claim, not verifiable from outside; there is no architecture post or code to confirm the container claim, and it sits oddly with the Cloudflare-edge claim (Cloudflare Workers are isolates, not containers — the operator may run its own containers behind Cloudflare, or the wording may be loose).

### Is it open source? — No
- **No repository for corsproxy.io itself was found.** The independent CORX comparison, which re-read the site/docs on 2026-09-17, states: "Self-hosting: No repository, source download or self-host path is linked anywhere on the site or in the docs." and "Closed source, hosted only: there is no self-host path." — https://corx.envx.cn/en/compare/corsproxy-io
- No license, language, or stack is disclosed for the service itself. The docs never name a runtime. Do not assume Node/Go/Workers from the edge-network claim.
- The homepage line "Used in 10,000+ Projects on Github" is a usage claim (a link to github.com), not a link to its own source — https://corsproxy.io/

### Same-name projects that are NOT corsproxy.io (do not confuse them)
| Project | What it is | Licence / stack |
|---|---|---|
| `github.com/melihbirim/corsproxy` | A different, newer Go CORS proxy (single binary, ~10 MB Docker image); blocks private/loopback/metadata IPs by default, re-checked on redirects; env vars `ALLOWED_ORIGINS`, `ALLOWED_HOSTS`, `RATE_LIMIT_PER_MINUTE` | MIT (per its DEV post https://dev.to/melih_birim_8363f43966da2/self-host-a-cors-proxy-in-60-seconds-a-go-alternative-to-cors-anywhere-34lk) |
| `github.com/marcosdiez/corsproxy` | Docker image "Proxies requests and adds CORS headers", forked from `pgaskin/corsproxy` | per https://hub.docker.com/r/marcosdiez/corsproxy |
| `github.com/hyacinthus/corsproxy` | Go `CORSProxy` HTTP handler package | per https://pkg.go.dev/github.com/hyacinthus/corsproxy |
| `github.com/Zibri/cloudflare-cors-anywhere` | The classic self-hosted Cloudflare Worker CORS proxy (single `index.js`, `wrangler deploy`); **notably has no SSRF filter and no enforced rate limit in code** — see §7 | MIT (per https://corsproxy.dev/blog/cloudflare-cors-anywhere-source-read) |

For a private clone, `melihbirim/corsproxy` (Go/Docker) and `Zibri/cloudflare-cors-anywhere` (Worker) are the closest *starting points*, but neither is corsproxy.io's code.

---

## 2. Request flow end to end

### The canonical request
Verified live in the docs (https://corsproxy.io/docs/how-to-use/):

```
https://corsproxy.io/?key=YOUR_API_KEY&url=<ENCODED_TARGET_URL>
```
e.g. `https://corsproxy.io/?key=YOUR_API_KEY&url=https%3A%2F%2Fapi.github.com%2Fusers%2Foctocat`

- The target must be encoded with `encodeURIComponent()` (or `URLSearchParams`), including its own query string. Unencoded targets with `?`, `&`, spaces, or non-ASCII break the query string.
- A legacy/alternative direct form `https://corsproxy.io/?https://…` exists but the docs call it "less-compatible" — "Using the less-compatible direct query format (`?https://...`) for complex URLs" is listed under Common mistakes (https://corsproxy.io/docs/how-to-use/).
- Getting started (https://corsproxy.io/docs/getting-started/): 1) create a free account / get a key and register your app domain (the *browser app's* domain, e.g. `my-app.example.com`, not the target API's domain; check the normalised-domain preview before saving); localhost and other dev origins work immediately on Free; production domains need a paid plan. 2) Put the key in the request (`URLSearchParams` encodes the complete target URL). 3) Diagnose errors (table: missing/invalid key; origin/Referer not registered; plan/content restriction; HTTP 429 — inspect body and `Retry-After`; HTTP 403 or other target error — inspect body and upstream auth; network error/timeout). 4) Verify from the deployed app.

### Step-by-step flow (as documented)
1. **Client → proxy.** Browser `fetch()` (or `curl`, `<img>`, etc.) to `corsproxy.io` with `key` + `url` (+ optional params, §3). The request is a normal cross-origin fetch to the proxy's own origin, so the *browser's* CORS check is against corsproxy.io's response, not the target's.
2. **Auth + caller-origin check.** The key authenticates the account, attributes usage, and enforces plan limits ("Your API key authenticates requests, attributes usage to your account, and powers the analytics dashboard" — https://corsproxy.io/docs/faq/). Paid plans check the caller domain against domains registered in the dashboard ("Allowed Domains"); Free covers development origins such as localhost without registration. The troubleshooting page states non-localhost web apps "must add your domain to the proxy dashboard" and lists production/staging/dev domains, with localhost/`127.0.0.1` exempt (https://corsproxy.io/docs/troubleshooting/). The Security page adds referrer allowlisting: "Configure your subdomain to only accept requests from specified referrers, preventing unauthorized access" and custom subdomains that can be generated/reset (https://corsproxy.io/docs/security/). The FAQ confirms: "Specify allowed referrers in your subdomain settings. Only requests from those referrers will be processed." (https://corsproxy.io/docs/faq/)
3. **Security gates (before the upstream fetch).** SSRF/protocol checks, content blocklist, rate limits — see §4.
4. **Upstream fetch.** The service makes the request server-side, in its own ephemeral container per the homepage claim. Method, headers, and body are forwarded as described below (with the credential caveat).
5. **Response handling / caching.** Edge caching may serve the response without touching the origin (default 1 h TTL, per-data-centre; see §3 / Dynamic Cache). Otherwise the upstream response is returned, with selected headers stripped/rewritten and CORS headers added.
6. **Client ← proxy.** The browser receives the upstream status/body plus proxy-added headers. Errors from the proxy itself are JSON, e.g. `{"error": {"status":400,"message":"No valid URL provided. Use ?url=https://example.com","requestId":…}}` (https://corsproxy.io/docs/troubleshooting/). Responses carry an `X-Request-ID` header for support/debugging (same page).

### HTTP methods supported
- Documented examples cover **GET** (simple API request) and **POST** (JSON body, GraphQL) — https://corsproxy.io/docs/usage-examples/. The same page shows a POST with `Content-Type: application/json` and a JSON body forwarded to the target.
- The operator's CORB/ORB blog post states it supports "all HTTP methods (GET, POST, PUT, DELETE)" and "Handling preflight OPTIONS requests properly" — https://staging.corsproxy.io/blog/corb-orb-blocking-fix/ (staging mirror of the blog; treat as operator claim, not a docs-page statement).
- The docs pages read do **not** publish an authoritative method list, and do not state whether PATCH/HEAD/DELETE are allowed on all plans. The Dynamic Cache doc implies HEAD is cacheable like GET, and POST is cacheable only for safe content types (see §3). **Verdict: GET/POST are certain; PUT/DELETE are claimed in a blog post; PATCH/HEAD/OPTIONS handling is not documented on a docs page.**

### Request headers / cookies / auth forwarding — CONFLICTING SOURCES, READ CAREFULLY
This is the least well-documented part, and the sources disagree:

- **Independent comparison (cors.dev, 2026):** "The service is designed not to forward cookies or Authorization headers to target servers." and the at-a-glance table lists corsproxy.io's credentials policy as "Does not forward cookies or Authorization" — https://cors.dev/guides/free-cors-proxy
- **Operator's own cache docs (consistent with non-forwarding or with bypass-on-auth):** "Caching is bypassed when… Request includes `Authorization` or `Cookie` headers" and "Response includes `Set-Cookie` or `WWW-Authenticate` headers" — https://staging.corsproxy.io/docs/dynamic-cache/. The Abuse page says the same: "Skips caching when requests include `Authorization` or `Cookie`." — https://corsproxy.io/abuse/. This proves those headers are *seen* by the proxy; it does not prove they are forwarded.
- **Operator's own examples (suggest forwarding):** Usage Examples and Best Practices both show `fetch(…, { headers: { 'Authorization': 'Bearer <redacted>' } })` against the proxy URL — https://corsproxy.io/docs/usage-examples/, https://corsproxy.io/docs/best-practices/. If Authorization were always stripped, those examples would silently fail against authenticated APIs.
- **Operator's glossary (suggests forwarding):** "When using CorsProxy, standard HTTP headers like User-Agent, Accept, Authorization, and custom application headers pass through transparently to destination servers." — https://staging.corsproxy.io/glossary/http-headers/. Glossary pages on this site are SEO-generated and less reliable than the docs pages.
- **Header Overrides doc (suggests explicit opt-in instead):** upstream auth is set via a query parameter, `reqHeaders=authorization:Bearer%20TOKEN` — https://staging.corsproxy.io/docs/header-rewrites/. If plain `Authorization` headers were forwarded, this override would be redundant for auth (though still useful for other headers). The CORX comparison notes the same design flaw: "Header overrides are query parameters (`reqHeaders=authorization:Bearer <redacted>`), so the value comes from the caller — their own FAQ says to keep upstream secrets out of browser code." — https://corx.envx.cn/en/compare/corsproxy-io
- **What is certain:** the Abuse page states header sanitisation "Strips forwarding headers (`x-forwarded-for`, `cf-*`, `x-real-ip`) and sensitive response headers like `set-cookie`." — https://corsproxy.io/abuse/. So the client's real IP is **not** forwarded via `X-Forwarded-For` (the upstream sees the proxy's IP; the operator's IP-address glossary notes `httpbin.org/ip` through the proxy returns the proxy IP), and upstream `Set-Cookie` is stripped from the response, so the proxy cannot be used to plant cookies in the caller's browser for the target domain.

**Bottom line for the clone:** do not copy corsproxy.io's ambiguity. Decide explicitly (recommendation in §7: strip `Cookie`/`Authorization` by default; inject upstream credentials server-side only, bound to specific hosts).

### Response headers
- The upstream status code and (most) response headers pass through — the 403 guide says to "Compare status codes and response bodies" between direct and proxied requests, implying status passthrough — https://staging.corsproxy.io/docs/403-forbidden/. The Troubleshooting page likewise says a 403 "means the request was blocked either by CorsProxy policy/plan limits or by the upstream site", i.e. upstream statuses are surfaced, not masked.
- Stripped from responses: `Set-Cookie` (Abuse page, above). Other hop-by-hop / security headers are not enumerated in the docs.
- Added by the proxy: CORS headers (homepage: "adds the CORS response headers your browser needs" — https://corsproxy.io/), cache diagnostics (`X-Cache-Status: HIT|MISS|BYPASS`, `X-Cache-Read`, `X-Cache-Write`, `X-Cache-Skip`, `X-Cache-Body-Hash` — https://staging.corsproxy.io/docs/dynamic-cache/), `X-Request-ID` (troubleshooting), and for image transforms `X-Transform-Status` (https://staging.corsproxy.io/docs/image-transformation/).
- **Exact CORS header values are not published in the docs pages read.** The CORB blog post says it adds "`Access-Control-Allow-Origin: *`" — https://staging.corsproxy.io/blog/corb-orb-blocking-fix/. No docs page states the values of `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age`, `Access-Control-Expose-Headers`, or whether credentials are allowed. Note `resHeaders` can override the response `Access-Control-Allow-Origin` to a specific origin, e.g. `resHeaders=access-control-allow-origin:https://myapp.com` — https://staging.corsproxy.io/docs/header-rewrites/.

### Redirects — NOT DOCUMENTED
No docs page read states whether/how many redirects are followed, whether redirect targets are re-checked against the SSRF rules, or whether the original `Authorization` (if any) is forwarded to the redirect target. (For contrast, cors.dev documents "up to 20 redirects are followed" and re-checks every hop — https://cors.dev/guides/free-cors-proxy — but that is cors.dev, not corsproxy.io.) The generic CORS rule that browsers reject redirects on preflight responses still applies to the browser↔proxy leg. **A clone must implement redirect re-validation explicitly; do not assume corsproxy.io does it.**

### Preflight (OPTIONS) — NOT DOCUMENTED ON A DOCS PAGE
No docs page read describes OPTIONS handling (whether the proxy answers preflight itself with CORS headers, or forwards OPTIONS upstream). The CORB blog claims "Handling preflight OPTIONS requests properly" (link above). The practical consequence: a browser calling the proxy with a JSON `Content-Type` or a custom header will send an OPTIONS preflight *to corsproxy.io*; for the flow to work, the proxy must answer that preflight itself. That is standard proxy behaviour, but it is not stated in the docs, and no `Access-Control-Max-Age` value is published.

### Binary bodies, streaming, SSE, WebSockets
- **Binary:** supported within plan limits — Hobby adds "raw image delivery" / "Text + Simple Media (jpg, png, gif, pdf…)", Production "Proxy all types of files… instead of only simple text formats" and "All (Streams & Downloads) (mp3, docx, exe, zip…)" — https://corsproxy.io/pricing/. Usage Examples show downloading an image as a `blob()` (Hobby or higher; plan size limits apply) — https://corsproxy.io/docs/usage-examples/.
- **Streaming / SSE:** not documented as a feature. The pricing table's Production row says "All (Streams & Downloads)", implying streams are a Production capability, but there is no doc on SSE, chunked transfer, or streaming passthrough, and the hard **30-second upstream timeout** (§5) bounds any long-lived stream in practice.
- **WebSockets:** the Abuse page allows `ws` and `wss` *schemes* ("Only `http`, `https`, `ws`, and `wss` are allowed") — https://corsproxy.io/abuse/ — and the pricing comparison table lists "WebSocket" as a connection type. But there is **no docs page explaining how to proxy a WebSocket through `?url=`** (e.g. whether `?url=wss://…` upgrades, or a separate endpoint is used). The Supabase integration guide says: "CORSPROXY's paid WebSocket support requires a separate Realtime transport integration; test channel joins, reconnects, and authentication before relying on it" and "Supabase Realtime opens a WebSocket connection. Changing `global.fetch` does not route that connection." — https://corsproxy.io/solutions/supabase/. Separately, the operator's own WebSocket blog post notes WebSockets bypass CORS entirely (no CORS headers are checked; the server must validate `Origin` itself) — https://staging.corsproxy.io/blog/websocket-cors-browser-games/. **Verdict: WS is a paid/ separate feature, not the plain `?url=` fetch flow; do not assume `?url=wss://…` works.**

---

## 3. Parameters / options besides `?url=`

All parameters are query-string parameters on `https://corsproxy.io/`. The docs distinguish the always-available `key`/`url` from Production-gated features. FAQ: "The following parameters require a Production plan and a valid API key: `extract`, `input`, `output`, and `ttl`." — https://corsproxy.io/docs/faq/. The Abuse page adds that "Advanced params (`extract`, `ttl`, …)" are blocked on Free and Hobby — https://corsproxy.io/abuse/.

| Parameter | Meaning | Plan | Source |
|---|---|---|---|
| `key` | API key (account auth, usage attribution, dashboard) | All (required) | https://corsproxy.io/docs/how-to-use/, https://corsproxy.io/docs/faq/ |
| `url` | Percent-encoded target URL | All | https://corsproxy.io/docs/how-to-use/ |
| `ttl` | Cache TTL override, integer **seconds** (e.g. `300`, `3600`); default cache TTL is 1 hour | Production + key | https://staging.corsproxy.io/docs/dynamic-cache/ |
| `debug` | `debug=1` adds cache diagnostics (`X-Cache-Path`, `X-Cache-Key-Url`, `X-Cache-Key-Hash`) | (documented without plan note) | https://staging.corsproxy.io/docs/dynamic-cache/ |
| `reqHeaders` | Repeatable; set/override a **request** header upstream, `name:value` (URL-encoded); e.g. `reqHeaders=accept:application/json`, `reqHeaders=authorization:Bearer%20TOKEN` | Header rewrites are listed as a Production feature on pricing | https://staging.corsproxy.io/docs/header-rewrites/ |
| `resHeaders` | Repeatable; set/override a **response** header; empty value removes it, e.g. `resHeaders=x-frame-options:`, `resHeaders=content-security-policy:`, `resHeaders=cache-control:no-cache` | Production feature | https://staging.corsproxy.io/docs/header-rewrites/ |
| `extract` | `extract=1` — extract structured/readable content from HTML instead of returning raw HTML | Production + key | https://corsproxy.io/docs/web-scraping/ |
| `selector` | CSS selector for main content (with `extract`) | Production | https://corsproxy.io/docs/web-scraping/ |
| `titleSelector` | CSS selector for title | Production | https://corsproxy.io/docs/web-scraping/ |
| `bylineSelector` | CSS selector for author/byline | Production | https://corsproxy.io/docs/web-scraping/ |
| `strip` | Comma-separated selectors to remove, e.g. `strip=.ads,.promo` | Production | https://corsproxy.io/docs/web-scraping/ |
| `format` | With `extract`: `json` (default) or `text`; response `application/json;charset=UTF-8` or `text/plain;charset=UTF-8` | Production | https://corsproxy.io/docs/web-scraping/ |
| `maxChars` | Max characters in extracted output, e.g. `maxChars=5000` | Production | https://corsproxy.io/docs/web-scraping/ |
| `input` | Conversion input format: `csv`, `xml`, or `rss` | Production + key | https://corsproxy.io/docs/file-conversion/ |
| `output` | Conversion output format: `json` (only value); with `output=json` alone, input is auto-detected | Production + key | https://corsproxy.io/docs/file-conversion/ |
| `delimiter` | CSV delimiter override, e.g. `delimiter=;` | Production | https://corsproxy.io/docs/file-conversion/ |
| `image` | `image=1` enables image transformation | All plans (public beta) | https://staging.corsproxy.io/docs/image-transformation/ |
| `imageWidth` | Required, integer 1–4095 (before DPR; plan max still applies) | All | https://staging.corsproxy.io/docs/image-transformation/ |
| `imageHeight` | Optional, 1–4095 | All | https://staging.corsproxy.io/docs/image-transformation/ |
| `imageFit` | `inside` (default) or `cover` | All | https://staging.corsproxy.io/docs/image-transformation/ |
| `imagePosition` | `center` (default) or `attention` (face-aware crop) | All | https://staging.corsproxy.io/docs/image-transformation/ |
| `imageFormat` | `webp` (default), `jpeg`, `png` | All | https://staging.corsproxy.io/docs/image-transformation/ |
| `imageQuality` | `economy`, `balanced` (default), `high` (PNG: balanced/high only) | All | https://staging.corsproxy.io/docs/image-transformation/ |
| `imageDpr` | `1`, `2`, `3` (applied before plan limits are checked) | All | https://staging.corsproxy.io/docs/image-transformation/ |

Notes and interactions:
- **Caching (Dynamic Cache):** two paths — Tiered cache (GET/HEAD, Cloudflare tiered cache, default TTL 1 hour) and Cache API (POST when cacheable, feature requests such as extract/convert/image, or TTL override; default 1 hour unless overridden). Cache is **per data centre, not global**. Cache keys derive from normalised target URL, HTTP method, POST body hash, API key (Cache API entries), TTL override, feature variant, and applicable request-header overrides. Cache response headers: `X-Cache-Status` (`HIT`/`MISS`/`BYPASS`), `X-Cache-Read`, `X-Cache-Write`, `X-Cache-Skip`, `X-Cache-Body-Hash`. Caching is bypassed if the request includes `Authorization`/`Cookie`, the response includes `Set-Cookie`/`WWW-Authenticate`, or a POST content type is unsafe/unknown (e.g. `application/x-www-form-urlencoded`, `multipart/form-data`). POST caching is restricted to `application/json`, `text/plain`, `application/graphql` (Abuse page). Source: https://staging.corsproxy.io/docs/dynamic-cache/ and https://corsproxy.io/abuse/
- **Header overrides:** names are case-insensitive; URL-encode values with spaces/symbols; a helper `buildProxyUrl()` is given in the docs. Do **not** combine `image=1` with extraction, data conversion, or response-header rewrite parameters (Image Transformation doc).
- **No other parameters were found** in the docs pages read: there is no documented `method`, `body`, `followRedirects`, `timeout`, `userAgent`, or `origin` parameter — method/body come from the actual HTTP request to the proxy, not the query string.
- **Legacy form:** `?https://target…` (no `url=` key) is described as less-compatible (see §2).

---

## 4. Security model / abuse prevention

Primary source: https://corsproxy.io/abuse/ ("Abuse Prevention & Security"), supplemented by https://corsproxy.io/docs/security/ and https://corsproxy.io/pricing/.

### Controls stated on the Abuse page
| Control | Description (operator's words, paraphrased) |
|---|---|
| SSRF blocking | Blocks requests to localhost, loopback, private IP ranges, `.local` domains, and cloud metadata endpoints (e.g. `169.254.169.254`, `metadata.google.internal`) |
| Protocol restriction | Only `http`, `https`, `ws`, `wss` allowed; all other schemes rejected |
| Timeout protection | Upstream requests aborted after **30 seconds** |
| Header sanitization | Strips forwarding headers (`x-forwarded-for`, `cf-*`, `x-real-ip`) and sensitive response headers like `set-cookie` |
| Cache safety | Skips caching when requests include `Authorization` or `Cookie`; POST caching restricted to `application/json`, `text/plain`, `application/graphql` |
| Route-level control | "Snippet rules restrict execution to explicit proxy URL patterns on the exact intended host — no arbitrary subpaths or subdomains" |

The page also states: "CORSPROXY is a proxy service — we do not host, store, or cache any files or content. We only temporarily transfer data between the client and the upstream server. No content persists on our infrastructure after a request completes." and "requests [matching abuse patterns] are automatically detected and blocked… before any data is transferred." (Note: this "no caching" claim conflicts with the documented edge-caching feature — the intended meaning is presumably no *hosting/storage* of content; the Dynamic Cache doc is explicit that responses are cached at the edge.)

### Tier-based access control (Abuse page, §2)
| Restriction | Free | Hobby | Production |
|---|---|---|---|
| Max file size | 1 MB | 1 MB | 1 GB |
| Content types | Text only | Text, images, PDF | Text, images, PDF |
| Video (`video/*`) | Blocked | Blocked | By request |
| Allowed origins | Localhost / dev only | Any | Any |
| Server-side usage | Blocked | Blocked | Allowed |
| Advanced params (`extract`, `ttl`, …) | Blocked | Blocked | Allowed |

"Server-side usage" is enforced by detecting non-browser clients (the exact detection — User-Agent, `Sec-Fetch-*`, absence of `Origin`/`Referer` — is not documented).

### Content blocklist
"An extensive keyword blocklist that is continuously updated. Requests matching blocked patterns are rejected immediately. The blocklist covers streaming services, piracy-related terms, IPTV protocols, and other categories commonly associated with abuse." Listed examples: `spotify uefa stream download hls m3u8 iptv` "+ hundreds more" — https://corsproxy.io/abuse/. This is a blunt keyword filter on the URL, not a content inspection — it will false-positive on legitimate URLs containing e.g. "stream" or "download".

### Rate limiting
- "All endpoints are subject to strict rate limits. Automated throttling prevents bulk abuse, scraping attempts, and resource exhaustion across the entire network." — no per-endpoint numbers are published on the Abuse page (https://corsproxy.io/abuse/).
- Per-plan RPM from pricing: **60 RPM (Free), 300 RPM (Hobby), 3,000 RPM (Production)**; monthly quotas 10,000 / 250,000 / unlimited* requests and 1 GB / 25 GB / unlimited* bandwidth; image-transform burst limits 20 / 100 / 500 per minute — https://corsproxy.io/pricing/, https://staging.corsproxy.io/docs/image-transformation/.
- 429 handling: Getting Started says to "Inspect the body and `Retry-After`; the limit may come from CORSPROXY or the target" — https://corsproxy.io/docs/getting-started/. Image-transform quota/burst exhaustion returns **429 with `Retry-After`** — https://staging.corsproxy.io/docs/image-transformation/.

### Authentication / API keys
- Every request requires `?key=` (live-tested, §2). Keys are per-account, created in the dashboard at `console.corsproxy.io`; the FAQ says the key "authenticates requests, attributes usage to your account, and powers the analytics dashboard" — https://corsproxy.io/docs/faq/.
- Caller restriction is by **registered domain / allowed referrer / custom subdomain** (resettable from the dashboard), not by IP allowlisting or by a second header. The FAQ: "Specify allowed referrers in your subdomain settings. Only requests from those referrers will be processed." (https://corsproxy.io/docs/faq/). Referer/Origin checks are spoofable by non-browser clients, so they are a browser-abuse control, not real authentication — the key in the URL is the only secret, and it is visible to anyone who sees the URL.
- There is **no server-side secret store** for upstream credentials: upstream auth can only be supplied by the caller, in the clear, via a fetch header or via `reqHeaders=…` in the URL (CORX comparison, https://corx.envx.cn/en/compare/corsproxy-io). The operator's own guidance is to keep upstream secrets out of browser code (ibid.).

### Logging and privacy
Privacy policy (last updated 23 August 2023 — https://corsproxy.io/privacy/):
- Account data: email address; password ("encrypted and not visible to us").
- Proxy usage data collected: **the requested URL, User Agent, and "standard web analytics data such as IP address, timestamps, and request counts"**. Explicit note: **"We do not log any body or header information of your requests."**
- Data is shared only with "trusted third-party service providers" who assist in operating the service, and when required by law / valid public-authority requests. It states "We do not sell, trade, or otherwise transfer your personal information to outside parties, except as described below".
- Retention: "as long as your account is active or as needed to provide you with our Services", plus legal/dispute/enforcement retention. No per-field retention period is given. No data-residency statement.
- The FAQ adds that the dashboard provides "request logs including URL, headers, and response status" (https://corsproxy.io/docs/faq/) — which sits in tension with the privacy policy's "we do not log any body or header information" (the dashboard may show headers for the *account holder's own* requests, or the FAQ may be loose; flag as unresolved).
- Practical implication: **the operator logs the full target URL** — including any API key, token, or `reqHeaders` credential embedded in it — plus the caller's IP and User-Agent. Anything sensitive in the `?url=` value is in the operator's logs by design.

### Abuse reporting
Abuse reports to `abuse@corsproxy.io`; "We respond to every report and remove abusive content within 24 hours… blocking an abusive URL pattern takes effect immediately across our entire network." DMCA via the DMCA policy (support@corsproxy.io) — https://corsproxy.io/abuse/, https://corsproxy.io/dmca/.

### What the SSRF guard does NOT demonstrably cover (gaps in the public record)
- The docs list host/IP categories, but do **not** state: whether DNS is resolved and re-checked at connect time (TOCTOU / DNS-rebinding defence), whether redirect targets are re-validated, whether IPv6 / 0.0.0.0 / decimal/hex/octal IP encodings / URL userinfo (`http://expected@evil`) / `@`-tricks are handled, or whether non-standard ports are restricted. A private clone must implement these explicitly (§7); do not assume corsproxy.io does.

---

## 5. Limits and failure modes

### Hard limits (documented)
| Limit | Free | Hobby | Production | Source |
|---|---|---|---|---|
| Requests / month | 10,000 | 250,000 | Unlimited* | https://corsproxy.io/pricing/ |
| Bandwidth / month | 1 GB | 25 GB | Unlimited* | https://corsproxy.io/pricing/ |
| Max response/file size | 1 MB | 1 MB | 1 GB | https://corsproxy.io/pricing/, https://corsproxy.io/abuse/ |
| Rate limit | 60 RPM | 300 RPM | 3,000 RPM | https://corsproxy.io/pricing/ |
| Production domains | localhost/dev only | 3 | 20 | https://corsproxy.io/pricing/ |
| Uptime commitment | Best effort, no SLA | 99.9% / month | 99.99% / month | https://corsproxy.io/pricing/ |
| Upstream timeout | 30 s (all plans) | 30 s | 30 s | https://corsproxy.io/abuse/, https://corsproxy.io/docs/troubleshooting/ |
| Image transform allowance | 50 / UTC month, burst 20/min, source ≤ 2 MiB, ≤ 1280 px | 1,000 / day, burst 100/min, ≤ 10 MiB, ≤ 2560 px | 10,000 / day, burst 500/min, ≤ 25 MiB, ≤ 4095 px | https://staging.corsproxy.io/docs/image-transformation/ |

\* "Fair use policy applies… Monthly allowances are monitored as a rolling 7-day quota equal to 1/4 of the monthly allowance. Excessive usage that impacts service quality may be subject to review." — https://corsproxy.io/pricing/. Free accounts created before 8 November 2026 "keep their existing access" (FAQ) — a grandfathering note implying a tightening of Free terms around that date.

### Status codes returned (docs: Troubleshooting + 403 guide + Image doc)
| Status | Meaning per docs | Source |
|---|---|---|
| 400 | No valid URL: `{"error":{"status":400,"message":"No valid URL provided. Use ?url=https://example.com","requestId":…}}`; also invalid image-transform params, non-image source, invalid `input`/`output` | https://corsproxy.io/docs/troubleshooting/, https://staging.corsproxy.io/docs/image-transformation/, https://corsproxy.io/docs/file-conversion/ |
| 401 | Invalid or inactive API key ("Invalid or inactive API key. Get a valid key at https://corsproxy.io/pricing/"); also the live no-key response body ("A valid API key is required…") | https://corsproxy.io/docs/troubleshooting/; live test 2026-11-13 (status code itself not captured from the browser JSON view) |
| 403 | Blocked/restricted: private/local targets, plan-restricted params (`extract`/`input`/`output`/`ttl`), server-side use on a browser-only plan, unregistered origin, missing/invalid key for a gated feature — **or the upstream itself returning 403** (datacenter-IP / bot / UA blocks). The docs stress distinguishing the two by fetching the target directly. | https://corsproxy.io/docs/troubleshooting/, https://staging.corsproxy.io/docs/403-forbidden/ |
| 413 | "Response exceeds `<limit>` size limit. Upgrade at https://corsproxy.io/pricing/" | https://corsproxy.io/docs/troubleshooting/ |
| 429 | Rate limit / quota exceeded (proxy or target); inspect body and `Retry-After`; image burst/quota exhaustion returns 429 with `Retry-After` | https://corsproxy.io/docs/getting-started/, https://staging.corsproxy.io/docs/image-transformation/ |
| 502 | "Failed to Fetch Target" — target URL wrong/unreachable | https://corsproxy.io/docs/troubleshooting/ |
| 504 | "Request Timeout (30s)" — target took too long | https://corsproxy.io/docs/troubleshooting/ |
| 2xx/3xx/4xx/5xx (other) | Upstream status codes are passed through (compare direct vs proxied) | https://staging.corsproxy.io/docs/403-forbidden/ |

### What breaks / failure modes
- **Large downloads:** hard-capped at 1 MB on Free/Hobby (413 above that), 1 GB on Production. A 1 MB cap makes the free tiers text/API-only in practice; the operator's own CORS guide lists "1MB limit, text-only (HTML disabled), rate limiting" for corsproxy.io — https://staging.corsproxy.io/blog/everything-about-cors/ (note: "HTML disabled" is not corroborated on the docs pages read; Free is described as "Text only" on the Abuse page, which may mean HTML is restricted as a content type on Free).
- **Slow APIs / long polling / SSE:** the 30-second upstream abort is a hard ceiling; anything slower returns 504. No streaming/SSE doc exists (§2).
- **Video / streaming services:** `video/*` blocked on Free/Hobby, "by request" on Production; the keyword blocklist rejects URLs containing `stream`, `hls`, `m3u8`, `iptv`, `download`, `spotify`, `uefa`, etc. — legitimate media/API URLs containing those substrings will be rejected.
- **Upstream bot protection:** many sites return 403 to the proxy's datacenter IPs even when the same URL works from a residential browser (docs name Polymarket and some finance/market APIs and news RSS feeds as examples). The proxy cannot fix this; the 403 guide's remedy is "try a different upstream endpoint or fetch it from your own backend" — https://staging.corsproxy.io/docs/403-forbidden/.
- **Cached staleness:** default 1-hour edge cache, per data centre (not global), means a changed upstream response can be stale for up to an hour unless `ttl` is overridden (Production) or the request bypasses cache (auth headers, `Cache-Control: no-cache` via `resHeaders`, or `debug=1` diagnostics) — https://staging.corsproxy.io/docs/dynamic-cache/.
- **Image transforms:** a failed/unrecognised transform silently returns the *original* image with `X-Transform-Status: unsupported` or `failed`; quota exhaustion returns the original with `X-Transform-Status: quota-exceeded` (if opted in via console) or 429 by default — callers must check `Content-Type` and `X-Transform-Status`, not assume transformation happened — https://staging.corsproxy.io/docs/image-transformation/.
- **Cache poisoning via shared cache:** the cache key includes the API key for Cache API entries and request-header overrides, but the tiered (GET/HEAD) cache is a shared edge cache; combined with the cache-bypass-on-auth rule, this is why authenticated responses must bypass cache — a clone that caches an authenticated response under a shared key would leak it to other callers (§7).
- **Exceeding monthly quota:** email notification; "Depending on your subscription plan" (FAQ wording is truncated on the page) — https://corsproxy.io/docs/faq/.

---

## 6. Self-hosting

### corsproxy.io itself: no
There is no self-host option for corsproxy.io: no repo, no Docker image, no binary, no Worker template, no licence. The only path is the hosted service at `https://corsproxy.io/` with an account at `console.corsproxy.io`. Independent confirmation: https://corx.envx.cn/en/compare/corsproxy-io ("Closed source, hosted only: there is no self-host path").

### What it would take to run a private equivalent
The requester already plans a Cloudflare Worker; the honest answer is that the *equivalent* must be built, not installed. The closest existing starting points (none is corsproxy.io's code):

1. **Cloudflare Worker from scratch / from `cloudflare-cors-anywhere` (Zibri, MIT).** One `index.js`, deployed with `wrangler deploy`; the public demo is `test.cors.workers.dev`. **Warning from a line-by-line source read:** that code has *no* SSRF filter (the target URL "is never checked against any host, IP, or address-space list"), no enforced rate limit (the printed "100,000 requests/day / 1,000 requests/10 minutes" is not enforced in code), and forwards headers — a verbatim copy would be an open relay and a credential-laundering vector. Source: https://corsproxy.dev/blog/cloudflare-cors-anywhere-source-read
2. **Go single-binary proxy — `melihbirim/corsproxy` (MIT).** `git clone https://github.com/melihbirim/corsproxy`, `docker compose up` or `go run main.go`, listens on `http://localhost:8080`; GET/POST/PUT/PATCH/DELETE pass through with headers/body; `/health` endpoint; env-var lockdown (`ALLOWED_ORIGINS`, `ALLOWED_HOSTS`, `RATE_LIMIT_PER_MINUTE`, `DAILY_REQUEST_LIMIT`); private/loopback/metadata IPs blocked by default and re-checked on redirects; one-click configs for Railway/Render/Fly.io/Koyeb. Source: https://dev.to/melih_birim_8363f43966da2/self-host-a-cors-proxy-in-60-seconds-a-go-alternative-to-cors-anywhere-34lk
3. **CORX (MIT, Cloudflare Worker + D1 + R2).** A newer open-source Worker proxy with per-key auth, server-side secret injection (AES-256-GCM), D1 request logging, and R2 GET cache — the closest open analogue to corsproxy.io's *paid* feature set. Source: https://corx.envx.cn/en/compare/corsproxy-io
4. **CORS Anywhere (Node.js, MIT).** The classic self-host pattern (`originWhitelist`, `requireHeader`, `removeHeaders: ['cookie','cookie2']`); public demo locked down since Feb 2021. Source: https://cors.dev/guides/free-cors-proxy

For a *private* single-operator Worker, the build is small: one Worker, a secret for the operator's own auth, an allowlist, SSRF checks, and Workers KV/D1 for rate-limit counters if needed. The work is almost entirely in the hardening (§7), not the proxying — a naive `fetch(target)` in a Worker is ~20 lines and is exactly the dangerous version.

---

## 7. Lessons for a private clone (single operator, all traffic through one domain)

These are recommendations derived from corsproxy.io's documented design and its gaps. Items marked **[copy]** mirror something corsproxy.io documents; **[harden/change]** fixes a weakness in its design or in the naive Worker pattern. Items marked **[decide]** are places corsproxy.io's docs are silent/contradictory, so the clone must make an explicit choice.

### Copy from corsproxy.io
- **[copy] `?url=` + `?key=` shape.** Keep the same URL shape — it is the de-facto standard, every client library/blog snippet already speaks it, and it makes migration trivial. Keep `encodeURIComponent()` of the whole target (including its query string).
- **[copy] Per-request isolation / no shared state.** No in-memory state shared between requests; no persistent storage of bodies. (Homepage claim; implement in a Worker by simply not using globals/KV for bodies.)
- **[copy] SSRF blocklist as a floor:** localhost, loopback, private ranges (`10/8`, `172.16/12`, `192.168/16`), link-local (`169.254/16`), `.local` domains, and cloud metadata (`169.254.169.254`, `metadata.google.internal`). Source: https://corsproxy.io/abuse/
- **[copy] Scheme allowlist:** only `http`/`https` (plus `ws`/`wss` only if you deliberately implement WS). Reject everything else (`file:`, `ftp:`, `gopher:`, `dict:`, etc.). Source: https://corsproxy.io/abuse/
- **[copy] Hard upstream timeout (30 s) and response-size cap.** Abort upstream fetches at 30 s; enforce a size cap with a 413-style error. Do not let one slow/large upstream exhaust the Worker. Sources: https://corsproxy.io/abuse/, https://corsproxy.io/docs/troubleshooting/
- **[copy] Strip forwarding headers and `Set-Cookie`.** Never send `X-Forwarded-For` / `CF-*` / `X-Real-IP` upstream (the upstream should see the Worker IP, not the operator's), and strip `Set-Cookie` from responses so a proxied target cannot set cookies in the operator's browser for its own origin. Source: https://corsproxy.io/abuse/
- **[copy] Cache-safety rules.** Never cache a response when the request carried `Authorization`/`Cookie`, or the response carries `Set-Cookie`/`WWW-Authenticate`; restrict POST caching to safe content types (`application/json`, `text/plain`, `application/graphql`); include method, body hash, and auth identity in the cache key. Source: https://staging.corsproxy.io/docs/dynamic-cache/, https://corsproxy.io/abuse/
- **[copy] Structured errors + request IDs.** Return JSON errors with a stable shape and an `X-Request-ID` on every response; log that ID server-side so a failure can be traced without logging bodies. Source: https://corsproxy.io/docs/troubleshooting/
- **[copy] Rate limits per key + per IP, with `Retry-After` on 429.** corsproxy.io's 60/300/3,000 RPM tiers are a reasonable starting scale for a single operator (set a generous per-minute cap and a daily backstop). Source: https://corsproxy.io/pricing/
- **[copy] Diagnostic headers.** `X-Cache-Status: HIT|MISS|BYPASS` and a `debug=1` mode that exposes cache-path/key diagnostics are cheap and invaluable when a proxied API misbehaves. Source: https://staging.corsproxy.io/docs/dynamic-cache/

### Harden / change (do not copy corsproxy.io's mistakes)
- **[harden] Never put secrets in the URL.** corsproxy.io's key *and* any upstream credential via `reqHeaders=authorization:Bearer …` travel in the query string — logged by the operator (it logs the full requested URL — https://corsproxy.io/privacy/), stored in browser history, and leaked via `Referer` to any third party the page loads. For a private clone: authenticate the operator with a header (`Authorization: Bearer <proxy-key>` or a cookie on the proxy's own origin) or a POST body, **not** `?key=`. If browser `fetch()` must carry the key, use a header set by your own client code — never embed it in a URL that can be copied/shared/logged.
- **[harden] Server-side secret store, bound per host.** corsproxy.io has none: "No server-side secret store. Header overrides are query parameters… so the value comes from the caller" (https://corx.envx.cn/en/compare/corsproxy-io). A private Worker should hold upstream API keys in Worker Secrets / env vars, and inject them **only** for the specific host(s) each secret belongs to (allowlist per secret). The browser must never hold or see the upstream key — this is the CORX model's main advantage and the single biggest security win over corsproxy.io's design.
- **[harden] Target-host allowlist — the highest-value control for this use case.** corsproxy.io is an *open* proxy (any public host) because it is a public service; that is precisely what forces its SSRF/blocklist/rate-limit machinery. The requester is funnelling *his own* traffic through one domain, so he can enumerate the upstreams he actually uses. Allowlist those hosts (exact host + scheme, ideally port) and reject everything else with 403. This single control neutralises SSRF, open-relay abuse, and most content-blocklist needs — and makes the keyword blocklist (which false-positives on words like "stream"/"download") unnecessary.
- **[harden] SSRF: resolve, then check, on every hop — do not trust the hostname string.** corsproxy.io's docs do not state whether it re-validates after DNS resolution or on redirects. In a Worker you cannot easily do a custom DNS lookup, so: (a) reject IP-literal targets outright (or allow only explicitly allowlisted IPs); (b) reject hosts that *look* like encoded IPs (decimal, hex, octal, `0x…`, trailing-dot, `@`-userinfo tricks like `https://allowed.com@evil.com/`); (c) follow redirects manually (`redirect: "manual"`), re-running the allowlist + scheme + IP checks on each `Location`, with a small hop limit (e.g. 5) and a same-allowlist rule — never let a redirect escape the allowlist to a private address; (d) block non-standard ports unless explicitly allowlisted; (e) block `metadata.google.internal` and any `*.internal` / `*.local` / `*.localhost` names even if they resolve publicly.
- **[harden] Strip credentials by default; forward them only by explicit rule.** corsproxy.io's own docs contradict themselves on `Authorization`/`Cookie` forwarding (§2). For a private clone, the safe default is: strip `Cookie`, `Authorization`, and `Proxy-Authorization` from the client-supplied request unless a server-side rule for that exact host says otherwise. This prevents the classic credential-laundering attack (a malicious page that can call your Worker tricking it into forwarding the operator's session cookie / bearer token to an attacker host) — the exact attack the `cloudflare-cors-anywhere` source read warns about (https://corsproxy.dev/blog/cloudflare-cors-anywhere-source-read).
- **[harden] CORS headers: echo the operator's origin, don't use `*` with credentials.** corsproxy.io (per its blog) returns `Access-Control-Allow-Origin: *`. For a private proxy that will carry authenticated traffic, return the *specific* allowed origin (the operator's app origin), `Vary: Origin`, and only set `Access-Control-Allow-Credentials: true` for that origin. Restrict `Access-Control-Allow-Methods`/`Allow-Headers` to what the operator's apps actually send, and answer OPTIONS preflights in the Worker itself (do not forward OPTIONS upstream) with a sensible `Access-Control-Max-Age` (e.g. 86400). Never reflect an arbitrary `Origin` header.
- **[harden] Do not add `resHeaders`-style arbitrary header override from the URL.** corsproxy.io lets any caller set/remove *response* headers via query params, including removing `x-frame-options` / `content-security-policy` (https://staging.corsproxy.io/docs/header-rewrites/). That is a clickjacking/XSS-enabling primitive in the wrong hands. In a private clone, header rewrites should be server-side rules, not caller-controlled parameters.
- **[harden] Logging: log metadata, never bodies/URLs-with-secrets.** corsproxy.io logs the requested URL, UA, IP, timestamps, counts (https://corsproxy.io/privacy/) — for a private clone, log target *host* + path (without query), status, latency, and cache status; never log query strings (they may contain keys), request/response bodies, or headers. Add a retention cap and an off switch. If the Worker is on the operator's own Cloudflare account, remember Cloudflare itself also logs requests at the edge.
- **[harden] Enforce the "browser-only" boundary deliberately.** corsproxy.io distinguishes browser vs server-side clients by plan (server-side blocked on Free/Hobby). For a private clone, decide: if the Worker is only for the operator's browser apps, require a browser `Origin`/`Sec-Fetch-Site` that matches the allowlist and reject bare `curl`-style calls without the operator header; if server-side use is intended, use a separate secret for it. Don't rely on `Referer`/`Origin` alone — they are trivially spoofable by non-browsers.
- **[harden] Don't cache across trust boundaries.** corsproxy.io's cache is per-data-centre and keyed partly by API key, but a shared tiered cache for GETs is a leak vector if an authenticated response is ever cached. For a private clone: cache only unauthenticated, public GETs, keyed by full URL + operator key, with a short default TTL (1 h is corsproxy.io's default — reasonable), and honour upstream `Cache-Control: private/no-store/no-cache` and `Vary`.
- **[harden] Rate-limit *and* concurrency-limit per upstream host.** corsproxy.io rate-limits per plan, but a private clone funnelling *all* traffic through one Worker can accidentally DDoS a small upstream (or get the Worker's IP banned by it). Add per-host concurrency caps and a circuit breaker, and surface upstream 429s to the caller instead of retrying aggressively.
- **[change] No keyword blocklist.** corsproxy.io's `spotify/uefa/stream/hls/m3u8/iptv/download` blocklist is a public-service abuse control; for a private allowlisted proxy it adds false positives and no security. Replace it with the allowlist.
- **[change] No "ephemeral container" theatre.** The isolation claim is marketing; in a Worker the equivalent is simply: no shared mutable state, no KV/R2 writes of response bodies, secrets only in env bindings, and `waitUntil` only for logging. Say so in the code comments rather than claiming container isolation.

### Decide explicitly (corsproxy.io is silent — pick and document)
- **Redirects:** follow manually, max 5 hops, re-validate every hop against the allowlist, never forward credentials to a different host on redirect, and return the final status (or the redirect itself) — document which.
- **Preflight:** answer OPTIONS in the Worker with the fixed CORS set; never forward OPTIONS upstream.
- **Streaming/SSE:** decide whether to stream (`response.body` passthrough) or buffer; if streaming, note the Worker's own CPU/streaming limits and that a 30 s cap still applies to the *upstream connect + first byte* rather than the whole stream, or set an explicit overall deadline. Test SSE through the Worker before relying on it — corsproxy.io documents nothing here.
- **WebSockets:** do not assume `?url=wss://…` works — corsproxy.io treats WS as a separate paid feature (https://corsproxy.io/solutions/supabase/). In a Worker, WebSocket proxying needs the `WebSocketPair` / `fetch` upgrade path and is a separate code path from `fetch()`; either implement it deliberately or return a clear 400/501 for `ws(s)` targets.
- **Binary bodies:** stream request/response bodies (`request.body` passthrough) rather than buffering into memory, and enforce the size cap by aborting past N bytes, not by reading the whole body first.
- **Error contract:** copy corsproxy.io's JSON error shape (`{"error":{"status":…,"message":…,"requestId":…}}`) and its status mapping (400 missing/invalid URL, 401 bad proxy key, 403 blocked host/param, 413 too large, 429 rate-limited with `Retry-After`, 502 upstream unreachable, 504 upstream timeout) — it is a good, debuggable contract — but add a distinct code for "host not allowlisted" so it is distinguishable from an upstream 403.

---

## Could not verify
- **Exact CORS headers added** (`Access-Control-Allow-Origin` value in the general case, `Allow-Methods`, `Allow-Headers`, `Max-Age`, `Expose-Headers`, credentials). Only the blog claim of `*` was found; no docs page lists them.
- **Whether `Authorization`/`Cookie` headers are forwarded upstream.** Sources conflict (§2): cors.dev says no; operator examples/glossary imply yes; `reqHeaders` implies opt-in. No account was created and no authenticated upstream test was run, so this could not be settled empirically.
- **Redirect behaviour** (count, re-validation, credential handling on redirect) — not documented anywhere found.
- **Preflight (OPTIONS) handling** — claimed "properly" in a blog post only; no docs-page description.
- **Streaming / SSE / chunked-response handling** — not documented; only the pricing hint "All (Streams & Downloads)" on Production.
- **WebSocket proxying mechanism via `?url=`** — `ws`/`wss` are allowed schemes per the Abuse page, but no docs page explains the WS flow; the Supabase guide treats it as a separate paid integration.
- **Operator identity, language/stack, and the "isolated container" claim** — no named operator, no code, no architecture doc; hosting is Cloudflare per Netcraft.
- **Live endpoint status codes** — the no-key live test returned the error JSON body, but the HTTP status was not captured from the browser's JSON view; the 401 attribution rests on the Troubleshooting doc.
- **Request-size (upload) limits and per-request body caps** — only response/file-size limits are published.
- Docs pages for "Get an API Key", "Reliability", "Prohibited Content", and "Cancel Subscription" were listed in the docs nav but not read in full; nothing in this report depends on them.

## Sources
- Docs index (verified live): https://corsproxy.io/docs/
- Getting Started (verified live): https://corsproxy.io/docs/getting-started/
- How to Use (verified live): https://corsproxy.io/docs/how-to-use/
- Troubleshooting (verified live): https://corsproxy.io/docs/troubleshooting/
- Security (verified live): https://corsproxy.io/docs/security/
- Web Scraping (verified live): https://corsproxy.io/docs/web-scraping/
- Homepage: https://corsproxy.io/
- Abuse Prevention & Security: https://corsproxy.io/abuse/
- Pricing: https://corsproxy.io/pricing/
- Privacy Policy (last updated 23 Aug 2023): https://corsproxy.io/privacy/
- FAQ: https://corsproxy.io/docs/faq/
- Usage Examples: https://corsproxy.io/docs/usage-examples/
- Best Practices: https://corsproxy.io/docs/best-practices/
- File Conversion: https://corsproxy.io/docs/file-conversion/
- Dynamic Cache (staging mirror; prod path cited by CORX): https://staging.corsproxy.io/docs/dynamic-cache/
- Header Overrides (staging mirror): https://staging.corsproxy.io/docs/header-rewrites/
- Image Transformation (Beta) (staging mirror): https://staging.corsproxy.io/docs/image-transformation/
- 403 Forbidden (staging mirror): https://staging.corsproxy.io/docs/403-forbidden/
- CORB/ORB blog (staging): https://staging.corsproxy.io/blog/corb-orb-blocking-fix/
- CORS guide / limits table (staging): https://staging.corsproxy.io/blog/everything-about-cors/
- WebSocket in browser games (staging): https://staging.corsproxy.io/blog/websocket-cors-browser-games/
- HTTP Headers glossary (staging): https://staging.corsproxy.io/glossary/http-headers/
- Supabase integration: https://corsproxy.io/solutions/supabase/
- DMCA Policy: https://corsproxy.io/dmca/
- CORX vs corsproxy.io (independent, checked 2026-09-17): https://corx.envx.cn/en/compare/corsproxy-io
- cors.dev free-proxy comparison (independent): https://cors.dev/guides/free-cors-proxy
- cloudflare-cors-anywhere source read (corsproxy.dev blog): https://corsproxy.dev/blog/cloudflare-cors-anywhere-source-read
- Self-host Go corsproxy (different project, MIT): https://dev.to/melih_birim_8363f43966da2/self-host-a-cors-proxy-in-60-seconds-a-go-alternative-to-cors-anywhere-34lk
- marcosdiez/corsproxy Docker Hub: https://hub.docker.com/r/marcosdiez/corsproxy
- hyacinthus/corsproxy Go package: https://pkg.go.dev/github.com/hyacinthus/corsproxy
- Netcraft site report: https://sitereport.netcraft.com/?url=https%3A%2F%2Fcorsproxy.io
- WHOIS mirror: http://corsproxy.io.siterate.org
- Live endpoint test (no key), 2026-11-13, research browser: `https://corsproxy.io/?url=https%3A%2F%2Fjsonplaceholder.typicode.com%2Fusers%2F1` → `{"error":"A valid API key is required. Get one at https://console.corsproxy.io/"}`

*Notes file: `notes/sources-primary.md` (per-source reading log, 2026-11-13).*
