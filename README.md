# cf-egrees — private ?url= fetch proxy (Cloudflare Worker)

A private `?url=` fetch proxy running on Cloudflare Workers. One domain
fronts all shell HTTP egress: clients ask the Worker for a target, the
Worker fetches it server-side and streams the response back.

Live: `https://cf-egress.skae.workers.dev` (Worker name `cf-egress`)

## Use

```sh
curl -s -H "X-Proxy-Key: $(cat ~/.config/cf-egress/proxy-key)" \
  "https://cf-egress.skae.workers.dev/?url=https://example.com"
```

- Auth is the `X-Proxy-Key` **header** — never in the URL (keys in URLs
  end up in logs, history, and `Referer` headers).
- `GET /health` needs no key.
- SSRF guard: http(s) only; localhost, loopback, private ranges,
  link-local, `.local`, and cloud metadata hosts are blocked (403).
- 30s upstream timeout, `X-Request-ID` on every response, `Set-Cookie`
  and forwarding headers stripped.

## Deploy

Secrets live in Replit Secrets on repl-14 (`CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID`). The `replit` CLI is at
`/nix/store/*-replit-cli-*/bin/replit` (not on PATH). Re-stage this dir
to repl-14, then:

```sh
replit secrets exec --keys CLOUDFLARE_API_TOKEN,CLOUDFLARE_ACCOUNT_ID -- bash deploy.sh
```

`deploy.sh` installs wrangler, generates `.proxy-key` if missing
(600, never printed), sets it as the Worker secret `PROXY_KEY`,
and deploys.

## Key

The `PROXY_KEY` secret is the only auth. Anyone holding it can use the
Worker. Keep it out of the repo (`.gitignore` covers `.proxy-key`),
out of `/tmp` (wiped on redeploy), and rotate it with
`wrangler secret put PROXY_KEY` if it leaks.

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
