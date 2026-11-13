#!/usr/bin/env bash
# Deploy cf-egress. Run on repl-14 via:
#   replit secrets exec --keys CLOUDFLARE_API_TOKEN,CLOUDFLARE_ACCOUNT_ID -- bash deploy.sh
# (Replit Secrets are injected into the child env; the fleet SSH session does NOT have them.)
set -euo pipefail
cd "$(dirname "$0")"
: "${CLOUDFLARE_API_TOKEN:?missing - run via replit secrets exec}"
: "${CLOUDFLARE_ACCOUNT_ID:?missing - run via replit secrets exec}"
# KV namespace (tokens + cache) must exist first, once:
#   npx wrangler kv namespace create KV   (same secrets exec)
# then put its id in wrangler.toml. Deploy refuses to run with the
# PENDING placeholder still in place.
grep -q 'id = "PENDING' wrangler.toml && { echo 'KV namespace id missing in wrangler.toml - create it first (see comment above)'; exit 1; }
[ -d node_modules/wrangler ] || npm install --no-audit --no-fund wrangler@4
if [ ! -f .proxy-key ]; then
  node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))" > .proxy-key
  chmod 600 .proxy-key
  echo "generated .proxy-key (kept on this box, never printed)"
fi
printf '%s' "$(cat .proxy-key)" | npx wrangler secret put PROXY_KEY
npx wrangler deploy
echo '--- deployed. test (key from .proxy-key):'
echo 'curl -s -H "X-Proxy-Key: $(cat .proxy-key)" "https://cf-egress.<subdomain>.workers.dev/?url=https://example.com" | head -c 300'
