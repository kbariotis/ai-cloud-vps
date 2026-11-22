#!/usr/bin/env bash
# Smoke-test the MCP gateway's OAuth surface the way an MCP client (Gemini) discovers it.
# Usage: local/smoke.sh [base_url] [ca_file]
#   local:  local/smoke.sh https://localhost:8443 <caddy-root.crt>   (Makefile: make local-smoke)
#   remote: local/smoke.sh https://mcp.example.com
set -euo pipefail

BASE="${1:-https://localhost:8443}"
CA="${2:-}"
CURL=(curl -sS --max-time 10)
[[ -n "$CA" ]] && CURL+=(--cacert "$CA")

pass=0 fail=0
check() { # name, condition-result
  if [[ "$2" == "0" ]]; then echo "PASS  $1"; pass=$((pass + 1)); else echo "FAIL  $1"; fail=$((fail + 1)); fi
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }

# 1. Health
[[ "$("${CURL[@]}" "$BASE/healthz")" == "ok" ]]; check "healthz returns ok" $?

# 2. Unauthenticated MCP call -> 401 + WWW-Authenticate pointing at resource metadata (RFC 9728)
hdrs=$("${CURL[@]}" -o /dev/null -D - -X POST "$BASE/mcp" \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')
grep -qE '^HTTP/[0-9.]+ 401' <<<"$hdrs"; check "/mcp without token -> 401" $?
grep -qi 'www-authenticate: Bearer.*resource_metadata=' <<<"$hdrs"; check "401 carries resource_metadata" $?
grep -qi 'strict-transport-security' <<<"$hdrs"; check "HSTS header set" $?

# 3. Protected resource metadata, fetched from the URL the 401 advertised (as a client would)
prm_url=$(grep -i '^www-authenticate:' <<<"$hdrs" | grep -oE 'resource_metadata="[^"]+"' | cut -d'"' -f2)
prm=$("${CURL[@]}" "$prm_url")
[[ "$(json "['resource']" <<<"$prm")" == "$BASE/mcp" ]]; check "PRM ($prm_url) resource == $BASE/mcp" $?
as=$(json "['authorization_servers'][0]" <<<"$prm")
as=${as%/}
[[ "$as" == "$BASE" ]]; check "PRM names $BASE as authorization server" $?

# 4. AS metadata via RFC 8414 path insertion: https://host/.well-known/oauth-authorization-server/<path>
origin=$(python3 -c "import sys,urllib.parse as u;p=u.urlparse(sys.argv[1]);print(f'{p.scheme}://{p.netloc}')" "$as")
as_path=${as#"$origin"}
asm=$("${CURL[@]}" "$origin/.well-known/oauth-authorization-server$as_path")
[[ "$(json "['issuer']" <<<"$asm" | sed 's#/$##')" == "$as" ]]; check "AS metadata (path-inserted) issuer == $as" $?
json "['code_challenge_methods_supported']" <<<"$asm" | grep -q S256; check "AS supports PKCE S256" $?
reg=$(json "['registration_endpoint']" <<<"$asm")
[[ "$reg" == "$BASE/register" ]]; check "AS advertises DCR endpoint" $?

# 5. Dynamic Client Registration (RFC 7591)
client=$("${CURL[@]}" -X POST "$reg" -H 'content-type: application/json' \
  -d '{"client_name":"smoke","redirect_uris":["https://example.invalid/cb"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}')
cid=$(json ".get('client_id','')" <<<"$client")
[[ -n "$cid" ]]; check "DCR issued client_id" $?

# 5b. Registration with a redirect outside the allowlist is refused
evil=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$reg" -H 'content-type: application/json' \
  -d '{"client_name":"evil","redirect_uris":["https://attacker.example/cb"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}')
[[ "$evil" =~ ^4 ]]; check "DCR rejects non-allowlisted redirect_uri (got $evil)" $?

# 6. Authorize -> must end up at Google (directly or via consent page), never issue a code itself
verifier=$(python3 -c "import secrets;print(secrets.token_urlsafe(48))")
challenge=$(python3 -c "import base64,hashlib,sys;print(base64.urlsafe_b64encode(hashlib.sha256(sys.argv[1].encode()).digest()).rstrip(b'=').decode())" "$verifier")
loc=$("${CURL[@]}" -o /dev/null -D - -G "$BASE/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$cid" \
  --data-urlencode "redirect_uri=https://example.invalid/cb" --data-urlencode "code_challenge=$challenge" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "state=xyz" \
  --data-urlencode "resource=$BASE/mcp" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
[[ "$loc" == https://accounts.google.com/* || "$loc" == "$BASE"/consent* ]]; check "authorize redirects to Google/consent (got: ${loc:0:60}...)" $?

# 6b. Consent page must be reachable at that URL (catches prefix-routing mistakes)
[[ "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$loc")" == "200" ]]; check "consent page loads through the proxy" $?

# 7. Forged bearer token is rejected
code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/mcp" -H 'authorization: Bearer forged.token.value' \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d '{}')
[[ "$code" == "401" ]]; check "forged bearer token -> 401" $?

echo "---- $pass passed, $fail failed"
[[ $fail -eq 0 ]]
