#!/bin/bash
# End-to-end smoke test for minidp: multi-client OIDC/OAuth2 flows.
# Self-contained: builds the binaries, creates a clients file (one public and
# one confidential client, each with its own users) and starts its own IdP
# instance on port 8099.
set -euo pipefail

BASE="http://localhost:8099"
CLIENT="demo-app"          # public client on instance 1
CONF_CLIENT="conf-app"     # confidential client on instance 1
CONF_SECRET="smoke-test-confidential-secret"
REDIRECT="http://localhost:3000/callback"
CONF_REDIRECT="https://conf.example.com/cb"
VERIFIER=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
STATE="st-123"
NONCE="n-abc"
JAR=$(mktemp)

# Fail fast when a previous (interrupted) run left an IdP bound to the smoke
# port: the health-check below would silently talk to that stale instance
# (old code/clients file) and every later assertion would mismatch.
if lsof -nP -iTCP:8099 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "ERROR: port 8099 is already in use — a previous smoke-test run" >&2
  echo "probably left a minidp instance behind. Kill it and retry:" >&2
  lsof -nP -iTCP:8099 -sTCP:LISTEN >&2
  exit 1
fi

# Scratch files and the test instance are removed when the script exits
# (success or failure).
cleanup() {
  [ -n "${MINIDP_PID:-}" ] && kill "$MINIDP_PID" 2>/dev/null || true
  rm -rf "${JAR:-}" "${WORKDIR:-}"
  rm -f /tmp/login.html
}
trap cleanup EXIT

# Browsers (Chrome/Firefox) treat localhost as a "potentially trustworthy
# origin" and send Secure cookies over plain-HTTP localhost; curl implements
# RFC 6265 literally and would keep them for https only. Flip the secure flag
# in the Netscape jar to emulate the browser exception for the demo.
mark_jar_insecure() {
  awk -F'\t' 'BEGIN{OFS="\t"} /^#/ || NF==0 {print; next} {$4="FALSE"; print}' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

# Extract a fresh CSRF token from the rendered login form for the given
# authorization request parameters.
csrf_for() {
  curl -s -c "$JAR" "$BASE/authorize?$1" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p'
  mark_jar_insecure "$JAR"
}

AUTH_QUERY="client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid%20profile%20email&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"

echo "== 0. build + create the clients file + boot a self-contained IdP instance =="
WORKDIR=$(mktemp -d)
go build -o "$WORKDIR/minidp" .
go build -o "$WORKDIR/clientctl" ./cmd/clientctl
CTL="$WORKDIR/clientctl"
CFILE="$WORKDIR/clients.json"
"$CTL" client add -file "$CFILE" -client "$CLIENT" -type public \
  -redirect "$REDIRECT" -post-logout "$REDIRECT" >/dev/null
"$CTL" user add -file "$CFILE" -client "$CLIENT" -username demo \
  -password demo-password -email demo@example.com -roles user >/dev/null
"$CTL" client add -file "$CFILE" -client "$CONF_CLIENT" -type confidential \
  -secret "$CONF_SECRET" -redirect "$CONF_REDIRECT" \
  -post-logout "https://conf.example.com/" >/dev/null
"$CTL" user add -file "$CFILE" -client "$CONF_CLIENT" -username bob \
  -password builder >/dev/null
"$CTL" client list -file "$CFILE" >/dev/null && echo "clientctl: clients file created and listed"
mkdir -p "$WORKDIR/keys"
IDP_PORT=8099 IDP_ISSUER="$BASE" IDP_CLIENTS_FILE="$CFILE" \
  IDP_KEY_DIR="$WORKDIR/keys" \
  "$WORKDIR/minidp" >"$WORKDIR/minidp.log" 2>&1 &
MINIDP_PID=$!
for _ in $(seq 1 50); do
  curl -sf "$BASE/healthz" >/dev/null && break
  sleep 0.2
done
curl -sf "$BASE/healthz" >/dev/null || { echo "IdP did not come up"; exit 1; }
echo "IdP running on $BASE (clients: $CLIENT public, $CONF_CLIENT confidential)"

echo "== 1. discovery =="
curl -s "$BASE/.well-known/openid-configuration" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['issuer']=='$BASE', d['issuer']
for k in ('authorization_endpoint','token_endpoint','jwks_uri','userinfo_endpoint'):
    assert k in d, k
m=d['token_endpoint_auth_methods_supported']
assert m==['none','client_secret_basic','client_secret_post'], m
print('issuer:', d['issuer'])
print('grant_types:', d['grant_types_supported'])
print('pkce methods:', d['code_challenge_methods_supported'])
print('client auth methods (union):', m)
"

echo "== 2. jwks =="
curl -s "$BASE/jwks" | python3 -c "
import json,sys
d=json.load(sys.stdin)
k=d['keys'][0]
assert k['kty']=='RSA' and k['alg']=='RS256' and k['use']=='sig', k
print('jwks ok, kid =', k['kid'])
"

echo "== 3. GET /authorize renders login form =="
curl -s -c "$JAR" "$BASE/authorize?client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid%20profile%20email&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256" -o /tmp/login.html
grep -q 'name="code_challenge" value="'"$CHALLENGE"'"' /tmp/login.html && echo "PKCE challenge echoed into form"
grep -q 'name="nonce" value="'"$NONCE"'"' /tmp/login.html && echo "nonce echoed into form"

echo "== 3b. unknown client_id and unregistered redirects are rejected =="
ST=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/authorize?client_id=other-app&redirect_uri=$REDIRECT&response_type=code&code_challenge=$CHALLENGE&code_challenge_method=S256")
[ "$ST" = "400" ] && echo "unknown client_id rejected (400) OK"
ST=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/authorize?client_id=$CLIENT&redirect_uri=https://attacker.example/cb&response_type=code&code_challenge=$CHALLENGE&code_challenge_method=S256")
[ "$ST" = "400" ] && echo "unregistered redirect_uri rejected (400) OK"
# Per-client redirect policies: neither client may use the other's URI.
ST=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/authorize?client_id=$CONF_CLIENT&redirect_uri=$REDIRECT&response_type=code&code_challenge=$CHALLENGE&code_challenge_method=S256")
[ "$ST" = "400" ] && echo "conf-app with demo-app's redirect rejected (400) OK"
ST=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/authorize?client_id=$CLIENT&redirect_uri=$CONF_REDIRECT&response_type=code&code_challenge=$CHALLENGE&code_challenge_method=S256")
[ "$ST" = "400" ] && echo "demo-app with conf-app's redirect rejected (400) OK"
# Unsupported scopes/params are answered with a redirect carrying the error.
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/authorize?client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=user&code_challenge=$CHALLENGE&code_challenge_method=S256&state=$STATE")
case "$LOC" in
  "$REDIRECT?error=invalid_scope"*) echo "invalid_scope redirect OK" ;;
  *) echo "UNEXPECTED: $LOC"; exit 1 ;;
esac
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$BASE/authorize?client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&code_challenge=$CHALLENGE&code_challenge_method=S256&state=$STATE&max_age=900")
case "$LOC" in
  "$REDIRECT?error=invalid_request"*) echo "unsupported max_age rejected OK" ;;
  *) echo "UNEXPECTED: $LOC"; exit 1 ;;
esac

echo "== 4. POST /authorize with WRONG password =="
CSRF=$(csrf_for "$AUTH_QUERY")
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" \
  --data-urlencode "password=wrongpass")
[ "$LOC" = "401" ] && echo "wrong password rejected (401) OK"

echo "== 4b. per-client user isolation: demo-app's user cannot sign in to conf-app =="
CSRF=$(csrf_for "client_id=$CONF_CLIENT&redirect_uri=$CONF_REDIRECT&response_type=code&scope=openid&state=si&nonce=ni&code_challenge=$CHALLENGE&code_challenge_method=S256")
ST=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CONF_CLIENT" \
  --data-urlencode "redirect_uri=$CONF_REDIRECT" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid" \
  --data-urlencode "state=si" \
  --data-urlencode "nonce=ni" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" \
  --data-urlencode "password=demo-password")
[ "$ST" = "401" ] && echo "user isolation across clients OK (401)"

echo "== 5. POST /authorize with correct credentials =="
CSRF=$(csrf_for "$AUTH_QUERY")
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" \
  --data-urlencode "password=demo-password")
echo "redirect: $LOC"
case "$LOC" in
  "$REDIRECT?code="*"&state=$STATE") echo "redirect with code+state OK" ;;
  *) echo "UNEXPECTED REDIRECT"; exit 1 ;;
esac
CODE=$(printf '%s' "$LOC" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')

echo "== 6. redeem code WITHOUT verifier (must fail) =="
# use a fresh code to avoid burning $CODE
CSRF=$(csrf_for "client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=s2&nonce=n2&code_challenge=$CHALLENGE&code_challenge_method=S256")
LOC2=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "state=s2" --data-urlencode "nonce=n2" \
  --data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" --data-urlencode "password=demo-password")
CODE2=$(printf '%s' "$LOC2" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=authorization_code&code=$CODE2&client_id=$CLIENT&redirect_uri=$REDIRECT")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('PKCE missing verifier rejected:', d['error'])
"

echo "== 7. redeem code WITH verifier =="
TOK=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$VERIFIER")
echo "$TOK" | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
for k in ('access_token','id_token','refresh_token','token_type','expires_in','scope'):
    assert k in d, k
assert d['token_type']=='Bearer'
def claims(t):
    p=t.split('.')[1]
    p+='='*(-len(p)%4)
    return json.loads(base64.urlsafe_b64decode(p))
def typ(t):
    h=t.split('.')[0]
    h+='='*(-len(h)%4)
    return json.loads(base64.urlsafe_b64decode(h))['typ']
ac=claims(d['access_token']); ic=claims(d['id_token'])
assert ac['iss']=='$BASE' and ic['iss']=='$BASE'
assert ac['aud']==['$CLIENT'] and ic['aud']==['$CLIENT']
assert ac['sub']=='demo' and ic['sub']=='demo'
assert ic['nonce']=='$NONCE', ic['nonce']
assert typ(d['access_token'])=='at+jwt', 'access token must carry the RFC 9068 typ header'
assert typ(d['id_token'])=='JWT', 'id token must carry typ JWT'
assert ac['email']=='demo@example.com', ac.get('email')
assert ac['roles']==['user'] and ic['roles']==['user'], 'roles must be released on both tokens when set'
print('access+id token claims OK (iss/aud/sub/nonce/typ/scope/roles claims)')
print('refresh token present, scope =', d['scope'])
"
REFRESH=$(printf '%s' "$TOK" | python3 -c "import json,sys;print(json.load(sys.stdin)['refresh_token'])")

echo "== 8. reuse the SAME code again (must fail, single-use) =="
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT&redirect_uri=$REDIRECT" --data-urlencode "code_verifier=$VERIFIER")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('code replay rejected OK')
"

echo "== 9. refresh token grant =="
TOK2=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT")
echo "$TOK2" | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
assert 'access_token' in d and 'refresh_token' in d and 'id_token' in d
p=d['id_token'].split('.')[1]; p+='='*(-len(p)%4)
ic=json.loads(base64.urlsafe_b64decode(p))
assert ic['sub']=='demo' and ic['nonce']=='$NONCE'
print('refresh grant OK, rotated refresh token issued, nonce preserved')
"
NEWREFRESH=$(printf '%s' "$TOK2" | python3 -c "import json,sys;print(json.load(sys.stdin)['refresh_token'])")

echo "== 10. refresh token reuse detection (family revocation) =="
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('replayed refresh token rejected OK')
"
# RFC 9700 §4.14.2: replaying a consumed refresh token is treated as theft —
# the whole family (including the legitimately rotated NEWREFRESH) is revoked.
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=$NEWREFRESH&client_id=$CLIENT")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('reuse detected: whole token family revoked OK')
"

echo "== 10b. unknown client_id cannot redeem or refresh =="
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=anything&client_id=other-app")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('unknown client at /token rejected OK')
"

echo "== 10c. cross-client code redemption (theft signal) =="
V4=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
C4=$(printf '%s' "$V4" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
CSRF=$(csrf_for "client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=s5&nonce=n5&code_challenge=$C4&code_challenge_method=S256")
LOC5=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "state=s5" --data-urlencode "nonce=n5" \
  --data-urlencode "code_challenge=$C4" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" --data-urlencode "password=demo-password")
CODE5=$(printf '%s' "$LOC5" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
# conf-app authenticates CORRECTLY but presents demo-app's code.
RESP=$(curl -s -u "$CONF_CLIENT:$CONF_SECRET" -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE5&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$V4")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('cross-client code redemption rejected OK (invalid_grant)')
"
# The burned code cannot be replayed by anyone.
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=authorization_code&code=$CODE5&client_id=$CLIENT&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$V4")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('code burned by the foreign redemption attempt OK')
"

echo "== 11. userinfo with a fresh token set =="
# A fresh login: the replay above killed the previous family on purpose.
V3=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
C3=$(printf '%s' "$V3" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
CSRF=$(csrf_for "client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid%20profile&state=s3&nonce=n3&code_challenge=$C3&code_challenge_method=S256")
LOC3=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid profile" \
  --data-urlencode "state=s3" --data-urlencode "nonce=n3" \
  --data-urlencode "code_challenge=$C3" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" --data-urlencode "password=demo-password")
CODE3=$(printf '%s' "$LOC3" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
TOK3=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE3&client_id=$CLIENT&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$V3")
AT=$(printf '%s' "$TOK3" | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
REFRESH3=$(printf '%s' "$TOK3" | python3 -c "import json,sys;print(json.load(sys.stdin)['refresh_token'])")
IDTOK3=$(printf '%s' "$TOK3" | python3 -c "import json,sys;print(json.load(sys.stdin)['id_token'])")
curl -s -H "Authorization: Bearer $AT" "$BASE/userinfo" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['sub']=='demo' and d['preferred_username']=='demo', d
assert 'email' not in d, 'email must not be released without the email scope'
print('userinfo OK (profile scope):', d['sub'])
"
# The id_token must NOT work as a bearer access token (typ profile separation).
ST=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $IDTOK3" "$BASE/userinfo")
[ "$ST" = "401" ] && echo "id_token rejected as access token OK"

echo "== 12. userinfo with garbage token (must 401) =="
curl -s -o /dev/null -w 'userinfo bad token -> %{http_code}\n' -H "Authorization: Bearer garbage" "$BASE/userinfo"

echo "== 13. introspect + revocation require client auth (confidential client registered) =="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/introspect" -d "token=$AT")
[ "$ST" = "401" ] && echo "introspect without client auth rejected (401) OK"
ST=$(curl -s -o /dev/null -w '%{http_code}' -u "$CONF_CLIENT:wrong-secret" -X POST "$BASE/introspect" -d "token=$AT")
[ "$ST" = "401" ] && echo "introspect with wrong secret rejected (401) OK"
curl -s -u "$CONF_CLIENT:$CONF_SECRET" -X POST "$BASE/introspect" -d "token=$AT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['active'] is True and d['sub']=='demo', d
assert d['aud']==['$CLIENT'], d
print('introspect with conf-app credentials OK (active)')
"
# Logout with the id_token_hint revokes the whole authorization: the access
# token is denied by jti and the refresh token is deleted.
curl -s -o /dev/null -w 'end_session with id_token_hint -> %{http_code}\n' \
  "$BASE/end_session?id_token_hint=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$IDTOK3")"
curl -s -H "Authorization: Bearer $AT" "$BASE/userinfo" -o /dev/null -w 'userinfo after logout -> %{http_code}\n' | grep -q 401 \
  && echo "access token denied after logout OK"
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=$REFRESH3&client_id=$CLIENT")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('refresh token revoked by logout OK')
"
# /revoke with an access token denies it immediately (client auth required).
LOC4=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$(csrf_for "client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=s4&nonce=n4&code_challenge=$C3&code_challenge_method=S256")" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "state=s4" --data-urlencode "nonce=n4" \
  --data-urlencode "code_challenge=$C3" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=demo" --data-urlencode "password=demo-password")
CODE4=$(printf '%s' "$LOC4" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
AT4=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE4&client_id=$CLIENT&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$V3" | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/revoke" -d "token=$AT4")
[ "$ST" = "401" ] && echo "revoke without client auth rejected (401) OK"
curl -s -u "$CONF_CLIENT:$CONF_SECRET" -X POST "$BASE/revoke" -d "token=$AT4" -o /dev/null -w 'revoke access token -> %{http_code}\n'
curl -s -H "Authorization: Bearer $AT4" "$BASE/userinfo" -o /dev/null -w 'userinfo after revoke -> %{http_code}\n' | grep -q 401 \
  && echo "revoked access token rejected OK"

echo "== 14. CORS preflight on /token =="
curl -s -o /dev/null -X OPTIONS "$BASE/token" \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type" \
  -D - | grep -i "access-control-allow-origin: http://localhost:3000" && echo "CORS OK"

echo "== 15. landing page + login page styling =="
curl -s "$BASE/" | grep -q 'href="/login.css"' && echo "landing links themed css"
curl -s "$BASE/login.css" | grep -Eqi -- '--accent:[[:space:]]*#0d8570;' && echo "Deep Water theme css served"
curl -s "$BASE/logo.svg" | grep -qi '<svg' && echo "logo served"

echo "== 16. security headers =="
curl -s -o /dev/null -D - "$BASE/" | grep -i "x-frame-options: DENY" >/dev/null \
  && curl -s -o /dev/null -D - "$BASE/" | grep -i "content-security-policy:.*frame-ancestors 'none'" >/dev/null \
  && echo "security headers OK"

echo "== 17. CSRF-protected login + token responses not cacheable =="
curl -s -b "$JAR" -o /dev/null -w 'POST /authorize without CSRF token -> %{http_code}\n' -X POST "$BASE/authorize" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "username=demo" --data-urlencode "password=demo-password" \
  | grep -q "400" && echo "login without CSRF token rejected OK"
curl -s -D - -o /dev/null -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=x&client_id=$CLIENT" \
  | grep -qi "cache-control: no-store" && echo "token response Cache-Control: no-store OK"

echo "== 18. confidential client flow: no PKCE, client_secret_basic/post =="
# Confidential clients may authorize WITHOUT PKCE.
QC="client_id=$CONF_CLIENT&redirect_uri=$CONF_REDIRECT&response_type=code&scope=openid%20profile&state=sC&nonce=nC"
CSRFC=$(csrf_for "$QC")
LOCC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRFC" --data-urlencode "client_id=$CONF_CLIENT" \
  --data-urlencode "redirect_uri=$CONF_REDIRECT" --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid profile" --data-urlencode "state=sC" --data-urlencode "nonce=nC" \
  --data-urlencode "username=bob" --data-urlencode "password=builder")
CODEC=$(printf '%s' "$LOCC" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
echo "authorize without PKCE OK (code issued)"

# Without client credentials (and without client_id) the request is missing a
# required parameter — and the code must survive the failed attempt.
RESPC=$(curl -s -X POST "$BASE/token" -d "grant_type=authorization_code&code=$CODEC&redirect_uri=$CONF_REDIRECT")
printf '%s' "$RESPC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_request', d
print('missing client_id answered invalid_request:', d['error'])
"
# With HTTP Basic credentials the code redeems, without any code_verifier.
TOKC=$(curl -s -u "$CONF_CLIENT:$CONF_SECRET" -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODEC&redirect_uri=$CONF_REDIRECT")
printf '%s' "$TOKC" | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
def claims(t):
    p=t.split('.')[1]; p+='='*(-len(p)%4)
    return json.loads(base64.urlsafe_b64decode(p))
def typ(t):
    h=t.split('.')[0]; h+='='*(-len(h)%4)
    return json.loads(base64.urlsafe_b64decode(h))['typ']
ac=claims(d['access_token']); ic=claims(d['id_token'])
assert ac['sub']=='bob', ac
assert ac['aud']==['conf-app'] and ic['aud']==['conf-app'], 'conf-app audience by default'
assert typ(d['access_token'])=='at+jwt', typ
print('confidential code grant with client_secret_basic OK (no PKCE needed)')
"
REFRESHC=$(printf '%s' "$TOKC" | python3 -c "import json,sys;print(json.load(sys.stdin)['refresh_token'])")

# RFC 6749 §6: refreshing also requires client authentication.
RC1=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/token" \
  -d "grant_type=refresh_token&refresh_token=$REFRESHC")
[ "$RC1" = "400" ] && echo "refresh without client_id rejected (400) OK"
RC2=$(curl -s -u "$CONF_CLIENT:wrong-secret" -o /dev/null -w '%{http_code}' -X POST "$BASE/token" \
  -d "grant_type=refresh_token&refresh_token=$REFRESHC")
[ "$RC2" = "401" ] && echo "refresh with wrong secret rejected (401) OK"
# The failed attempts must not have consumed the token.
curl -s -u "$CONF_CLIENT:$CONF_SECRET" -X POST "$BASE/token" \
  -d "grant_type=refresh_token&refresh_token=$REFRESHC" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert 'access_token' in d and 'refresh_token' in d, d
print('refresh with correct secret OK (rotation, family intact)')
"

echo "== 19. clientctl round trip =="
CFILE2="$WORKDIR/clients2.json"
"$CTL" client add -file "$CFILE2" -client spa -type public -redirect https://spa.example.com/cb >/dev/null
"$CTL" user add -file "$CFILE2" -client spa -username alice -password wonderland -email alice@wonderland.example -roles user,auditor >/dev/null
"$CTL" client list -file "$CFILE2" | grep -q "^spa" && echo "tool: client added and listed"
"$CTL" user list -file "$CFILE2" -client spa | grep -q "^alice.*roles: user,auditor" && echo "tool: users added and listed"
"$CTL" client update -file "$CFILE2" -client spa -audience spa-aud >/dev/null && echo "tool: audience updated"
"$CTL" user update -file "$CFILE2" -client spa -username alice -roles user >/dev/null && echo "tool: roles updated"
"$CTL" user update -file "$CFILE2" -client spa -username alice -password - <<< "builder2" >/dev/null && echo "tool: password updated via stdin"
"$CTL" user remove -file "$CFILE2" -client spa -username alice >/dev/null && echo "tool: user removed"
"$CTL" client remove -file "$CFILE2" -client spa >/dev/null && echo "tool: client removed"
# The tool must not print secrets or hashes.
if "$CTL" client show -file "$CFILE" -client "$CONF_CLIENT" | grep -q "$CONF_SECRET"; then
  echo "UNEXPECTED: client show leaked the client secret"; exit 1
fi
echo "tool: secrets never printed OK"

echo "== 20. fail-fast startup checks =="
# A removed single-client variable must abort startup loudly.
if IDP_CLIENT_ID=demo-app IDP_CLIENTS_FILE="$CFILE" "$WORKDIR/minidp" >"$WORKDIR/reject.log" 2>&1; then
  echo "UNEXPECTED: startup succeeded with IDP_CLIENT_ID set"; exit 1
fi
grep -q "no longer supported" "$WORKDIR/reject.log" && echo "removed env var rejected OK"
# A missing or empty clients file must abort startup.
if IDP_CLIENTS_FILE="$WORKDIR/missing.json" "$WORKDIR/minidp" >"$WORKDIR/missing.log" 2>&1; then
  echo "UNEXPECTED: startup succeeded without a clients file"; exit 1
fi
if grep -q "read clients file" "$WORKDIR/missing.log"; then
  echo "missing clients file rejected OK"
else
  echo "UNEXPECTED: missing-file error not reported"; exit 1
fi
echo "[]" > "$WORKDIR/empty.json"
if IDP_CLIENTS_FILE="$WORKDIR/empty.json" "$WORKDIR/minidp" >"$WORKDIR/empty.log" 2>&1; then
  echo "UNEXPECTED: startup succeeded with an empty clients file"; exit 1
fi
grep -q "contains no clients" "$WORKDIR/empty.log" && echo "empty clients file rejected OK"

echo
echo "ALL CHECKS PASSED"
