#!/bin/bash
# End-to-end smoke test for minidp: full public-client PKCE flow.
set -euo pipefail

BASE="http://localhost:8099"
CLIENT="rego-adventure"
REDIRECT="http://localhost:3000/callback"
VERIFIER=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
STATE="st-123"
NONCE="n-abc"
JAR=$(mktemp)

# Extract a fresh CSRF token from the rendered login form for the given
# authorization request parameters.
csrf_for() {
  curl -s -c "$JAR" "$BASE/authorize?$1" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p'
}

AUTH_QUERY="client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid%20profile&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"

echo "== 1. discovery =="
curl -s "$BASE/.well-known/openid-configuration" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['issuer']=='$BASE', d['issuer']
for k in ('authorization_endpoint','token_endpoint','jwks_uri','userinfo_endpoint'):
    assert k in d, k
print('issuer:', d['issuer'])
print('grant_types:', d['grant_types_supported'])
print('pkce methods:', d['code_challenge_methods_supported'])
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
curl -s -c "$JAR" "$BASE/authorize?client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid%20profile&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256" -o /tmp/login.html
grep -q 'name="code_challenge" value="'$CHALLENGE'"' /tmp/login.html && echo "PKCE challenge echoed into form"
grep -q 'name="nonce" value="'$NONCE'"' /tmp/login.html && echo "nonce echoed into form"

echo "== 4. POST /authorize with WRONG password =="
CSRF=$(csrf_for "$AUTH_QUERY")
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=rego" \
  --data-urlencode "password=wrongpass")
[ "$LOC" = "401" ] && echo "wrong password rejected (401) OK"

echo "== 5. POST /authorize with correct credentials =="
CSRF=$(csrf_for "$AUTH_QUERY")
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "state=$STATE" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=rego" \
  --data-urlencode "password=adventure")
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
  --data-urlencode "username=rego" --data-urlencode "password=adventure")
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
ac=claims(d['access_token']); ic=claims(d['id_token'])
assert ac['iss']=='$BASE' and ic['iss']=='$BASE'
assert ac['aud']==['$CLIENT'] and ic['aud']==['$CLIENT']
assert ac['sub']=='rego' and ic['sub']=='rego'
assert ic['nonce']=='$NONCE', ic['nonce']
print('access+id token claims OK (iss/aud/sub/nonce)')
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
assert ic['sub']=='rego' and ic['nonce']=='$NONCE'
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

echo "== 11. userinfo with a fresh token set =="
# A fresh login: the replay above killed the previous family on purpose.
V3=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
C3=$(printf '%s' "$V3" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
CSRF=$(csrf_for "client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=s3&nonce=n3&code_challenge=$C3&code_challenge_method=S256")
LOC3=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "state=s3" --data-urlencode "nonce=n3" \
  --data-urlencode "code_challenge=$C3" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=rego" --data-urlencode "password=adventure")
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
assert d['sub']=='rego' and d['preferred_username']=='rego', d
print('userinfo OK:', d['sub'])
"

echo "== 12. userinfo with garbage token (must 401) =="
curl -s -o /dev/null -w 'userinfo bad token -> %{http_code}\n' -H "Authorization: Bearer garbage" "$BASE/userinfo"

echo "== 13. introspect + revocation + logout =="
curl -s -X POST "$BASE/introspect" -d "token=$AT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['active'] is True and d['sub']=='rego', d
print('introspect OK (active)')
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
# /revoke with an access token denies it immediately.
LOC4=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
  --data-urlencode "csrf_token=$(csrf_for "client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=s4&nonce=n4&code_challenge=$C3&code_challenge_method=S256")" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "response_type=code" --data-urlencode "scope=openid" \
  --data-urlencode "state=s4" --data-urlencode "nonce=n4" \
  --data-urlencode "code_challenge=$C3" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=rego" --data-urlencode "password=adventure")
CODE4=$(printf '%s' "$LOC4" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
AT4=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=authorization_code&code=$CODE4&client_id=$CLIENT&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$V3" | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
curl -s -X POST "$BASE/revoke" -d "token=$AT4" -o /dev/null -w 'revoke access token -> %{http_code}\n'
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
curl -s "$BASE/login.css" | grep -q -- '--accent-color: #c77d00' && echo "rego-adventure theme css served"
curl -s "$BASE/logo.svg" | grep -qi '<svg' && echo "logo served"

echo "== 16. security headers =="
curl -s -o /dev/null -D - "$BASE/" | grep -i "x-frame-options: DENY" >/dev/null \
  && curl -s -o /dev/null -D - "$BASE/" | grep -i "content-security-policy:.*frame-ancestors 'none'" >/dev/null \
  && echo "security headers OK"

echo "== 17. CSRF-protected login =="
curl -s -b "$JAR" -o /dev/null -w 'POST /authorize without CSRF token -> %{http_code}\n' -X POST "$BASE/authorize" \
  --data-urlencode "client_id=$CLIENT" --data-urlencode "username=rego" --data-urlencode "password=adventure" \
  | grep -q "400" && echo "login without CSRF token rejected OK"

echo "== 18. multi-user mode (users file + minidp-users tool) =="
TOOL=/tmp/minidp-users
go build -o "$TOOL" ./cmd/minidp-users
# The multi-user section starts its own IdP instance; build the server next to
# the tool so the section works on a fresh checkout that only followed the
# README (which builds into the repo directory, not /tmp).
go build -o /tmp/minidp .
UFILE="$(mktemp -d)/users.json"
"$TOOL" add -file "$UFILE" -username alice -password wonderland -email alice@wonderland.example >/dev/null
"$TOOL" add -file "$UFILE" -username bob -password builder >/dev/null
"$TOOL" list -file "$UFILE" | grep -q "^alice" && echo "tool: users added and listed"
"$TOOL" update -file "$UFILE" -username bob -password builder2 >/dev/null && echo "tool: password updated"
"$TOOL" remove -file "$UFILE" -username bob >/dev/null && echo "tool: user removed"

IDP_PORT=8098 IDP_ISSUER=http://localhost:8098 IDP_USERS_FILE="$UFILE" /tmp/minidp &
MINIDP2_PID=$!
sleep 1

BASE2="http://localhost:8098"
V2=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
C2=$(printf '%s' "$V2" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n')
Q2="client_id=$CLIENT&redirect_uri=$REDIRECT&response_type=code&scope=openid&state=s9&nonce=n9&code_challenge=$C2&code_challenge_method=S256"
JAR2=$(mktemp)
CSRF2=$(curl -s -c "$JAR2" "$BASE2/authorize?$Q2" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
LOC9=$(curl -s -b "$JAR2" -o /dev/null -w '%{redirect_url}' -X POST "$BASE2/authorize" \
  --data-urlencode "csrf_token=$CSRF2" --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid" --data-urlencode "state=s9" --data-urlencode "nonce=n9" \
  --data-urlencode "code_challenge=$C2" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=alice" --data-urlencode "password=wonderland")
CODE9=$(printf '%s' "$LOC9" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
TOK9=$(curl -s -X POST "$BASE2/token" \
  -d "grant_type=authorization_code&code=$CODE9&client_id=$CLIENT&redirect_uri=$REDIRECT" \
  --data-urlencode "code_verifier=$V2")
printf '%s' "$TOK9" | python3 -c "
import json,sys,base64
d=json.load(sys.stdin)
def claims(t):
    p=t.split('.')[1]; p+='='*(-len(p)%4)
    return json.loads(base64.urlsafe_b64decode(p))
ac=claims(d['access_token']); ic=claims(d['id_token'])
assert ac['sub']=='alice' and ic['sub']=='alice', (ac['sub'], ic['sub'])
assert ic['email']=='alice@wonderland.example', ic['email']
print('multi-user: alice logged in, sub/email claims correct')
"

# The former single-user demo credentials must not work in multi-user mode.
CSRF3=$(curl -s -c "$JAR2" "$BASE2/authorize?$Q2" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p')
ST9=$(curl -s -b "$JAR2" -o /dev/null -w '%{http_code}' -X POST "$BASE2/authorize" \
  --data-urlencode "csrf_token=$CSRF3" --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "response_type=code" \
  --data-urlencode "scope=openid" --data-urlencode "state=s9" --data-urlencode "nonce=n9" \
  --data-urlencode "code_challenge=$C2" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "username=rego" --data-urlencode "password=adventure")
if [ "$ST9" != "401" ]; then
  echo "UNEXPECTED: rego/adventure in multi-user mode -> $ST9 (want 401)"; exit 1
fi
echo "multi-user: rego/adventure rejected OK"
kill "$MINIDP2_PID" 2>/dev/null

echo
echo "ALL CHECKS PASSED"
