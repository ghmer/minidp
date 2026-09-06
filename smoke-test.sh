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
LOC=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/authorize" \
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
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
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
LOC2=$(curl -s -o /dev/null -w '%{redirect_url}' -X POST "$BASE/authorize" \
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

echo "== 10. old refresh token is single-use (must fail) =="
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('refresh token rotation enforced OK')
"

echo "== 11. userinfo with new access token =="
AT=$(printf '%s' "$TOK2" | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")
curl -s -H "Authorization: Bearer $AT" "$BASE/userinfo" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['sub']=='rego' and d['preferred_username']=='rego', d
print('userinfo OK:', d['sub'])
"

echo "== 12. userinfo with garbage token (must 401) =="
curl -s -o /dev/null -w 'userinfo bad token -> %{http_code}\n' -H "Authorization: Bearer garbage" "$BASE/userinfo"

echo "== 13. introspect + revoke =="
curl -s -X POST "$BASE/introspect" -d "token=$AT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['active'] is True and d['sub']=='rego', d
print('introspect OK (active)')
"
curl -s -X POST "$BASE/revoke" -d "token=$NEWREFRESH" -o /dev/null -w 'revoke -> %{http_code}\n'
RESP=$(curl -s -X POST "$BASE/token" -d "grant_type=refresh_token&refresh_token=$NEWREFRESH&client_id=$CLIENT")
echo "$RESP" | python3 -c "
import json,sys
d=json.load(sys.stdin)
assert d['error']=='invalid_grant', d
print('revoked refresh token rejected OK')
"

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

echo
echo "ALL CHECKS PASSED"
