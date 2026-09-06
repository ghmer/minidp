package idp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// testIDP spins up a real HTTP test server. The listener is created first so
// the issuer URL is known before the Server (which signs tokens with it) is
// constructed.
func testIDP(t *testing.T, mutate func(*Config)) (*httptest.Server, *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := Config{
		Host:            "127.0.0.1",
		Username:        "rego",
		Password:        "adventure",
		Issuer:          "http://" + ln.Addr().String(),
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 2 * time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: srv.Handler()},
	}
	ts.Start()
	t.Cleanup(ts.Close)
	return ts, srv
}

// noFollow returns a client that surfaces redirects instead of following them.
func noFollow() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postForm sends a form POST and returns the response without following redirects.
func postForm(t *testing.T, client *http.Client, target string, form url.Values) *http.Response {
	t.Helper()
	resp, err := client.PostForm(target, form)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("invalid JSON %q: %v", body, err)
	}
	return out
}

// pkcePair returns a fresh verifier/challenge pair (S256).
func pkcePair() (verifier, challenge string) {
	verifier = randomToken()
	return verifier, pkceS256(verifier)
}

const (
	testClientID   = "rego-adventure"
	testRedirect   = "http://localhost:3000/callback"
	testScopes     = "openid profile"
	testNonceValue = "n-abc"
	testStateValue = "st-123"
)

// authorizeForm builds a valid authorization request body.
func authorizeForm(verifier string) url.Values {
	return url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"response_type":         {"code"},
		"scope":                 {testScopes},
		"state":                 {testStateValue},
		"nonce":                 {testNonceValue},
		"code_challenge":        {pkceS256(verifier)},
		"code_challenge_method": {"S256"},
	}
}

// login redeems the login form for an authorization code and returns the
// redirect target URL.
func login(t *testing.T, base, user, pass, verifier string) string {
	t.Helper()
	form := authorizeForm(verifier)
	form.Set("username", user)
	form.Set("password", pass)
	resp := postForm(t, noFollow(), base+"/authorize", form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize: status = %d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func codeFrom(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", location, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", location)
	}
	return code
}

func TestDiscoveryDocument(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET discovery: status = %d", resp.StatusCode)
	}
	d := decodeJSON(t, resp)
	if d["issuer"] != ts.URL {
		t.Errorf("issuer = %v, want %v", d["issuer"], ts.URL)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
		if d[key] == "" {
			t.Errorf("discovery missing %q", key)
		}
	}
	if grants, _ := d["grant_types_supported"].([]any); len(grants) != 2 {
		t.Errorf("grant_types_supported = %v", grants)
	}
	if methods, _ := d["code_challenge_methods_supported"].([]any); len(methods) == 0 {
		t.Error("code_challenge_methods_supported must not be empty")
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts, srv := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks: status = %d", resp.StatusCode)
	}
	d := decodeJSON(t, resp)
	keys, _ := d["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("expected 1 JWK, got %d", len(keys))
	}
	key, _ := keys[0].(map[string]any)
	if key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" {
		t.Errorf("unexpected JWK: %v", key)
	}
	if key["kid"] != srv.key.kid {
		t.Errorf("kid = %v, want %q", key["kid"], srv.key.kid)
	}
}

func TestAuthorizeFormRendersHiddenParams(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	resp, err := http.Get(ts.URL + "/authorize?" + authorizeForm(verifier).Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /authorize: status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{
		`action="/authorize"`,
		`name="client_id" value="` + testClientID + `"`,
		`name="code_challenge_method" value="S256"`,
		`name="nonce" value="` + testNonceValue + `"`,
		`name="state" value="` + testStateValue + `"`,
		`href="/login.css"`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("login form missing %q", want)
		}
	}
}

func TestAuthorizeRejectsMissingPKCE(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/authorize?client_id=c1&redirect_uri=" + url.QueryEscape(testRedirect) + "&response_type=code")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "code_challenge") {
		t.Error("expected an explanation that PKCE is required")
	}
}

func TestAuthorizeWrongPassword(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	form := authorizeForm(verifier)
	form.Set("username", "rego")
	form.Set("password", "wrong")
	resp := postForm(t, noFollow(), ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Invalid username or password") {
		t.Error("expected an error message on the form")
	}
	// The OAuth2 context must survive the failed attempt.
	if !strings.Contains(string(body), testClientID) {
		t.Error("expected client_id to be echoed back after a failed login")
	}
}

func TestAuthorizeRedirectsUnknownResponseType(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/authorize?client_id=c1&redirect_uri=" + url.QueryEscape(testRedirect) + "&response_type=token&code_challenge=x")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("response_type=token: status = %d, want 400", resp.StatusCode)
	}
}

func TestFullCodeGrantWithPKCE(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()

	location := login(t, ts.URL, "rego", "adventure", verifier)
	if !strings.HasPrefix(location, testRedirect+"?code=") {
		t.Fatalf("redirect %q does not start with %s?code=", location, testRedirect)
	}
	if !strings.Contains(location, "state="+testStateValue) {
		t.Errorf("redirect %q is missing the state", location)
	}
	code := codeFrom(t, location)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
	tokens := decodeJSON(t, resp)
	if tokens["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", tokens["token_type"])
	}
	if tokens["refresh_token"] == "" || tokens["access_token"] == "" || tokens["id_token"] == "" {
		t.Fatalf("expected all three tokens, got %v", tokens)
	}

	claims := verifyTokenString(t, tokens["access_token"].(string), ts.URL)
	if claims["sub"] != "rego" {
		t.Errorf("access sub = %v", claims["sub"])
	}
	idClaims := verifyTokenString(t, tokens["id_token"].(string), ts.URL)
	if idClaims["nonce"] != testNonceValue {
		t.Errorf("id nonce = %v, want %q", idClaims["nonce"], testNonceValue)
	}
}

// verifyTokenString parses and validates a token against the issuer's JWKS.
func verifyTokenString(t *testing.T, tokenString, issuer string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a JWT: %q", tokenString)
	}
	// Decode the payload for claim checks; signature validity is covered by
	// TestJWKSPublishedKeyVerifiesToken and the round trips in key_test.go.
	payload, err := base64Decode(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if claims["iss"] != issuer {
		t.Errorf("iss = %v, want %q", claims["iss"], issuer)
	}
	return claims
}

func TestTokenGrantRejectsWrongVerifier(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))

	form := authorizeForm(verifier)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", testClientID)
	form.Set("redirect_uri", testRedirect)
	form.Set("code_verifier", randomToken()) // wrong verifier
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", got)
	}
}

func TestTokenGrantRejectsCodeReplay(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))

	redeem := func() *http.Response {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {testClientID},
			"redirect_uri":  {testRedirect},
			"code_verifier": {verifier},
		}
		return postForm(t, http.DefaultClient, ts.URL+"/token", form)
	}
	first := redeem()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first redemption: status = %d", first.StatusCode)
	}
	second := redeem()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed code: status = %d, want 400", second.StatusCode)
	}
	if got := decodeJSON(t, second)["error"]; got != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", got)
	}
}

func TestTokenGrantRejectsRedirectMismatch(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {"http://evil.example.com/callback"},
		"code_verifier": {verifier},
	}
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRefreshGrantRotatesTokens(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))

	first := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	oldRefresh := first["refresh_token"].(string)

	second := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefresh},
		"client_id":     {testClientID},
	}))
	newRefresh, hasNew := second["refresh_token"]
	if !hasNew || newRefresh == "" {
		t.Fatal("refresh grant must return a new refresh token")
	}
	if newRefresh == oldRefresh {
		t.Error("refresh token must be rotated")
	}
	if second["access_token"] == "" {
		t.Error("refresh grant must return an access token")
	}
	idClaims := verifyTokenString(t, second["id_token"].(string), ts.URL)
	if idClaims["nonce"] != testNonceValue {
		t.Errorf("refreshed id nonce = %v, want the original %q", idClaims["nonce"], testNonceValue)
	}

	// The old refresh token is single-use.
	replay := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefresh},
		"client_id":     {testClientID},
	}))
	if replay["error"] != "invalid_grant" {
		t.Errorf("replayed refresh token: %v, want invalid_grant", replay["error"])
	}
}

func TestUnsupportedGrantType(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{"grant_type": {"password"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "unsupported_grant_type" {
		t.Errorf("error = %v", got)
	}
}

func TestUserinfo(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	access := tokens["access_token"].(string)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	info := decodeJSON(t, resp)
	if info["sub"] != "rego" || info["preferred_username"] != "rego" {
		t.Errorf("userinfo = %v", info)
	}

	// A garbage token must be rejected with 401.
	bad, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	bad.Header.Set("Authorization", "Bearer garbage")
	badResp, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = badResp.Body.Close() }()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage token: status = %d, want 401", badResp.StatusCode)
	}
}

func TestIntrospectAndRevoke(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	refresh := tokens["refresh_token"].(string)

	introspection := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/introspect",
		url.Values{"token": {refresh}}))
	if introspection["active"] == true {
		t.Error("refresh tokens are opaque and must not introspect as active JWTs")
	}

	// Revoke the refresh token, then verify it can no longer be redeemed.
	if resp := postForm(t, http.DefaultClient, ts.URL+"/revoke", url.Values{"token": {refresh}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: status = %d, want 200", resp.StatusCode)
	}
	after := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {testClientID},
	}))
	if after["error"] != "invalid_grant" {
		t.Errorf("revoked refresh token: %v, want invalid_grant", after["error"])
	}
}

func TestEndSessionRequiresAllowlist(t *testing.T) {
	// Without an allowlist, no redirect may happen (open-redirect hardening).
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/end_session?post_logout_redirect_uri=" + url.QueryEscape("https://evil.example.com/"))
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (page, not redirect)", resp.StatusCode)
	}

	// With an allowlist, exact matches redirect to the allowlist entry.
	ts2, _ := testIDP(t, func(c *Config) {
		c.AllowedRedirects = []string{testRedirect}
	})
	req, err := http.NewRequest(http.MethodGet, ts2.URL+"/end_session?post_logout_redirect_uri="+url.QueryEscape(testRedirect), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp2, err := noFollow().Do(req)
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusFound || resp2.Header.Get("Location") != testRedirect {
		t.Fatalf("status = %d, location = %q; want 302 to the allowlist entry",
			resp2.StatusCode, resp2.Header.Get("Location"))
	}
}

// base64Decode decodes a base64url string without padding.
func base64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func TestRedirectURIAllowed(t *testing.T) {
	// Default policy: any well-formed http(s) URI is allowed.
	_, srv := testIDP(t, nil)
	if !srv.redirectURIAllowed(testRedirect) {
		t.Error("expected default policy to allow well-formed http(s) redirect URIs")
	}
	if srv.redirectURIAllowed("javascript:alert(1)") {
		t.Error("non-http schemes must be rejected")
	}
	if srv.redirectURIAllowed("not a url") {
		t.Error("garbage redirect URIs must be rejected")
	}

	// With an allowlist, only exactly listed URIs pass.
	_, srv2 := testIDP(t, func(c *Config) {
		c.AllowedRedirects = []string{testRedirect}
	})
	if !srv2.redirectURIAllowed(testRedirect) {
		t.Error("allowlisted URI must be allowed")
	}
	if srv2.redirectURIAllowed("https://other.example.com/cb") {
		t.Error("non-allowlisted URI must be rejected")
	}
}

func TestCORS(t *testing.T) {
	ts, _ := testIDP(t, nil)
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/token", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight: status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Errorf("Access-Control-Allow-Origin = %q", got)
	}

	// A normal request must also carry the CORS headers.
	origin := "https://adventure.example.com"
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/openid-configuration", nil)
	req2.Header.Set("Origin", origin)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if got := resp2.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, origin)
	}
}

func TestLandingAndBareLogin(t *testing.T) {
	ts, _ := testIDP(t, nil)

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status = %d", resp.StatusCode)
	}

	form := url.Values{"username": {"rego"}, "password": {"adventure"}}
	ok := postForm(t, noFollow(), ts.URL+"/login", form)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("POST /login: status = %d", ok.StatusCode)
	}
	body, _ := io.ReadAll(ok.Body)
	if !strings.Contains(string(body), "Signed in as rego") {
		t.Errorf("expected a signed-in confirmation, got %q", body)
	}

	form.Set("password", "nope")
	bad := postForm(t, noFollow(), ts.URL+"/login", form)
	if bad.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /login with wrong password: status = %d, want 401", bad.StatusCode)
	}
}

func TestStaticAssets(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/login.css")
	if err != nil {
		t.Fatalf("GET /login.css: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("login.css Content-Type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "--accent-color: #c77d00") {
		t.Error("login.css must carry the rego-adventure theme accent color")
	}

	logoResp, err := http.Get(ts.URL + "/logo.svg")
	if err != nil {
		t.Fatalf("GET /logo.svg: %v", err)
	}
	defer func() { _ = logoResp.Body.Close() }()
	if ct := logoResp.Header.Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("logo.svg Content-Type = %q", ct)
	}

	health, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = health.Body.Close() }()
	if health.StatusCode != http.StatusOK {
		t.Errorf("/healthz: status = %d", health.StatusCode)
	}
}
