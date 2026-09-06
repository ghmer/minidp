package idp

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
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
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, base+"/authorize", authorizeForm(verifier)))
	resp := postForm(t, browser, base+"/authorize", form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize: status = %d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

var csrfFieldRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// newBrowser returns a client that behaves like a browser for the login flow:
// it stores cookies (the CSRF nonce) and surfaces redirects instead of
// following them.
func newBrowser() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// fetchCSRF renders the login page at target (query built from form) and
// extracts the signed CSRF token from the form. The client must be reused for
// the subsequent POST so the nonce cookie round-trips.
func fetchCSRF(t *testing.T, client *http.Client, target string, form url.Values) string {
	t.Helper()
	resp, err := client.Get(target + "?" + form.Encode())
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d", target, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	m := csrfFieldRe.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("no csrf_token in login form from %s", target)
	}
	return m[1]
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
		`name="csrf_token"`,
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

// TestAuthorizeRejectsPlainPKCE pins the RFC 9700 requirement: only S256 is
// accepted, both at authorization and (defensively) at token verification.
func TestAuthorizeRejectsPlainPKCE(t *testing.T) {
	ts, _ := testIDP(t, nil)
	for _, method := range []string{"plain", "", "s256"} {
		target := ts.URL + "/authorize?client_id=c1&redirect_uri=" + url.QueryEscape(testRedirect) +
			"&response_type=code&code_challenge=abc&code_challenge_method=" + url.QueryEscape(method)
		resp, err := http.Get(target)
		if err != nil {
			t.Fatalf("GET /authorize (method=%q): %v", method, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("method=%q: status = %d, want 400", method, resp.StatusCode)
		}
		if !strings.Contains(string(body), "S256") {
			t.Errorf("method=%q: expected an explanation mentioning S256", method)
		}
	}

	// Defense in depth: a stored plain challenge must not verify either.
	if verifyPKCE("some-verifier", "plain", "some-verifier") {
		t.Error("verifyPKCE must reject the plain method")
	}
}

func TestAuthorizeWrongPassword(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	form := authorizeForm(verifier)
	form.Set("username", "rego")
	form.Set("password", "wrong")
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeForm(verifier)))
	resp := postForm(t, browser, ts.URL+"/authorize", form)
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

// TestTokenGrantRequiresClientIDAndRedirect pins RFC 6749 §4.1.3: the token
// request must repeat client_id and redirect_uri, not merely repeat them
// correctly when present.
func TestTokenGrantRequiresClientIDAndRedirect(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()

	// A fresh code per case: the code is consumed before parameter validation
	// fails, so reusing it would turn the second case into invalid_grant.
	freshCode := func() string {
		return codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))
	}

	// Missing client_id / redirect_uri -> invalid_request.
	for _, drop := range []string{"client_id", "redirect_uri"} {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {freshCode()},
			"client_id":     {testClientID},
			"redirect_uri":  {testRedirect},
			"code_verifier": {verifier},
		}
		form.Del(drop)
		resp := postForm(t, http.DefaultClient, ts.URL+"/token", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("without %s: status = %d, want 400", drop, resp.StatusCode)
		}
		if got := decodeJSON(t, resp)["error"]; got != "invalid_request" {
			t.Errorf("without %s: error = %v, want invalid_request", drop, got)
		}
	}

	// Missing client_id on the refresh grant -> invalid_request (RFC 6749 §6).
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type": {"refresh_token"},
	})
	if got := decodeJSON(t, resp)["error"]; got != "invalid_request" {
		t.Errorf("refresh without client_id: error = %v, want invalid_request", got)
	}
}

// TestRefreshReuseRevokesWholeFamily drives the RFC 9700 §4.14.2 behaviour
// end-to-end: replaying a rotated refresh token must invalidate every token
// derived from the same authorization, not just fail.
func TestRefreshReuseRevokesWholeFamily(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))

	redeemRefresh := func(token string) map[string]any {
		return decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
			"client_id":     {testClientID},
		}))
	}

	first := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	v1 := first["refresh_token"].(string)

	second := redeemRefresh(v1)
	v2 := second["refresh_token"].(string)
	if v2 == "" || v2 == v1 {
		t.Fatal("expected a rotated refresh token")
	}

	// The attacker replays the already-consumed v1.
	if got := redeemRefresh(v1)["error"]; got != "invalid_grant" {
		t.Fatalf("replay: error = %v, want invalid_grant", got)
	}
	// Reuse detection must have revoked the family: the legitimately rotated
	// v2 is dead too.
	if got := redeemRefresh(v2)["error"]; got != "invalid_grant" {
		t.Fatalf("descendant of a replayed chain: error = %v, want invalid_grant", got)
	}

	// client_id must match the refresh token's client (RFC 6749 §6).
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFrom(t, login(t, ts.URL, "rego", "adventure", verifier))},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	})
	fresh := decodeJSON(t, resp)["refresh_token"].(string)
	mismatch := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {fresh},
		"client_id":     {"other-client"},
	}))
	if mismatch["error"] != "invalid_grant" {
		t.Errorf("client_id mismatch: error = %v, want invalid_grant", mismatch["error"])
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
	// With a redirect allowlist, its hosts are credited as CORS origins.
	ts, _ := testIDP(t, func(c *Config) { c.AllowedRedirects = []string{testRedirect} })
	allowedOrigin := "http://localhost:3000" // derived from testRedirect
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/token", nil)
	req.Header.Set("Origin", allowedOrigin)
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
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}

	// A normal request from an allowed origin must also carry the CORS headers.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/openid-configuration", nil)
	req2.Header.Set("Origin", allowedOrigin)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if got := resp2.Header.Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
	}
}

// TestCORSRejectsArbitraryOrigins pins the review fix: an Origin that is not
// on the allowlist (redirect hosts + IDP_ALLOWED_ORIGINS) must never be
// reflected, let alone with credentials.
func TestCORSRejectsArbitraryOrigins(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) { c.AllowedRedirects = []string{testRedirect} })
	for _, origin := range []string{"https://evil.example.com", "http://localhost:3000.evil.com"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/openid-configuration", nil)
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET discovery with Origin %q: %v", origin, err)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q: Access-Control-Allow-Origin = %q, want no CORS grant", origin, got)
		}
		if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
			t.Errorf("origin %q: Access-Control-Allow-Credentials = %q, want unset", origin, got)
		}
		_ = resp.Body.Close()
	}

	// Without any allowlist, nothing is credited cross-origin.
	ts2, _ := testIDP(t, nil)
	req, _ := http.NewRequest(http.MethodGet, ts2.URL+"/healthz", nil)
	req.Header.Set("Origin", "https://adventure.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("no allowlist configured: Access-Control-Allow-Origin = %q, want unset", got)
	}
}

// TestCORSExplicitOrigins covers the IDP_ALLOWED_ORIGINS escape hatch for
// origins that have no corresponding redirect allowlist entry.
func TestCORSExplicitOrigins(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) { c.AllowedOrigins = []string{"https://spa.example.com"} })
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
	req.Header.Set("Origin", "https://spa.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://spa.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the explicit origin (trailing slash tolerated)", got)
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
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/", url.Values{}))
	ok := postForm(t, browser, ts.URL+"/login", form)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("POST /login: status = %d", ok.StatusCode)
	}
	body, _ := io.ReadAll(ok.Body)
	if !strings.Contains(string(body), "Signed in as rego") {
		t.Errorf("expected a signed-in confirmation, got %q", body)
	}

	form.Set("password", "nope")
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/", url.Values{}))
	bad := postForm(t, browser, ts.URL+"/login", form)
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

func TestAuthorizeRejectsInvalidCSRF(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	form := authorizeForm(verifier)
	form.Set("username", "rego")
	form.Set("password", "adventure")
	form.Set("csrf_token", "not-a-valid-token")
	resp := postForm(t, noFollow(), ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "session expired") {
		t.Error("expected an explanatory error message")
	}
}

func TestAuthorizeRejectsParamTampering(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	// Get a CSRF token bound to the legit parameters...
	form := authorizeForm(verifier)
	browser := newBrowser()
	token := fetchCSRF(t, browser, ts.URL+"/authorize", form)
	// ...then swap the redirect_uri behind the server's back.
	form.Set("redirect_uri", "http://evil.example.com/callback")
	form.Set("username", "rego")
	form.Set("password", "adventure")
	form.Set("csrf_token", token)
	resp := postForm(t, browser, ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered redirect_uri: status = %d, want 400", resp.StatusCode)
	}
}

// TestCSRFTokenRequiresBrowserNonce reproduces the cross-site attack from
// FINDINGS: an attacker pre-fetches a login form (and its CSRF token) for
// attacker-chosen OAuth parameters, then replays both against a victim's
// browser. The token must be rejected because the victim's browser does not
// carry the attacker's nonce cookie.
func TestCSRFTokenRequiresBrowserNonce(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()

	// The attacker fetches a valid form for their own parameters.
	attacker := newBrowser()
	attackerForm := authorizeForm(verifier)
	attackerForm.Set("redirect_uri", "http://evil.example.com/callback")
	token := fetchCSRF(t, attacker, ts.URL+"/authorize", attackerForm)

	submit := func(victim *http.Client) *http.Response {
		form := attackerForm
		form.Set("username", "rego")
		form.Set("password", "adventure")
		form.Set("csrf_token", token)
		return postForm(t, victim, ts.URL+"/authorize", form)
	}

	// Case 1: victim's browser has never visited the IdP (no cookie at all).
	if resp := submit(newBrowser()); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed token without nonce cookie: status = %d, want 400", resp.StatusCode)
	}

	// Case 2: victim's browser has its own legitimate nonce (mismatch).
	victim := newBrowser()
	fetchCSRF(t, victim, ts.URL+"/authorize", authorizeForm(verifier))
	if resp := submit(victim); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed token with mismatched nonce: status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeFormSetsNonceCookie(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) { c.Issuer = strings.Replace(c.Issuer, "http://", "https://", 1) })
	verifier, _ := pkcePair()
	resp, err := newBrowser().Get(ts.URL + "/authorize?" + authorizeForm(verifier).Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name != "minidp-login" {
			continue
		}
		found = true
		if !cookie.HttpOnly {
			t.Error("nonce cookie must be HttpOnly")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("nonce cookie SameSite = %v, want Lax", cookie.SameSite)
		}
		if !cookie.Secure {
			t.Error("nonce cookie must be Secure for an https issuer")
		}
	}
	if !found {
		t.Fatal("GET /authorize did not set the nonce cookie")
	}
}

func TestLoginRateLimiting(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) { c.LoginRateLimit = 2 })
	verifier, _ := pkcePair()

	browser := newBrowser()
	attempt := func() int {
		form := authorizeForm(verifier)
		form.Set("username", "rego")
		form.Set("password", "adventure")
		form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeForm(verifier)))
		resp := postForm(t, browser, ts.URL+"/authorize", form)
		return resp.StatusCode
	}
	if s := attempt(); s != http.StatusFound {
		t.Fatalf("attempt 1: status = %d, want 302", s)
	}
	if s := attempt(); s != http.StatusFound {
		t.Fatalf("attempt 2: status = %d, want 302", s)
	}
	if s := attempt(); s != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: status = %d, want 429", s)
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	for header, want := range map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
	} {
		if got := resp.Header.Get(header); got == "" || !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it set and containing %q", header, got, want)
		}
	}
}

func TestClientIPHonoursTrustedProxies(t *testing.T) {
	_, srv := testIDP(t, func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/8"} })

	r := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	r.RemoteAddr = "10.1.2.3:5555" // trusted proxy
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.1.2.3")
	if got := srv.clientIP(r); got != "203.0.113.7" {
		t.Errorf("trusted proxy: clientIP = %q, want the rightmost non-trusted forwarded address", got)
	}

	r = httptest.NewRequest(http.MethodPost, "/authorize", nil)
	r.RemoteAddr = "192.0.2.9:1234" // not a trusted proxy
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := srv.clientIP(r); got != "192.0.2.9" {
		t.Errorf("untrusted peer: clientIP = %q, want the socket address (no header spoofing)", got)
	}
}

// TestClientIPResistsSpoofedXFF pins the right-to-left walk: a proxy that
// APPENDS the real client address must defeat an attacker-supplied leftmost
// entry, otherwise rotating the spoofed value rotates the rate-limit key.
func TestClientIPResistsSpoofedXFF(t *testing.T) {
	_, srv := testIDP(t, func(c *Config) { c.TrustedProxies = []string{"10.0.0.0/8"} })

	// Attacker sends "6.6.6.6"; the trusted proxy appends the real client.
	r := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	r.RemoteAddr = "10.1.2.3:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.23")
	if got := srv.clientIP(r); got != "198.51.100.23" {
		t.Errorf("spoofed XFF chain: clientIP = %q, want the proxy-appended 198.51.100.23", got)
	}

	// A chain consisting solely of trusted proxies yields the socket peer.
	r2 := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	r2.RemoteAddr = "10.1.2.3:5555"
	r2.Header.Set("X-Forwarded-For", "10.9.9.9, 10.8.8.8")
	if got := srv.clientIP(r2); got != "10.1.2.3" {
		t.Errorf("all-trusted chain: clientIP = %q, want the socket host 10.1.2.3", got)
	}

	// X-Real-IP spoofed by the client is ignored when XFF is present.
	r3 := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	r3.RemoteAddr = "10.1.2.3:5555"
	r3.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.23")
	r3.Header.Set("X-Real-IP", "7.7.7.7")
	if got := srv.clientIP(r3); got != "198.51.100.23" {
		t.Errorf("XFF present: clientIP = %q, want 198.51.100.23 (X-Real-IP must be ignored)", got)
	}

	// X-Real-IP is honoured only when XFF is absent.
	r4 := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	r4.RemoteAddr = "10.1.2.3:5555"
	r4.Header.Set("X-Real-IP", "198.51.100.23")
	if got := srv.clientIP(r4); got != "198.51.100.23" {
		t.Errorf("X-Real-IP without XFF: clientIP = %q, want 198.51.100.23", got)
	}
}

// TestMultiUserFlow drives the complete PKCE flow for two users from a users
// file and asserts that each token carries the right subject and profile.
func TestMultiUserFlow(t *testing.T) {
	usersFile := filepath.Join(t.TempDir(), "users.json")
	if err := SaveUsers(usersFile, []User{
		{Username: "alice", PasswordHash: testHash(t, "wonderland"), Email: "alice@wonderland.example", Name: "Alice"},
		{Username: "bob", PasswordHash: testHash(t, "builder")},
	}); err != nil {
		t.Fatalf("SaveUsers: %v", err)
	}
	ts, _ := testIDP(t, func(c *Config) {
		c.UsersFile = usersFile
		c.Username = "" // multi-user mode
	})

	redeem := func(user, pass, verifier string) map[string]any {
		code := codeFrom(t, login(t, ts.URL, user, pass, verifier))
		return decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"client_id":     {testClientID},
			"redirect_uri":  {testRedirect},
			"code_verifier": {verifier},
		}))
	}

	// Alice: subject and the email/name claims from the users file.
	verifierA, _ := pkcePair()
	tokensA := redeem("alice", "wonderland", verifierA)
	accessA := verifyTokenString(t, tokensA["access_token"].(string), ts.URL)
	if accessA["sub"] != "alice" {
		t.Errorf("alice access sub = %v", accessA["sub"])
	}
	if accessA["email"] != "alice@wonderland.example" {
		t.Errorf("alice access email = %v", accessA["email"])
	}
	idA := verifyTokenString(t, tokensA["id_token"].(string), ts.URL)
	if idA["email"] != "alice@wonderland.example" || idA["name"] != "Alice" {
		t.Errorf("alice id claims = %v/%v", idA["email"], idA["name"])
	}

	// Bob: no email in the file -> placeholder fallback, no name claim.
	verifierB, _ := pkcePair()
	tokensB := redeem("bob", "builder", verifierB)
	idB := verifyTokenString(t, tokensB["id_token"].(string), ts.URL)
	if idB["sub"] != "bob" {
		t.Errorf("bob id sub = %v", idB["sub"])
	}
	if idB["email"] != "bob@example.com" {
		t.Errorf("bob id email = %v, want the placeholder", idB["email"])
	}
	if _, has := idB["name"]; has {
		t.Error("bob has no name in the users file; the claim must be absent")
	}

	// The single-user demo credentials must no longer authenticate.
	verifierC, _ := pkcePair()
	form := authorizeForm(verifierC)
	form.Set("username", "rego")
	form.Set("password", "adventure")
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeForm(verifierC)))
	resp := postForm(t, browser, ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("single-user credentials in multi-user mode: status = %d, want 401", resp.StatusCode)
	}
}
