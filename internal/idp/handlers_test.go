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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testIDP spins up a real HTTP test server. The listener is created first so
// the issuer URL is known before the Server (which signs tokens with it) is
// constructed. The default client registration matches the authorize helpers
// below; mutate the Config for other cases.
func testIDP(t *testing.T, mutate func(*Config)) (*httptest.Server, *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := Config{
		Host:             "127.0.0.1",
		ClientID:         testClientID,
		Audience:         testClientID,
		UsersFile:        writeUsersFile(t),
		AllowedRedirects: []string{testRedirect},
		Issuer:           "http://" + ln.Addr().String(),
		AccessTokenTTL:   time.Hour,
		RefreshTokenTTL:  2 * time.Hour,
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
	verifier, err := randomToken()
	if err != nil {
		// crypto/rand failure is unrecoverable for a test process; production
		// code propagates it as an error (review finding F6).
		panic("pkcePair: " + err.Error())
	}
	return verifier, pkceS256(verifier)
}

const (
	testClientID   = "demo-app"
	testRedirect   = "http://localhost:3000/callback"
	testScopes     = "openid profile email"
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

// themeAccentRe matches the Deep Water accent token in the served stylesheet
// (spacing-insensitive, so CSS re-formatting cannot silently break the check).
var themeAccentRe = regexp.MustCompile(`(?i)--accent:\s*#0d8570\s*;`)

// trustLocalhostTransport emulates the browsers' "localhost is a potentially
// trustworthy origin" exception (W3C Secure Contexts; implemented by Chrome
// and Firefox, not by Safari): it strips the Secure attribute from Set-Cookie
// headers before Go's RFC 6265-literal cookiejar sees them, so the nonce
// cookie issued over plain-HTTP httptest connections round-trips exactly as
// it would in Chrome/Firefox on http://localhost.
type trustLocalhostTransport struct{ base http.RoundTripper }

func (t trustLocalhostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err == nil {
		for i, c := range resp.Header["Set-Cookie"] {
			resp.Header["Set-Cookie"][i] = strings.Replace(c, "; Secure", "", 1)
		}
	}
	return resp, err
}

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
		Transport:     trustLocalhostTransport{base: http.DefaultTransport},
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
	if methods, _ := d["code_challenge_methods_supported"].([]any); len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [S256]", methods)
	}
	// claims_supported must advertise exactly what is issued: auth_time was
	// once listed although no token ever carried it.
	for _, claim := range d["claims_supported"].([]any) {
		if claim == "auth_time" {
			t.Error("claims_supported must not advertise auth_time: it is never issued")
		}
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

// authorizeError extracts the OAuth error code from a 302 the authorize
// endpoint sent to the registered redirect_uri.
func authorizeError(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 to the redirect_uri", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.String() != resp.Header.Get("Location") {
		t.Fatalf("bad redirect location %q", resp.Header.Get("Location"))
	}
	if got := loc.String(); !strings.HasPrefix(got, testRedirect+"?") {
		t.Fatalf("error went to %q, want the registered redirect_uri", got)
	}
	if loc.Query().Get("state") != testStateValue {
		t.Errorf("error redirect must echo state, got %q", loc.Query().Get("state"))
	}
	return loc.Query().Get("error")
}

// TestAuthorizeRejectsUnknownClientID pins the H1 fix: minidp is a
// single-client provider, so only the registered client_id may start a flow.
func TestAuthorizeRejectsUnknownClientID(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp, err := http.Get(ts.URL + "/authorize?client_id=any-other-app&redirect_uri=" + url.QueryEscape(testRedirect) + "&response_type=code&code_challenge=" + strings.Repeat("a", 43) + "&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Unknown client_id") {
		t.Error("expected an explanatory error page, not a redirect to an attacker-controlled URI")
	}
}

// TestAuthorizeRejectsUnregisteredRedirect pins the H1/H2 fix: redirect URIs
// outside the client registration are rejected with an error page — never a
// redirect.
func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	ts, _ := testIDP(t, nil)
	target := ts.URL + "/authorize?client_id=" + testClientID + "&redirect_uri=" + url.QueryEscape("https://attacker.example/cb") + "&response_type=code&code_challenge=" + strings.Repeat("a", 43) + "&code_challenge_method=S256"
	resp, err := noFollow().Get(target)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeRejectsMissingPKCE(t *testing.T) {
	ts, _ := testIDP(t, nil)
	// After the client binding is validated, errors are redirected to the
	// registered redirect_uri (RFC 6749 §4.1.2.1) — never shown on a page.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/authorize?client_id="+testClientID+"&redirect_uri="+url.QueryEscape(testRedirect)+"&response_type=code&state="+testStateValue, nil)
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := authorizeError(t, resp); got != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", got)
	}
}

// TestAuthorizeRejectsPlainPKCE pins the RFC 9700 requirement: only S256 is
// accepted, both at authorization and (defensively) at token verification.
func TestAuthorizeRejectsPlainPKCE(t *testing.T) {
	ts, _ := testIDP(t, nil)
	for _, method := range []string{"plain", "", "s256"} {
		target := ts.URL + "/authorize?client_id=" + testClientID + "&redirect_uri=" + url.QueryEscape(testRedirect) +
			"&response_type=code&state=" + testStateValue + "&code_challenge=abc&code_challenge_method=" + url.QueryEscape(method)
		resp, err := noFollow().Get(target)
		if err != nil {
			t.Fatalf("GET /authorize (method=%q): %v", method, err)
		}
		_ = resp.Body.Close()
		if got := authorizeError(t, resp); got != "invalid_request" {
			t.Errorf("method=%q: error = %q, want invalid_request", method, got)
		}
	}

	// Defense in depth: a stored plain challenge must not verify either.
	if verifyPKCE("some-verifier", "plain", "some-verifier") {
		t.Error("verifyPKCE must reject the plain method")
	}
}

// TestAuthorizeRejectsUnsupportedScope pins the M1 fix: scopes outside the
// advertised set are rejected with invalid_scope instead of being copied into
// tokens.
func TestAuthorizeRejectsUnsupportedScope(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	for _, scope := range []string{"admin", "offline_access openid", "openid profile bogus"} {
		q := authorizeForm(verifier)
		q.Set("scope", scope)
		resp, err := noFollow().Get(ts.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatalf("GET /authorize (scope=%q): %v", scope, err)
		}
		_ = resp.Body.Close()
		if got := authorizeError(t, resp); got != "invalid_scope" {
			t.Errorf("scope=%q: error = %q, want invalid_scope", scope, got)
		}
	}
}

// TestAuthorizeRejectsUnsupportedOIDCParams pins the M3 fix: prompt (other
// than login/none), max_age, response_mode, display, ui_locales and
// acr_values are rejected explicitly instead of being accepted and ignored.
func TestAuthorizeRejectsUnsupportedOIDCParams(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	cases := map[string]url.Values{
		"max_age":        {"max_age": {"900"}},
		"acr_values":     {"acr_values": {"mfa"}},
		"display":        {"display": {"popup"}},
		"ui_locales":     {"ui_locales": {"de"}},
		"response_mode":  {"response_mode": {"form_post"}},
		"prompt=consent": {"prompt": {"consent"}},
	}
	for name, extra := range cases {
		q := authorizeForm(verifier)
		for k, v := range extra {
			q.Set(k, v[0])
		}
		resp, err := noFollow().Get(ts.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatalf("GET /authorize (%s): %v", name, err)
		}
		_ = resp.Body.Close()
		if got := authorizeError(t, resp); got != "invalid_request" {
			t.Errorf("%s: error = %q, want invalid_request", name, got)
		}
	}
}

// TestAuthorizePromptNoneReturnsLoginRequired pins the OIDC behaviour for
// prompt=none: minidp keeps no browser session, so the correct answer is the
// login_required error redirect, not a login page.
func TestAuthorizePromptNoneReturnsLoginRequired(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	q := authorizeForm(verifier)
	q.Set("prompt", "none")
	resp, err := noFollow().Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := authorizeError(t, resp); got != "login_required" {
		t.Errorf("error = %q, want login_required", got)
	}
}

// TestTokenResponseNoStore pins the M4 fix: /token responses (including
// errors) must not be cached (RFC 6749 §5.1).
func TestTokenResponseNoStore(t *testing.T) {
	ts, _ := testIDP(t, nil)
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{"grant_type": {"password"}})
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("error response Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("error response Pragma = %q, want no-cache", got)
	}
	_ = resp.Body.Close()

	// A successful response must carry the headers as well.
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
	ok := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	})
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("token grant: status = %d", ok.StatusCode)
	}
	if got := ok.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("success response Cache-Control = %q, want no-store", got)
	}
	if got := ok.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("success response Pragma = %q, want no-cache", got)
	}
	_ = ok.Body.Close()
}

func TestAuthorizeWrongPassword(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	form := authorizeForm(verifier)
	form.Set("username", "demo")
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
	q := url.Values{
		"client_id":      {testClientID},
		"redirect_uri":   {testRedirect},
		"response_type":  {"token"},
		"state":          {testStateValue},
		"code_challenge": {strings.Repeat("a", 43)},
	}
	resp, err := noFollow().Get(ts.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := authorizeError(t, resp); got != "unsupported_response_type" {
		t.Errorf("error = %q, want unsupported_response_type", got)
	}
}

func TestFullCodeGrantWithPKCE(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()

	location := login(t, ts.URL, "demo", "demo-password", verifier)
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
	if claims["sub"] != "demo" {
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
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

	form := authorizeForm(verifier)
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", testClientID)
	form.Set("redirect_uri", testRedirect)
	wrongVerifier, err := randomToken()
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	form.Set("code_verifier", wrongVerifier) // wrong verifier
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
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

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
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

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
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

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
		return codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
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
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

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
		"code":          {codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))},
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
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
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
	if info["sub"] != "demo" || info["preferred_username"] != "demo" {
		t.Errorf("userinfo = %v", info)
	}
	if info["email"] != "demo@example.com" {
		t.Errorf("userinfo email = %v, want the users-file value", info["email"])
	}
	// F3: discovery advertises `name` in claims_supported, so UserInfo must
	// emit it too when the profile scope was granted.
	if info["name"] != "Demo User" {
		t.Errorf("userinfo name = %v, want the users-file value", info["name"])
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

// TestUserinfoEnforcesScopesAndTokenProfile pins the H3/M2 fixes end-to-end:
// an id_token is not a bearer access token, and profile claims follow the
// granted scopes.
func TestUserinfoEnforcesScopesAndTokenProfile(t *testing.T) {
	ts, srv := testIDP(t, nil)
	verifier, _ := pkcePair()

	// A flow WITHOUT profile/email scopes: userinfo must return sub only.
	form := authorizeForm(verifier)
	form.Set("scope", "openid")
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", form))
	form.Set("username", "demo")
	form.Set("password", "demo-password")
	loginResp := postForm(t, browser, ts.URL+"/authorize", form)
	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize: status = %d", loginResp.StatusCode)
	}
	code := codeFrom(t, loginResp.Header.Get("Location"))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))

	call := func(token string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /userinfo: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, decodeJSON(t, resp)
	}

	status, info := call(tokens["access_token"].(string))
	if status != http.StatusOK {
		t.Fatalf("userinfo (openid only): status = %d", status)
	}
	if info["sub"] != "demo" {
		t.Errorf("userinfo sub = %v", info["sub"])
	}
	if _, has := info["preferred_username"]; has {
		t.Error("preferred_username must not be released without the profile scope")
	}
	if _, has := info["name"]; has {
		t.Error("name must not be released without the profile scope")
	}
	if _, has := info["email"]; has {
		t.Error("email must not be released without the email scope")
	}

	// The id_token (typ JWT) must be rejected as a bearer access token (H3).
	status, _ = call(tokens["id_token"].(string))
	if status != http.StatusUnauthorized {
		t.Errorf("id_token at /userinfo: status = %d, want 401", status)
	}

	// A signed access token for a foreign audience must be rejected (H4).
	foreign := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "demo",
		"aud": "some-other-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"jti": "foreign-aud-jti",
	}
	signed, err := srv.key.signAccess(foreign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	status, _ = call(signed)
	if status != http.StatusUnauthorized {
		t.Errorf("foreign-audience token at /userinfo: status = %d, want 401", status)
	}
}

func TestIntrospectAndRevoke(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
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

// TestRevokeAccessTokenDeniesIt pins the L4 fix: revoking an access token
// must make it immediately unusable at /userinfo instead of leaving it valid
// for its full TTL.
func TestRevokeAccessTokenDeniesIt(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	access := tokens["access_token"].(string)

	userinfo := func() int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /userinfo: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if got := userinfo(); got != http.StatusOK {
		t.Fatalf("userinfo before revoke: status = %d, want 200", got)
	}
	if resp := postForm(t, http.DefaultClient, ts.URL+"/revoke", url.Values{"token": {access}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: status = %d, want 200", resp.StatusCode)
	}
	if got := userinfo(); got != http.StatusUnauthorized {
		t.Errorf("userinfo after revoke: status = %d, want 401", got)
	}
}

// TestEndSessionRevokesTokenFamily pins the L19 fix: /end_session with an
// id_token_hint revokes the authorization the hint belongs to — its refresh
// token becomes unredeemable and its access token denied.
func TestEndSessionRevokesTokenFamily(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	access := tokens["access_token"].(string)
	refresh := tokens["refresh_token"].(string)
	idToken := tokens["id_token"].(string)

	// Logout with the id_token_hint identifies the family via sid.
	resp, err := http.Get(ts.URL + "/end_session?id_token_hint=" + url.QueryEscape(idToken))
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	_ = resp.Body.Close()

	// The access token is denied.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	ui, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	_ = ui.Body.Close()
	if ui.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo after logout: status = %d, want 401", ui.StatusCode)
	}

	// The refresh token is gone.
	grant := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {testClientID},
	}))
	if grant["error"] != "invalid_grant" {
		t.Errorf("refresh after logout: %v, want invalid_grant", grant["error"])
	}

	// Without a hint the endpoint still renders the logout page.
	resp2, err := http.Get(ts.URL + "/end_session")
	if err != nil {
		t.Fatalf("GET /end_session without hint: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("/end_session without hint: status = %d, want 200", resp2.StatusCode)
	}
}

// TestEndSessionHintValidatesAudience pins the F4 fix: an id_token_hint whose
// audience does not match this provider is rejected, so a signed token minted
// for a DIFFERENT client cannot revoke a session here — even when it names a
// live family via sid. A hint with the right audience but a stale exp is still
// honoured (M6): expiry does not disqualify a logout hint.
func TestEndSessionHintValidatesAudience(t *testing.T) {
	ts, srv := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	access := tokens["access_token"].(string)
	realSID := verifyTokenString(t, tokens["id_token"].(string), ts.URL)["sid"].(string)

	familyAlive := func(want int) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+access)
		ui, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /userinfo: %v", err)
		}
		_ = ui.Body.Close()
		if ui.StatusCode != want {
			t.Errorf("userinfo after logout attempt: status = %d, want %d", ui.StatusCode, want)
		}
	}

	// A validly signed id_token for a foreign audience must be rejected as a
	// logout hint: the family stays alive.
	foreign := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "demo",
		"aud": "some-other-client",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"sid": realSID,
	}
	hint, err := srv.key.sign(foreign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp, err := http.Get(ts.URL + "/end_session?id_token_hint=" + url.QueryEscape(hint))
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	_ = resp.Body.Close()
	familyAlive(http.StatusOK)

	// A matching-audience hint with an EXPIRED token still revokes the family.
	expired := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "demo",
		"aud": srv.cfg.Audience,
		"exp": time.Now().Add(-time.Minute).Unix(),
		"iat": time.Now().Add(-time.Hour).Unix(),
		"sid": realSID,
	}
	hint2, err := srv.key.sign(expired)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp2, err := http.Get(ts.URL + "/end_session?id_token_hint=" + url.QueryEscape(hint2))
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	_ = resp2.Body.Close()
	familyAlive(http.StatusUnauthorized)
}

// TestIntrospectRevokeClientAuth pins the review fix: in confidential mode
// (MINIDP_MODE=confidential with IDP_CLIENT_SECRET), /introspect and /revoke
// require client authentication. The token redemption inside also exercises
// the client_secret_post method at /token.
func TestIntrospectRevokeClientAuth(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) {
		c.Mode = ModeConfidential
		c.ClientSecret = "s3cret"
	})
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"client_secret": {"s3cret"},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	access := tokens["access_token"].(string)

	// Without credentials both endpoints must reject with 401 invalid_client.
	for _, ep := range []string{"/introspect", "/revoke"} {
		resp := postForm(t, http.DefaultClient, ts.URL+ep, url.Values{"token": {access}})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without auth: status = %d, want 401", ep, resp.StatusCode)
		}
		if got := decodeJSON(t, resp)["error"]; got != "invalid_client" {
			t.Errorf("%s without auth: error = %v, want invalid_client", ep, got)
		}
	}

	// HTTP Basic auth with the correct secret is accepted.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/introspect",
		strings.NewReader(url.Values{"token": {access}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, "s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect with basic auth: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("introspect with basic auth: status = %d, want 200", resp.StatusCode)
	}

	// A client_secret form field is accepted as well.
	resp2 := postForm(t, http.DefaultClient, ts.URL+"/revoke", url.Values{
		"token":         {access},
		"client_secret": {"s3cret"},
	})
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("revoke with form secret: status = %d, want 200", resp2.StatusCode)
	}

	// A wrong secret is rejected.
	resp3 := postForm(t, http.DefaultClient, ts.URL+"/introspect", url.Values{
		"token":         {access},
		"client_secret": {"wrong"},
	})
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("introspect with wrong secret: status = %d, want 401", resp3.StatusCode)
	}
	_ = resp3.Body.Close()
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
	// With a registered policy, only exactly listed URIs pass.
	_, srv2 := testIDP(t, func(c *Config) {
		c.AllowedRedirects = []string{testRedirect}
	})
	if !srv2.redirectURIAllowed(testRedirect) {
		t.Error("registered URI must be allowed")
	}
	if srv2.redirectURIAllowed("https://other.example.com/cb") {
		t.Error("non-registered URI must be rejected")
	}
	if srv2.redirectURIAllowed(testRedirect + "#frag") {
		t.Error("a URI with a fragment must be rejected")
	}
	if srv2.redirectURIAllowed("javascript:alert(1)") {
		t.Error("non-http schemes must be rejected")
	}
	if srv2.redirectURIAllowed("not a url") {
		t.Error("garbage redirect URIs must be rejected")
	}

	// There is no open fallback: without a policy nothing is allowed (the
	// server refuses to start this way; this only pins the check).
	_, srv3 := testIDP(t, func(c *Config) { c.AllowedRedirects = nil })
	if srv3.redirectURIAllowed(testRedirect) {
		t.Error("an empty policy must allow nothing")
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

	// An origin that is neither derived from a registered redirect nor
	// listed in IDP_ALLOWED_ORIGINS is never credited.
	ts2, _ := testIDP(t, nil)
	req, _ := http.NewRequest(http.MethodGet, ts2.URL+"/healthz", nil)
	req.Header.Set("Origin", "https://demo-password.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unrelated origin: Access-Control-Allow-Origin = %q, want unset", got)
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

	form := url.Values{"username": {"demo"}, "password": {"demo-password"}}
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/", url.Values{}))
	ok := postForm(t, browser, ts.URL+"/login", form)
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("POST /login: status = %d", ok.StatusCode)
	}
	body, _ := io.ReadAll(ok.Body)
	if !strings.Contains(string(body), "Signed in as demo") {
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
	if !themeAccentRe.Match(body) {
		t.Error("login.css must carry the Deep Water theme accent color")
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

// TestAssetOverrides verifies the fixed assets directory: a file present at
// <workdir>/assets/<name> overrides exactly its embedded default, and the
// other asset keeps the shipped version (per-file fallback).
func TestAssetOverrides(t *testing.T) {
	const customCSS = "/* operator override */ .login-form { gap: 2rem; }"
	const customLogo = `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>`

	setup := func(t *testing.T, names ...string) {
		t.Helper()
		assets := filepath.Join(t.TempDir(), "assets")
		if err := os.MkdirAll(assets, 0o700); err != nil {
			t.Fatalf("mkdir assets: %v", err)
		}
		files := map[string]string{"login.css": customCSS, "logo.svg": customLogo}
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(assets, name), []byte(files[name]), 0o600); err != nil {
				t.Fatalf("write override %s: %v", name, err)
			}
		}
		t.Chdir(filepath.Dir(assets))
	}

	get := func(t *testing.T, url string) string {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return string(body)
	}

	t.Run("both files overridden", func(t *testing.T) {
		setup(t, "login.css", "logo.svg")
		ts, _ := testIDP(t, nil)
		if css := get(t, ts.URL+"/login.css"); css != customCSS {
			t.Errorf("login.css not overridden: %q", css)
		}
		if logo := get(t, ts.URL+"/logo.svg"); logo != customLogo {
			t.Errorf("logo.svg not overridden: %q", logo)
		}
	})

	t.Run("per-file fallback to embedded default", func(t *testing.T) {
		setup(t, "logo.svg")
		ts, _ := testIDP(t, nil)
		if css := get(t, ts.URL + "/login.css"); !themeAccentRe.MatchString(css) {
			t.Error("login.css must fall back to the embedded Deep Water theme")
		}
		if logo := get(t, ts.URL+"/logo.svg"); logo != customLogo {
			t.Errorf("logo.svg not overridden: %q", logo)
		}
	})
}

func TestAuthorizeRejectsInvalidCSRF(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	form := authorizeForm(verifier)
	form.Set("username", "demo")
	form.Set("password", "demo-password")
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
	form.Set("username", "demo")
	form.Set("password", "demo-password")
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

	// The attacker fetches a valid form for their own (registered redirect,
	// attacker-chosen state) parameters.
	attacker := newBrowser()
	attackerForm := authorizeForm(verifier)
	attackerForm.Set("state", "attacker-state")
	attackerForm.Set("nonce", "attacker-nonce")
	token := fetchCSRF(t, attacker, ts.URL+"/authorize", attackerForm)

	submit := func(victim *http.Client) *http.Response {
		form := attackerForm
		form.Set("username", "demo")
		form.Set("password", "demo-password")
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

// TestAuthorizeFormSetsNonceCookie pins the unconditional Secure attribute:
// the nonce cookie always carries HttpOnly, SameSite=Lax and Secure. The
// plain (non-jar) client is used so the raw header is inspected without the
// trustLocalhostTransport stripping the attribute.
func TestAuthorizeFormSetsNonceCookie(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	resp, err := http.Get(ts.URL + "/authorize?" + authorizeForm(verifier).Encode())
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
			t.Error("nonce cookie must always be Secure (localhost demo relies on the browser secure-context exception)")
		}
	}
	if !found {
		t.Fatal("GET /authorize did not set the nonce cookie")
	}
}

// TestLoginFormsSurviveRerender pins the review fix: rendering a new login
// form (second tab, failed-login re-render) must not rotate the nonce cookie,
// which used to invalidate every previously rendered form.
func TestLoginFormsSurviveRerender(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifierA, _ := pkcePair()
	verifierB, _ := pkcePair()

	browser := newBrowser()

	// Tab A fetches its form.
	formA := authorizeForm(verifierA)
	respA, err := browser.Get(ts.URL + "/authorize?" + formA.Encode())
	if err != nil {
		t.Fatalf("GET /authorize (tab A): %v", err)
	}
	bodyA, _ := io.ReadAll(respA.Body)
	_ = respA.Body.Close()
	tokenA := csrfFieldRe.FindStringSubmatch(string(bodyA))
	if tokenA == nil {
		t.Fatal("tab A: no csrf_token")
	}

	// Tab B fetches its own form. It must not mint a new nonce cookie.
	formB := authorizeForm(verifierB)
	respB, err := browser.Get(ts.URL + "/authorize?" + formB.Encode())
	if err != nil {
		t.Fatalf("GET /authorize (tab B): %v", err)
	}
	for _, c := range respB.Cookies() {
		if c.Name == csrfCookie {
			t.Error("re-render must not rotate the nonce cookie")
		}
	}
	_ = respB.Body.Close()

	// Tab A's form, submitted after tab B's render, must still be accepted.
	formA.Set("username", "demo")
	formA.Set("password", "demo-password")
	formA.Set("csrf_token", tokenA[1])
	resp := postForm(t, browser, ts.URL+"/authorize", formA)
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("stale form rejected: status = %d, body = %s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Location"), testRedirect+"?code=") {
		t.Errorf("location = %q, want a code redirect", resp.Header.Get("Location"))
	}
}

func TestLoginRateLimiting(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) { c.LoginRateLimit = 2 })
	verifier, _ := pkcePair()

	browser := newBrowser()
	attempt := func() (*http.Response, url.Values) {
		form := authorizeForm(verifier)
		form.Set("username", "demo")
		form.Set("password", "demo-password")
		form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeForm(verifier)))
		resp := postForm(t, browser, ts.URL+"/authorize", form)
		return resp, form
	}
	if resp, _ := attempt(); resp.StatusCode != http.StatusFound {
		t.Fatalf("attempt 1: status = %d, want 302", resp.StatusCode)
	}
	if resp, _ := attempt(); resp.StatusCode != http.StatusFound {
		t.Fatalf("attempt 2: status = %d, want 302", resp.StatusCode)
	}
	resp, form := attempt()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: status = %d, want 429", resp.StatusCode)
	}
	// The 429 re-render must keep the OAuth2 context so a retry after the
	// cooldown submits a complete form instead of losing client_id & co.
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, key := range []string{"client_id", "redirect_uri", "code_challenge", "state", "nonce"} {
		if !strings.Contains(string(body), `name="`+key+`" value="`+form.Get(key)+`"`) {
			t.Errorf("429 page is missing the hidden field %q", key)
		}
	}
}

// TestRateLimitIgnoresCSRFJunk pins the F5 fix: POSTs without a valid CSRF
// token are rejected before the limiter runs, so junk traffic cannot burn the
// per-IP budget and lock a legitimate user out (shared NAT). Attempts that DO
// carry a browser-issued CSRF token are still throttled (TestLoginRateLimiting).
func TestRateLimitIgnoresCSRFJunk(t *testing.T) {
	ts, _ := testIDP(t, func(c *Config) { c.LoginRateLimit = 2 })
	verifier, _ := pkcePair()

	for i := 0; i < 5; i++ {
		form := authorizeForm(verifier)
		form.Set("username", "demo")
		form.Set("password", "demo-password")
		form.Set("csrf_token", "forged")
		resp := postForm(t, http.DefaultClient, ts.URL+"/authorize", form)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("junk attempt %d: status = %d, want 400 (CSRF rejection, not 429)", i+1, resp.StatusCode)
		}
	}

	// The legitimate user on the same IP is unaffected.
	browser := newBrowser()
	form := authorizeForm(verifier)
	form.Set("username", "demo")
	form.Set("password", "demo-password")
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeForm(verifier)))
	resp := postForm(t, browser, ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login after junk: status = %d, want 302", resp.StatusCode)
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

	// Bob: no email or name in the file -> the claims are absent, nothing is
	// fabricated.
	verifierB, _ := pkcePair()
	tokensB := redeem("bob", "builder", verifierB)
	idB := verifyTokenString(t, tokensB["id_token"].(string), ts.URL)
	if idB["sub"] != "bob" {
		t.Errorf("bob id sub = %v", idB["sub"])
	}
	if _, has := idB["email"]; has {
		t.Error("bob has no email in the users file; the claim must be absent")
	}
	if _, has := idB["name"]; has {
		t.Error("bob has no name in the users file; the claim must be absent")
	}

	// Credentials that are not in the users file do not authenticate.
	verifierC, _ := pkcePair()
	form := authorizeForm(verifierC)
	form.Set("username", "demo")
	form.Set("password", "demo-password")
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeForm(verifierC)))
	resp := postForm(t, browser, ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("single-user credentials in multi-user mode: status = %d, want 401", resp.StatusCode)
	}
}
