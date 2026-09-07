package idp

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// testConfidentialIDP returns an IdP whose single client is confidential
// (MINIDP_MODE=confidential) with the given client secret.
func testConfidentialIDP(t *testing.T, secret string) (*httptest.Server, *Server) {
	t.Helper()
	return testIDP(t, func(c *Config) {
		c.Mode = ModeConfidential
		c.ClientSecret = secret
	})
}

// authorizeFormNoPKCE builds a valid authorization request without PKCE, as a
// confidential client may (the secret is its credential at /token).
func authorizeFormNoPKCE() url.Values {
	return url.Values{
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"response_type": {"code"},
		"scope":         {testScopes},
		"state":         {testStateValue},
		"nonce":         {testNonceValue},
	}
}

// loginNoPKCE runs the authorize round-trip without a code_challenge and
// returns the redirect target URL (containing the code).
func loginNoPKCE(t *testing.T, base, user, pass string) string {
	t.Helper()
	form := authorizeFormNoPKCE()
	form.Set("username", user)
	form.Set("password", pass)
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, base+"/authorize", authorizeFormNoPKCE()))
	resp := postForm(t, browser, base+"/authorize", form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize: status = %d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// postTokenBasic sends a token request authenticated with HTTP Basic
// (client_secret_basic).
func postTokenBasic(t *testing.T, target string, form url.Values, id, secret string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestConfidentialDiscoveryAdvertisesClientAuth pins the discovery metadata
// for both modes: the token/revocation/introspection endpoint auth methods
// must reflect the configured client mode.
func TestConfidentialDiscoveryAdvertisesClientAuth(t *testing.T) {
	for _, tc := range []struct {
		mode   ClientMode
		secret string
		want   []string
	}{
		{ModePublic, "", []string{"none"}},
		{ModeConfidential, "a-confidential-secret", []string{"client_secret_basic", "client_secret_post"}},
	} {
		ts, _ := testIDP(t, func(c *Config) { c.Mode = tc.mode; c.ClientSecret = tc.secret })
		resp, err := http.Get(ts.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("GET discovery: %v", err)
		}
		d := decodeJSON(t, resp)
		_ = resp.Body.Close()
		got, _ := d["token_endpoint_auth_methods_supported"].([]any)
		if len(got) != len(tc.want) {
			t.Fatalf("mode %q: token_endpoint_auth_methods_supported = %v, want %v", tc.mode, got, tc.want)
		}
		for i, want := range tc.want {
			if got[i] != want {
				t.Errorf("mode %q: auth methods = %v, want %v", tc.mode, got, tc.want)
			}
		}
	}
}

// TestConfidentialFullFlowWithoutPKCE drives the confidential end-to-end
// happy path: authorize without any PKCE parameters, redeem the code with
// client_secret_basic only.
func TestConfidentialFullFlowWithoutPKCE(t *testing.T) {
	ts, _ := testConfidentialIDP(t, "a-confidential-secret")

	location := loginNoPKCE(t, ts.URL, "demo", "demo-password")
	if !strings.HasPrefix(location, testRedirect+"?code=") {
		t.Fatalf("redirect %q does not start with %s?code=", location, testRedirect)
	}
	code := codeFrom(t, location)

	resp := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirect},
	}, testClientID, "a-confidential-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
	tokens := decodeJSON(t, resp)
	if tokens["access_token"] == "" || tokens["id_token"] == "" || tokens["refresh_token"] == "" {
		t.Fatalf("expected all three tokens, got %v", tokens)
	}
	claims := verifyTokenString(t, tokens["access_token"].(string), ts.URL)
	if claims["sub"] != "demo" {
		t.Errorf("access sub = %v, want demo", claims["sub"])
	}
}

// TestConfidentialWithPKCEStillAccepted pins that PKCE remains supported for
// confidential clients (RFC 9700 recommends it even there): authorize with a
// challenge, redeem with Basic auth and the matching verifier.
func TestConfidentialWithPKCEStillAccepted(t *testing.T) {
	ts, _ := testConfidentialIDP(t, "a-confidential-secret")
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

	resp := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}, testClientID, "a-confidential-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestConfidentialAuthorizeStillValidatesPKCE pins that a confidential client
// that CHOOSES to send PKCE still gets it validated: plain method and
// malformed challenges stay invalid_request.
func TestConfidentialAuthorizeStillValidatesPKCE(t *testing.T) {
	ts, _ := testConfidentialIDP(t, "a-confidential-secret")
	for _, tc := range []struct{ name, challenge, method string }{
		{"plain method", strings.Repeat("a", 43), "plain"},
		{"malformed challenge", "too-short", "S256"},
	} {
		form := authorizeFormNoPKCE()
		form.Set("code_challenge", tc.challenge)
		form.Set("code_challenge_method", tc.method)
		resp, err := newBrowser().Get(ts.URL + "/authorize?" + form.Encode())
		if err != nil {
			t.Fatalf("GET /authorize: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("%s: status = %d, want 302 redirect with error", tc.name, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
			t.Errorf("%s: Location = %q, want an error redirect", tc.name, loc)
		}
	}
}

// TestConfidentialTokenRequiresClientAuth covers the client authentication
// matrix at /token: no credentials, wrong credentials, wrong client id, and
// the Basic-vs-form client_id conflict all fail with invalid_client; both
// documented methods succeed.
func TestConfidentialTokenRequiresClientAuth(t *testing.T) {
	ts, _ := testConfidentialIDP(t, "a-confidential-secret")

	// A fresh code per redemption attempt: the code must not be the variable
	// under test (failed client auth must not burn it, which is pinned
	// separately in TestConfidentialFailedAuthDoesNotBurnCode).
	freshCode := func() string {
		return codeFrom(t, loginNoPKCE(t, ts.URL, "demo", "demo-password"))
	}
	grant := func(code string) url.Values {
		return url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {testRedirect},
		}
	}

	// No credentials at all -> 401 invalid_client with WWW-Authenticate.
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", grant(freshCode()))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credentials: status = %d, want 401", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_client" {
		t.Errorf("no credentials: error = %v, want invalid_client", got)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("no credentials: WWW-Authenticate header missing")
	}

	// Basic with a wrong secret -> 401.
	if r := postTokenBasic(t, ts.URL+"/token", grant(freshCode()), testClientID, "wrong"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong Basic secret: status = %d, want 401", r.StatusCode)
	}
	// Basic with a wrong client id -> 401.
	if r := postTokenBasic(t, ts.URL+"/token", grant(freshCode()), "other-client", "a-confidential-secret"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong Basic client_id: status = %d, want 401", r.StatusCode)
	}
	// client_secret_post with a wrong secret -> 401.
	wrongPost := grant(freshCode())
	wrongPost.Set("client_id", testClientID)
	wrongPost.Set("client_secret", "wrong")
	if r := postForm(t, http.DefaultClient, ts.URL+"/token", wrongPost); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong form secret: status = %d, want 401", r.StatusCode)
	}
	// Basic credentials that conflict with a form client_id -> 401
	// (RFC 9700 §2.3.2).
	conflict := grant(freshCode())
	conflict.Set("client_id", "other-client")
	if r := postTokenBasic(t, ts.URL+"/token", conflict, testClientID, "a-confidential-secret"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("Basic vs form client_id conflict: status = %d, want 401", r.StatusCode)
	}

	// Basic with correct credentials -> 200.
	r1 := postTokenBasic(t, ts.URL+"/token", grant(freshCode()), testClientID, "a-confidential-secret")
	if r1.StatusCode != http.StatusOK {
		t.Errorf("client_secret_basic: status = %d, want 200", r1.StatusCode)
	}
	// client_secret_post with correct credentials -> 200.
	post := grant(freshCode())
	post.Set("client_id", testClientID)
	post.Set("client_secret", "a-confidential-secret")
	if r2 := postForm(t, http.DefaultClient, ts.URL+"/token", post); r2.StatusCode != http.StatusOK {
		t.Errorf("client_secret_post: status = %d, want 200", r2.StatusCode)
	}
}

// TestConfidentialFailedAuthDoesNotBurnCode pins that client authentication
// happens BEFORE the one-time code is consumed: after a failed client auth on
// a valid code, the correct credentials can still redeem it (RFC 9700
// §4.4.1).
func TestConfidentialFailedAuthDoesNotBurnCode(t *testing.T) {
	ts, _ := testConfidentialIDP(t, "a-confidential-secret")
	code := codeFrom(t, loginNoPKCE(t, ts.URL, "demo", "demo-password"))
	grant := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirect},
	}

	if r := postTokenBasic(t, ts.URL+"/token", grant, testClientID, "wrong"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("failed auth: status = %d, want 401", r.StatusCode)
	}

	resp := postTokenBasic(t, ts.URL+"/token", grant, testClientID, "a-confidential-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("redemption after failed auth: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestConfidentialRefreshRequiresAuth pins RFC 6749 §6 for the refresh grant:
// the confidential client must authenticate when refreshing, and a wrong
// secret must not consume (and thereby destroy) a valid refresh token.
func TestConfidentialRefreshRequiresAuth(t *testing.T) {
	ts, _ := testConfidentialIDP(t, "a-confidential-secret")
	code := codeFrom(t, loginNoPKCE(t, ts.URL, "demo", "demo-password"))

	first := decodeJSON(t, postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirect},
	}, testClientID, "a-confidential-secret"))
	refresh := first["refresh_token"].(string)

	// Refresh without credentials -> 401.
	r1 := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if r1.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh without auth: status = %d, want 401", r1.StatusCode)
	}
	if got := decodeJSON(t, r1)["error"]; got != "invalid_client" {
		t.Errorf("refresh without auth: error = %v, want invalid_client", got)
	}

	// Refresh with a wrong secret -> 401.
	r2 := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	}, testClientID, "wrong")
	if r2.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh with wrong secret: status = %d, want 401", r2.StatusCode)
	}

	// The failed attempts must NOT have consumed the token: the legitimate
	// client can still rotate it.
	r3 := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	}, testClientID, "a-confidential-secret")
	if r3.StatusCode != http.StatusOK {
		t.Fatalf("refresh with correct secret: status = %d, body = %v", r3.StatusCode, decodeJSON(t, r3))
	}
	rotated := decodeJSON(t, r3)["refresh_token"].(string)
	if rotated == "" || rotated == refresh {
		t.Error("expected a rotated refresh token")
	}
}

// TestConfidentialBasicAuthDecodesURLEncodedCredentials pins RFC 6749
// §2.3.1: credentials in the Basic header are
// application/x-www-form-urlencoded first, so a secret containing reserved
// characters must be percent-decoded before comparison.
func TestConfidentialBasicAuthDecodesURLEncodedCredentials(t *testing.T) {
	const secret = "s3cret/+=&" // contains characters urlencoding must survive
	ts, _ := testConfidentialIDP(t, secret)
	code := codeFrom(t, loginNoPKCE(t, ts.URL, "demo", "demo-password"))

	// Build the header exactly as RFC 6749 §2.3.1 prescribes:
	// form-urlencoded credentials joined with ":" and base64-encoded.
	raw := url.QueryEscape(testClientID) + ":" + url.QueryEscape(secret)
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {testRedirect},
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(raw)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestPublicModeIgnoresClientSecretField pins the public-mode token endpoint:
// without a configured secret there is nothing to authenticate against, so a
// client_secret form field is ignored and identification stays client_id +
// PKCE. This documents that the field neither grants nor denies anything in
// public mode.
func TestPublicModeIgnoresClientSecretField(t *testing.T) {
	ts, _ := testIDP(t, nil)
	verifier, _ := pkcePair()
	code := codeFrom(t, login(t, ts.URL, "demo", "demo-password", verifier))

	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
		"client_secret": {"a-confidential-secret"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public mode with stray client_secret: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
}
