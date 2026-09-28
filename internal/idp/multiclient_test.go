package idp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// multiClientIDP returns an IdP with two clients: the default public
// demo-app and a confidential client with its own redirect policy, audience
// and user.
func multiClientIDP(t *testing.T, secret string) (*httptest.Server, *Server) {
	t.Helper()
	conf := Client{
		ClientID:               "conf-app",
		Type:                   TypeConfidential,
		ClientSecret:           secret,
		Audience:               "conf-api",
		RedirectURIs:           []string{"https://conf.example.com/cb"},
		PostLogoutRedirectURIs: []string{"https://conf.example.com/"},
		Users: []User{
			{Username: "bob", PasswordHash: testHash(t, "builder")},
		},
	}
	return testIDPClients(t, []Client{testPublicClient(t), conf}, nil)
}

// authorizeFormFor builds a valid PKCE authorization request body for an
// arbitrary client.
func authorizeFormFor(clientID, redirect, verifier string) url.Values {
	return url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {testScopes},
		"state":                 {testStateValue},
		"nonce":                 {testNonceValue},
		"code_challenge":        {pkceS256(verifier)},
		"code_challenge_method": {"S256"},
	}
}

// loginFor runs the authorize round-trip for a client and returns the
// redirect target URL.
func loginFor(t *testing.T, base, clientID, redirect, user, pass, verifier string) string {
	t.Helper()
	form := authorizeFormFor(clientID, redirect, verifier)
	form.Set("username", user)
	form.Set("password", pass)
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, base+"/authorize", authorizeFormFor(clientID, redirect, verifier)))
	resp := postForm(t, browser, base+"/authorize", form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize for %s: status = %d, want 302", clientID, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// TestMultiClientBothClientsFlow drives the full PKCE flow for both clients
// of one IdP and pins that each client's tokens carry that client's audience.
func TestMultiClientBothClientsFlow(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")

	verifierA, _ := pkcePair()
	locationA := loginFor(t, ts.URL, testClientID, testRedirect, "demo", "demo-password", verifierA)
	if !strings.HasPrefix(locationA, testRedirect+"?code=") {
		t.Fatalf("demo-app redirect %q unexpected", locationA)
	}
	tokensA := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFrom(t, locationA)},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifierA},
	}))
	if tokensA["access_token"] == "" {
		t.Fatalf("demo-app token flow failed: %v", tokensA)
	}
	claimsA := verifyTokenString(t, tokensA["access_token"].(string), ts.URL)
	audA, _ := claimsA["aud"].([]any)
	if len(audA) != 1 || audA[0] != testClientID {
		t.Errorf("demo-app aud = %v, want [%s]", audA, testClientID)
	}

	verifierB, _ := pkcePair()
	locationB := loginFor(t, ts.URL, "conf-app", "https://conf.example.com/cb", "bob", "builder", verifierB)
	respB := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFrom(t, locationB)},
		"redirect_uri":  {"https://conf.example.com/cb"},
		"code_verifier": {verifierB},
	}, "conf-app", "a-confidential-secret")
	if respB.StatusCode != http.StatusOK {
		t.Fatalf("conf-app token flow: status = %d, body = %v", respB.StatusCode, decodeJSON(t, respB))
	}
	claimsB := verifyTokenString(t, decodeJSON(t, respB)["access_token"].(string), ts.URL)
	audB, _ := claimsB["aud"].([]any)
	if len(audB) != 1 || audB[0] != "conf-api" {
		t.Errorf("conf-app aud = %v, want [conf-api]", audB)
	}
	if claimsB["client_id"] != "conf-app" {
		t.Errorf("conf-app client_id = %v, want [conf-app] (RFC 9068 §2.2)", claimsB["client_id"])
	}
}

// TestMultiClientAPIAudienceIDToken pins the audience split at the HTTP
// boundary: conf-app's access token is minted for its configured API
// audience while its id_token is minted for the client id itself.
func TestMultiClientAPIAudienceIDToken(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")

	verifier, _ := pkcePair()
	location := loginFor(t, ts.URL, "conf-app", "https://conf.example.com/cb", "bob", "builder", verifier)
	tokens := decodeJSON(t, postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFrom(t, location)},
		"redirect_uri":  {"https://conf.example.com/cb"},
		"code_verifier": {verifier},
	}, "conf-app", "a-confidential-secret"))

	idClaims := verifyTokenString(t, tokens["id_token"].(string), ts.URL)
	audID, _ := idClaims["aud"].([]any)
	if len(audID) != 1 || audID[0] != "conf-app" {
		t.Errorf("id aud = %v, want [conf-app] (the RP, not the conf-api audience)", audID)
	}
	nonce, _ := idClaims["nonce"].(string)
	if nonce != testNonceValue {
		t.Errorf("id nonce = %q, want %q", nonce, testNonceValue)
	}
}

// TestMultiClientAPIAudienceUserInfoAndLogout pins that the endpoints that
// must resolve the client behind a token still work when the access token's
// audience is the API audience, not the client id: /userinfo resolves the
// account store via the RFC 9068 client_id claim, and /end_session resolves
// the client from the id_token_hint's client-id audience and revokes the
// token family.
func TestMultiClientAPIAudienceUserInfoAndLogout(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")

	verifier, _ := pkcePair()
	location := loginFor(t, ts.URL, "conf-app", "https://conf.example.com/cb", "bob", "builder", verifier)
	tokens := decodeJSON(t, postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFrom(t, location)},
		"redirect_uri":  {"https://conf.example.com/cb"},
		"code_verifier": {verifier},
	}, "conf-app", "a-confidential-secret"))
	access := tokens["access_token"].(string)
	idToken := tokens["id_token"].(string)

	// /userinfo with an API-audience access token: the client_id claim —
	// not the audience — resolves bob's account store.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	ui, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	uiClaims := decodeJSON(t, ui)
	_ = ui.Body.Close()
	if ui.StatusCode != http.StatusOK {
		t.Fatalf("/userinfo: status = %d, body = %v", ui.StatusCode, uiClaims)
	}
	if uiClaims["sub"] != "bob" || uiClaims["preferred_username"] != "bob" {
		t.Errorf("userinfo = %v, want bob's profile resolved via the client_id claim", uiClaims)
	}

	// /end_session with the conf-app id_token_hint: the hint's audience (the
	// client id) must resolve conf-app even though its registered audience
	// is conf-api, and logout must revoke the token family.
	logoutResp, err := noFollow().Get(ts.URL + "/end_session?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape("https://conf.example.com/"))
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	_ = logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusFound || logoutResp.Header.Get("Location") != "https://conf.example.com/" {
		t.Errorf("end_session: status = %d, location = %q, want redirect to conf-app's allowlisted target",
			logoutResp.StatusCode, logoutResp.Header.Get("Location"))
	}

	// The revoked family: the refresh token no longer redeems.
	grant := decodeJSON(t, postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)},
	}, "conf-app", "a-confidential-secret"))
	if grant["error"] != "invalid_grant" {
		t.Errorf("refresh after logout: %v, want invalid_grant", grant["error"])
	}
}

// TestMultiClientPerClientRedirectPolicy pins that a client cannot use
// another client's redirect_uri: the authorization request is rejected on
// the HTML page, never redirected.
func TestMultiClientPerClientRedirectPolicy(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")

	resp, err := newBrowser().Get(ts.URL + "/authorize?" + authorizeFormFor("conf-app", testRedirect, "ignored-because-rejected").Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("conf-app with demo-app's redirect: status = %d, want 400", resp.StatusCode)
	}

	// The reverse direction: demo-app with conf-app's redirect.
	resp2, err := newBrowser().Get(ts.URL + "/authorize?" + authorizeFormFor(testClientID, "https://conf.example.com/cb", "x").Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("demo-app with conf-app's redirect: status = %d, want 400", resp2.StatusCode)
	}
}

// TestMultiClientUserIsolation pins that each client's login form only
// accepts that client's own users: client A's user cannot sign in to
// client B's flow.
func TestMultiClientUserIsolation(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")

	verifier, _ := pkcePair()
	form := authorizeFormFor("conf-app", "https://conf.example.com/cb", verifier)
	form.Set("username", "demo") // demo-app's user
	form.Set("password", "demo-password")
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, ts.URL+"/authorize", authorizeFormFor("conf-app", "https://conf.example.com/cb", verifier)))
	resp := postForm(t, browser, ts.URL+"/authorize", form)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("demo user on conf-app: status = %d, want 401", resp.StatusCode)
	}
}

// TestMultiClientCrossClientCodeRedemption pins that a confidential client's
// valid credentials cannot redeem another client's authorization code: the
// code binding (RFC 6749 §4.1.3) rejects the foreign client with
// invalid_grant.
func TestMultiClientCrossClientCodeRedemption(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")
	verifier, _ := pkcePair()
	code := codeFrom(t, loginFor(t, ts.URL, testClientID, testRedirect, "demo", "demo-password", verifier))

	// conf-app authenticates correctly at /token but presents demo-app's
	// code: rejected with invalid_grant (RFC 6749 §4.1.3 code binding).
	resp := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}, "conf-app", "a-confidential-secret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-client redemption: status = %d, want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("cross-client redemption: error = %v, want invalid_grant", got)
	}

	// The code is burned by the foreign redemption attempt (a different
	// client presenting a code is a theft signal — same semantics as the
	// refresh-token client mismatch): even the legitimate client is locked
	// out, and the code cannot be replayed.
	resp2 := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("redemption after foreign attempt: status = %d, want 400 (code burned)", resp2.StatusCode)
	}
}

// TestMultiClientCrossClientRefresh pins the refresh-token binding: a
// refresh token of one client cannot be used by another client, and the
// mismatch drops the whole token family (theft signal).
func TestMultiClientCrossClientRefresh(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")
	verifier, _ := pkcePair()
	code := codeFrom(t, loginFor(t, ts.URL, testClientID, testRedirect, "demo", "demo-password", verifier))
	tokens := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}))
	refresh := tokens["refresh_token"].(string)

	// conf-app presents its valid credentials with demo-app's refresh token.
	resp := postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	}, "conf-app", "a-confidential-secret")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-client refresh: status = %d, want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_grant" {
		t.Errorf("cross-client refresh: error = %v, want invalid_grant", got)
	}

	// The mismatch revoked the family: even the legitimate client is locked
	// out (theft signal semantics).
	resp2 := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {testClientID},
	})
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("refresh after mismatch: status = %d, want 400 (family revoked)", resp2.StatusCode)
	}
}

// TestMultiClientEndSessionPostLogoutIsPerClient pins that the
// post_logout_redirect_uri of /end_session is validated against the
// redirecting client's own list: demo-app's callback is not a valid logout
// target for conf-app.
func TestMultiClientEndSessionPostLogoutIsPerClient(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")

	// Resolved via client_id: demo-app's own target redirects.
	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/end_session?client_id="+url.QueryEscape(testClientID)+"&post_logout_redirect_uri="+url.QueryEscape(testRedirect), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := noFollow().Do(req)
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != testRedirect {
		t.Fatalf("demo-app logout: status = %d, location = %q; want 302", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The same target requested for conf-app is not on ITS list: page, no
	// redirect.
	req2, err := http.NewRequest(http.MethodGet,
		ts.URL+"/end_session?client_id="+url.QueryEscape("conf-app")+"&post_logout_redirect_uri="+url.QueryEscape(testRedirect), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp2, err := noFollow().Do(req2)
	if err != nil {
		t.Fatalf("GET /end_session: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("conf-app logout with demo-app's target: status = %d, want 200 (page)", resp2.StatusCode)
	}
}

// TestMultiClientPublicClientCannotAuthenticate pins the profile separation:
// a public client has no secret, so Basic credentials are meaningless — the
// identification happens via the client_id form field (RFC 6749 §2.3: clients
// without a secret do not authenticate). A missing client_id stays a
// malformed request.
func TestMultiClientPublicClientCannotAuthenticate(t *testing.T) {
	ts, _ := multiClientIDP(t, "a-confidential-secret")
	verifier, _ := pkcePair()
	code := codeFrom(t, loginFor(t, ts.URL, testClientID, testRedirect, "demo", "demo-password", verifier))
	grant := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	}

	// Basic credentials naming the public client are ignored (no secret to
	// verify); identification via the form client_id succeeds.
	if r := postTokenBasic(t, ts.URL+"/token", grant, testClientID, "guess"); r.StatusCode != http.StatusOK {
		t.Errorf("public client with Basic credentials: status = %d, want 200", r.StatusCode)
	}

	// Without any client_id the request is malformed (RFC 6749 §5.2).
	verifier2, _ := pkcePair()
	code2 := codeFrom(t, loginFor(t, ts.URL, testClientID, testRedirect, "demo", "demo-password", verifier2))
	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code2},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier2},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token request without client_id: status = %d, want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_request" {
		t.Errorf("token request without client_id: error = %v, want invalid_request", got)
	}
}

// delegatedScopeIDP returns an IdP whose confidential client conf-app is
// registered with the delegated API scopes api://conf-api/read and
// api://conf-api/write.
func delegatedScopeIDP(t *testing.T, secret string) (*httptest.Server, *Server) {
	t.Helper()
	conf := Client{
		ClientID:      "conf-app",
		Type:          TypeConfidential,
		ClientSecret:  secret,
		Audience:      "conf-api",
		RedirectURIs:  []string{"https://conf.example.com/cb"},
		AllowedScopes: []string{"api://conf-api/read", "api://conf-api/write"},
		Users: []User{
			{Username: "bob", PasswordHash: testHash(t, "builder")},
		},
	}
	return testIDPClients(t, []Client{testPublicClient(t), conf}, nil)
}

// TestAuthorizeAllowedScopes pins the per-client delegated-scope allowlist:
// conf-app may request the api:// scopes registered in its own entry — the
// granted scope travels into the token's RFC 9068 scope claim and survives
// the refresh grant — while a foreign resource, an unregistered permission
// name and another client's registered scope are rejected with invalid_scope.
func TestAuthorizeAllowedScopes(t *testing.T) {
	ts, _ := delegatedScopeIDP(t, "a-confidential-secret")

	// A registered delegated scope is granted end to end.
	verifier, _ := pkcePair()
	location := loginForScopes(t, ts.URL, "conf-app", "https://conf.example.com/cb", "bob", "builder", verifier,
		"openid profile api://conf-api/read")
	tokens := decodeJSON(t, postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeFrom(t, location)},
		"redirect_uri":  {"https://conf.example.com/cb"},
		"code_verifier": {verifier},
	}, "conf-app", "a-confidential-secret"))
	if want := "openid profile api://conf-api/read"; tokens["scope"] != want {
		t.Errorf("token response scope = %v, want %q", tokens["scope"], want)
	}
	claims := verifyTokenString(t, tokens["access_token"].(string), ts.URL)
	if claims["scope"] != "openid profile api://conf-api/read" {
		t.Errorf("scope claim = %v, want the full requested scopes (RFC 9068 §2.2.3)", claims["scope"])
	}

	// The refresh grant carries the same granted scopes forward.
	refreshed := decodeJSON(t, postTokenBasic(t, ts.URL+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens["refresh_token"].(string)},
	}, "conf-app", "a-confidential-secret"))
	if refreshed["scope"] != "openid profile api://conf-api/read" {
		t.Errorf("refreshed scope = %v, want the granted scopes", refreshed["scope"])
	}

	// A foreign resource, an unregistered permission name, and another
	// client's (here: unregistered) scope are refused with invalid_scope.
	for _, tc := range []struct {
		name  string
		scope string
	}{
		{"foreign resource", "openid api://demo-api/read"},
		{"unregistered permission", "openid api://conf-api/admin"},
		{"client without registrations", "openid api://conf-api/read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := authorizeFormFor("conf-app", "https://conf.example.com/cb", verifier)
			if tc.name == "client without registrations" {
				q = authorizeFormFor(testClientID, testRedirect, verifier)
			}
			q.Set("scope", tc.scope)
			resp, err := noFollow().Get(ts.URL + "/authorize?" + q.Encode())
			if err != nil {
				t.Fatalf("GET /authorize: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want 302 to the registered redirect_uri", resp.StatusCode)
			}
			loc, err := url.Parse(resp.Header.Get("Location"))
			if err != nil {
				t.Fatalf("bad redirect location: %v", err)
			}
			if got := loc.Query().Get("error"); got != "invalid_scope" {
				t.Errorf("scope=%q: error = %q, want invalid_scope", tc.scope, got)
			}
			if loc.Query().Get("state") != testStateValue {
				t.Errorf("error redirect must echo state, got %q", loc.Query().Get("state"))
			}
		})
	}
}

// loginForScopes runs the authorize round-trip for a client with an explicit
// scope value and returns the redirect target URL.
func loginForScopes(t *testing.T, base, clientID, redirect, user, pass, verifier, scope string) string {
	t.Helper()
	// The CSRF token is bound to the OAuth parameters of the GET-rendered
	// form, so the same parameters (including the custom scope) must be used
	// for both the fetch and the POST body. The credentials are only in the
	// POST body, never in the GET query.
	params := authorizeFormFor(clientID, redirect, verifier)
	params.Set("scope", scope)
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("username", user)
	form.Set("password", pass)
	browser := newBrowser()
	form.Set("csrf_token", fetchCSRF(t, browser, base+"/authorize", params))
	resp := postForm(t, browser, base+"/authorize", form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize for %s: status = %d, want 302", clientID, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}
