package idp

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	clientsFile := filepath.Join(t.TempDir(), "clients.json")
	if err := SaveClients(clientsFile, []Client{testPublicClient(t)}); err != nil {
		t.Fatalf("SaveClients: %v", err)
	}
	srv, err := New(Config{
		Issuer:          "https://idp.test",
		ClientsFile:     clientsFile,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func parseWithServer(t *testing.T, srv *Server, tokenString string) jwt.MapClaims {
	t.Helper()
	parsed, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) {
		return &srv.key.key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		t.Fatalf("token did not verify: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}
	return claims
}

func TestIssueTokensAccessAndIDClaims(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.issueTokens(&authContext{
		Sub:      "demo",
		ClientID: testClientID,
		Scopes:   []string{"openid", "profile", "email"},
		Nonce:    "n-abc",
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != int(time.Hour.Seconds()) {
		t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, int(time.Hour.Seconds()))
	}
	if resp.Scope != "openid profile email" {
		t.Errorf("Scope = %q", resp.Scope)
	}
	if resp.RefreshToken == "" {
		t.Fatal("expected a refresh token to be issued")
	}
	if resp.IDToken == "" {
		t.Fatal("expected an id_token for the openid scope")
	}

	access := parseWithServer(t, srv, resp.AccessToken)
	if access["iss"] != "https://idp.test" {
		t.Errorf("access iss = %v", access["iss"])
	}
	if access["sub"] != "demo" {
		t.Errorf("access sub = %v", access["sub"])
	}
	aud, _ := access.GetAudience()
	if len(aud) != 1 || aud[0] != "demo-app" {
		t.Errorf("access aud = %v, want [demo-app]", aud)
	}
	if access["scope"] != "openid profile email" {
		t.Errorf("access scope = %v", access["scope"])
	}
	if access["preferred_username"] != "demo" {
		t.Errorf("access preferred_username = %v", access["preferred_username"])
	}
	if access["email"] != "demo@example.com" {
		t.Errorf("access email = %v", access["email"])
	}

	id := parseWithServer(t, srv, resp.IDToken)
	if id["iss"] != "https://idp.test" || id["sub"] != "demo" {
		t.Errorf("id iss/sub = %v/%v", id["iss"], id["sub"])
	}
	if id["nonce"] != "n-abc" {
		t.Errorf("id nonce = %v, want n-abc (oidc-client-ts validates this)", id["nonce"])
	}
	audID, _ := id.GetAudience()
	if len(audID) != 1 || audID[0] != "demo-app" {
		t.Errorf("id aud = %v", audID)
	}
}

// TestIssueTokensReleasesClaimsByScope pins the OIDC scope model: profile
// unlocks preferred_username/name, email unlocks email, and nothing is
// fabricated when the users-file record lacks a value.
func TestIssueTokensReleasesClaimsByScope(t *testing.T) {
	srv := newTestServer(t)

	// openid only: no profile claims.
	resp, err := srv.issueTokens(&authContext{
		Sub:      "demo",
		ClientID: testClientID,
		Scopes:   []string{"openid"},
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	access := parseWithServer(t, srv, resp.AccessToken)
	if _, has := access["preferred_username"]; has {
		t.Error("preferred_username must not be released without the profile scope")
	}
	if _, has := access["email"]; has {
		t.Error("email must not be released without the email scope")
	}

	// profile scope for a user without profile data (removed from the file):
	// nothing is fabricated.
	resp2, err := srv.issueTokens(&authContext{
		Sub:      "ghost",
		ClientID: testClientID,
		Scopes:   []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	ghost := parseWithServer(t, srv, resp2.AccessToken)
	if _, has := ghost["email"]; has {
		t.Error("no email must be fabricated for a subject without an email address")
	}
}

// TestIssueTokensReleasesRoles pins the roles behaviour: a users-file record
// with roles gets the roles array claim on both the access and the ID token,
// independent of the granted scopes, while a user without roles gets no roles
// claim at all.
func TestIssueTokensReleasesRoles(t *testing.T) {
	clientsFile := filepath.Join(t.TempDir(), "clients.json")
	client := testPublicClient(t)
	client.Users = []User{
		{Username: "alice", PasswordHash: testHash(t, "wonderland"), Roles: []string{"admin", "auditor"}},
		{Username: "bob", PasswordHash: testHash(t, "builder")},
	}
	if err := SaveClients(clientsFile, []Client{client}); err != nil {
		t.Fatalf("SaveClients: %v", err)
	}
	srv, err := New(Config{
		Issuer:          "https://idp.test",
		ClientsFile:     clientsFile,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Roles are released regardless of the granted scopes.
	resp, err := srv.issueTokens(&authContext{
		Sub:      "alice",
		ClientID: testClientID,
		Scopes:   []string{"openid"},
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	access := parseWithServer(t, srv, resp.AccessToken)
	want := []any{"admin", "auditor"}
	if got, ok := access["roles"].([]any); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("access roles = %v, want %v", access["roles"], want)
	}
	id := parseWithServer(t, srv, resp.IDToken)
	if got, ok := id["roles"].([]any); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("id roles = %v, want %v", id["roles"], want)
	}

	// A user without roles gets no roles claim.
	resp2, err := srv.issueTokens(&authContext{
		Sub:      "bob",
		ClientID: testClientID,
		Scopes:   []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	access2 := parseWithServer(t, srv, resp2.AccessToken)
	if _, has := access2["roles"]; has {
		t.Error("a user without roles must not get a roles claim on the access token")
	}
	id2 := parseWithServer(t, srv, resp2.IDToken)
	if _, has := id2["roles"]; has {
		t.Error("a user without roles must not get a roles claim on the id token")
	}
}

func TestIssueTokensWithoutOpenIDScopeOmitsIDToken(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.issueTokens(&authContext{
		Sub:      "demo",
		ClientID: testClientID,
		Scopes:   []string{"profile"},
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	if resp.IDToken != "" {
		t.Errorf("id_token issued without the openid scope: %q", resp.IDToken)
	}
}

func TestIssueTokensStoresRedeemableRefreshToken(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.issueTokens(&authContext{
		Sub:      "demo",
		ClientID: testClientID,
		Scopes:   []string{"openid"},
		Nonce:    "keep-me",
	})
	if err != nil {
		t.Fatalf("issueTokens: %v", err)
	}
	entry, reused := srv.store.takeRefresh(resp.RefreshToken)
	if entry == nil || reused {
		t.Fatal("issued refresh token is not redeemable")
	}
	if entry.Sub != "demo" || entry.ClientID != testClientID {
		t.Errorf("unexpected refresh entry: %+v", entry)
	}
	if entry.Nonce != "keep-me" {
		t.Errorf("refresh entry nonce = %q, want keep-me", entry.Nonce)
	}
}

// signedTestToken signs arbitrary claims as an access token (at+jwt) or id
// token (JWT) of the test server.
func signedTestToken(t *testing.T, srv *Server, claims jwt.MapClaims, access bool) string {
	t.Helper()
	var err error
	var signed string
	if access {
		signed, err = srv.key.signAccess(claims)
	} else {
		signed, err = srv.key.sign(claims)
	}
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// TestVerifyAccessTokenRequiresAudience pins the H4 fix: a correctly signed,
// unexpired access token whose audience does not belong to a registered
// client must be rejected by userinfo/introspect instead of being accepted
// for any audience.
func TestVerifyAccessTokenRequiresAudience(t *testing.T) {
	srv := newTestServer(t)
	base := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "demo",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	// No aud at all.
	if _, err := srv.verifyAccessToken(signedTestToken(t, srv, base, true)); err == nil {
		t.Error("a token without an aud claim must be rejected")
	}

	// A foreign audience.
	wrong := jwt.MapClaims{}
	for k, v := range base {
		wrong[k] = v
	}
	wrong["aud"] = "some-other-client"
	if _, err := srv.verifyAccessToken(signedTestToken(t, srv, wrong, true)); err == nil {
		t.Error("a token minted for another audience must be rejected")
	}

	// The configured audience is accepted.
	right := jwt.MapClaims{}
	for k, v := range base {
		right[k] = v
	}
	right["aud"] = testClientID
	if _, err := srv.verifyAccessToken(signedTestToken(t, srv, right, true)); err != nil {
		t.Errorf("a token for the configured audience must be accepted: %v", err)
	}
}

// TestIDTokenRejectedAsAccessToken pins the H3 fix: an id_token (typ JWT)
// must never pass as a bearer access token, even with otherwise valid claims.
func TestIDTokenRejectedAsAccessToken(t *testing.T) {
	srv := newTestServer(t)
	claims := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "demo",
		"aud": testClientID,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	idToken := signedTestToken(t, srv, claims, false)
	if _, err := srv.verifyAccessToken(idToken); err == nil {
		t.Error("an id_token must be rejected as a bearer access token")
	}
	// The same claims with the access-token profile pass.
	if _, err := srv.verifyAccessToken(signedTestToken(t, srv, claims, true)); err != nil {
		t.Errorf("an at+jwt token must be accepted: %v", err)
	}
}

// TestParseIDTokenHintAcceptsExpired pins the M6 fix: an expired
// id_token_hint still identifies the token family for /end_session.
func TestParseIDTokenHintAcceptsExpired(t *testing.T) {
	srv := newTestServer(t)
	claims := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "demo",
		"aud": testClientID,
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"sid": "family-1",
	}
	hint := signedTestToken(t, srv, claims, false)
	parsed, client, err := srv.parseIDTokenHint(hint)
	if err != nil {
		t.Fatalf("expired id_token_hint rejected: %v", err)
	}
	if client == nil || client.ID() != testClientID {
		t.Errorf("hint client = %v, want %q", client, testClientID)
	}
	if parsed["sid"] != "family-1" {
		t.Errorf("sid = %v, want family-1", parsed["sid"])
	}

	// Access tokens and foreign issuers stay rejected.
	if _, _, err := srv.parseIDTokenHint(signedTestToken(t, srv, claims, true)); err == nil {
		t.Error("an access token must be rejected as id_token_hint")
	}
	foreign := jwt.MapClaims{}
	for k, v := range claims {
		foreign[k] = v
	}
	foreign["iss"] = "https://evil.example"
	if _, _, err := srv.parseIDTokenHint(signedTestToken(t, srv, foreign, false)); err == nil {
		t.Error("a hint from another issuer must be rejected")
	}
}

// TestPKCESyntaxValidation pins the L1 fix: verifiers must satisfy the RFC
// 7636 syntax and length, challenges must be base64url of the right length.
func TestPKCESyntaxValidation(t *testing.T) {
	// 66 characters of the RFC 7636 unreserved set.
	good := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	if len(good) != 66 || !validPKCEVerifier(good) {
		t.Fatalf("the reference verifier must pass: %d chars", len(good))
	}
	if validPKCEVerifier("short") {
		t.Error("verifiers below 43 characters must be rejected")
	}
	if validPKCEVerifier(good[:42] + "+") {
		t.Error("verifiers with reserved characters must be rejected")
	}
	if validPKCEVerifier(good[:42] + "%") {
		t.Error("verifiers with percent-escapes must be rejected")
	}
	exactly128 := strings.Repeat(good, 2)[:128]
	if !validPKCEVerifier(exactly128) {
		t.Error("a 128-character verifier must pass")
	}
	if validPKCEVerifier(strings.Repeat(good, 2)[:129]) {
		t.Error("verifiers above 128 characters must be rejected")
	}

	challenge := pkceS256(good)
	if !validPKCEChallenge(challenge) {
		t.Error("a valid S256 challenge must pass")
	}
	if validPKCEChallenge(challenge + "=") { // padding is not allowed
		t.Error("a padded challenge must be rejected")
	}
	if validPKCEChallenge("tooshort") {
		t.Error("a too-short challenge must be rejected")
	}
}

func TestJoinScopesDeduplicatesAndKeepsOrder(t *testing.T) {
	got := joinScopes([]string{"openid", "profile", "openid", "", "email", "profile"})
	if got != "openid profile email" {
		t.Errorf("joinScopes = %q", got)
	}
	if joinScopes(nil) != "" {
		t.Error("joinScopes(nil) should be empty")
	}
}

func TestHasScope(t *testing.T) {
	scopes := []string{"openid", "profile"}
	if !hasScope(scopes, "openid") {
		t.Error("hasScope should find openid")
	}
	if hasScope(scopes, "email") {
		t.Error("hasScope should not find email")
	}
	if hasScope(nil, "openid") {
		t.Error("hasScope on nil should be false")
	}
}

func TestParseScopesDefaultsToOpenID(t *testing.T) {
	cases := map[string][]string{
		"":                  {"openid"},
		"   ":               {"openid"},
		"openid":            {"openid"},
		"openid  profile  ": {"openid", "profile"},
		"a\tb":              {"a", "b"},
	}
	for in, want := range cases {
		if got := parseScopes(in); len(got) != len(want) || got[0] != want[0] {
			t.Errorf("parseScopes(%q) = %v, want %v", in, got, want)
		}
	}
}
