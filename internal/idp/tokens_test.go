package idp

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := New(Config{
		Issuer:          "https://idp.test",
		Username:        "rego",
		Password:        "adventure",
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
		Sub:      "rego",
		ClientID: "rego-adventure",
		Scopes:   []string{"openid", "profile"},
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
	if resp.Scope != "openid profile" {
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
	if access["sub"] != "rego" {
		t.Errorf("access sub = %v", access["sub"])
	}
	aud, _ := access.GetAudience()
	if len(aud) != 1 || aud[0] != "rego-adventure" {
		t.Errorf("access aud = %v, want [rego-adventure]", aud)
	}
	if access["scope"] != "openid profile" {
		t.Errorf("access scope = %v", access["scope"])
	}
	if access["preferred_username"] != "rego" {
		t.Errorf("access preferred_username = %v", access["preferred_username"])
	}

	id := parseWithServer(t, srv, resp.IDToken)
	if id["iss"] != "https://idp.test" || id["sub"] != "rego" {
		t.Errorf("id iss/sub = %v/%v", id["iss"], id["sub"])
	}
	if id["nonce"] != "n-abc" {
		t.Errorf("id nonce = %v, want n-abc (oidc-client-ts validates this)", id["nonce"])
	}
	audID, _ := id.GetAudience()
	if len(audID) != 1 || audID[0] != "rego-adventure" {
		t.Errorf("id aud = %v", audID)
	}
}

func TestIssueTokensWithoutOpenIDScopeOmitsIDToken(t *testing.T) {
	srv := newTestServer(t)
	resp, err := srv.issueTokens(&authContext{
		Sub:      "rego",
		ClientID: "c1",
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
		Sub:      "rego",
		ClientID: "c1",
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
	if entry.Sub != "rego" || entry.ClientID != "c1" {
		t.Errorf("unexpected refresh entry: %+v", entry)
	}
	if entry.Nonce != "keep-me" {
		t.Errorf("refresh entry nonce = %q, want keep-me", entry.Nonce)
	}
}

// TestVerifyAccessTokenRequiresAudience pins the review fix: a correctly
// signed, unexpired token without an aud claim must be rejected by
// userinfo/introspect instead of being accepted for any client.
func TestVerifyAccessTokenRequiresAudience(t *testing.T) {
	srv := newTestServer(t)
	claims := jwt.MapClaims{
		"iss": srv.cfg.Issuer,
		"sub": "rego",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		// deliberately no aud
	}
	signed, err := srv.key.sign(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := srv.verifyAccessToken(signed); err == nil {
		t.Error("a token without an aud claim must be rejected")
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
