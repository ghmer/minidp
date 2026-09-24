package idp

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// testServiceClient returns an M2M-only client registration: confidential,
// client_credentials as its only grant, no users and no redirect URIs — the
// registry accepts exactly this shape for purely-service clients.
func testServiceClient(t *testing.T, clientID, secret string) Client {
	t.Helper()
	return Client{
		ClientID:                clientID,
		Type:                    TypeConfidential,
		ClientSecret:            secret,
		Audience:                "fake-hr",
		GrantTypes:              []string{GrantClientCredentials},
		ClientCredentialsScopes: []string{"fake-hr:read", "fake-hr:write"},
	}
}

// ccToken requests a client_credentials token with client_secret_basic.
func ccToken(t *testing.T, target, clientID, secret string) *http.Response {
	t.Helper()
	return postTokenBasic(t, target, url.Values{"grant_type": {"client_credentials"}}, clientID, secret)
}

// TestClientCredentialsHappyPath drives the M2M grant end to end: the
// confidential service client authenticates with client_secret_basic and
// receives an access token for its configured audience and scopes — with
// sub = client_id, no id_token and no refresh token.
func TestClientCredentialsHappyPath(t *testing.T) {
	ts, _ := testIDPClients(t, []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}, nil)

	resp := ccToken(t, ts.URL+"/token", "fake-hr-mcp-service", "a-confidential-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
	tokens := decodeJSON(t, resp)
	if tokens["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tokens["token_type"])
	}
	if tokens["id_token"] != nil || tokens["refresh_token"] != nil {
		t.Errorf("client_credentials must not issue id_token/refresh_token, got %v", tokens)
	}
	if tokens["scope"] != "fake-hr:read fake-hr:write" {
		t.Errorf("scope = %v, want the statically configured scopes", tokens["scope"])
	}

	claims := verifyTokenString(t, tokens["access_token"].(string), ts.URL)
	if claims["sub"] != "fake-hr-mcp-service" {
		t.Errorf("sub = %v, want the client_id", claims["sub"])
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "fake-hr" {
		t.Errorf("aud = %v, want [fake-hr]", claims["aud"])
	}
	if scope, _ := claims["scope"].(string); scope != "fake-hr:read fake-hr:write" {
		t.Errorf("token scope = %v, want the configured scopes", claims["scope"])
	}
	for _, banned := range []string{"preferred_username", "email", "roles"} {
		if _, present := claims[banned]; present {
			t.Errorf("token must not carry the user claim %q", banned)
		}
	}
}

// TestClientCredentialsClientSecretPost pins the second documented client
// authentication method for the M2M grant.
func TestClientCredentialsClientSecretPost(t *testing.T) {
	ts, _ := testIDPClients(t, []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}, nil)

	resp := postForm(t, http.DefaultClient, ts.URL+"/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"fake-hr-mcp-service"},
		"client_secret": {"a-confidential-secret"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("client_secret_post: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestClientCredentialsRejectsWrongSecret pins that the grant honours client
// authentication: a wrong secret is invalid_client, not a token.
func TestClientCredentialsRejectsWrongSecret(t *testing.T) {
	ts, _ := testIDPClients(t, []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}, nil)

	resp := ccToken(t, ts.URL+"/token", "fake-hr-mcp-service", "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong secret: status = %d, want 401", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_client" {
		t.Errorf("wrong secret: error = %v, want invalid_client", got)
	}
}

// TestClientCredentialsRequiresOptIn pins the policy checks: a public client
// and a confidential client without the client_credentials grant both answer
// unauthorized_client (RFC 6749 §5.2), not a token.
func TestClientCredentialsRequiresOptIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		client func(t *testing.T) Client
	}{
		{"public client", func(t *testing.T) Client { return testPublicClient(t) }},
		{"confidential client without the grant", func(t *testing.T) Client {
			c := testConfidentialClient(t, "a-confidential-secret")
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.client(t)
			if c.Confidential() {
				c.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
			}
			ts, _ := testIDPClients(t, []Client{c}, nil)
			// A public client cannot authenticate, so it identifies itself
			// with the client_id form field (the Basic header carries no
			// credential for it); the confidential client authenticates with
			// Basic.
			resp := postTokenBasic(t, ts.URL+"/token", url.Values{
				"grant_type": {"client_credentials"},
				"client_id":  {testClientID},
			}, testClientID, "a-confidential-secret")
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if got := decodeJSON(t, resp)["error"]; got != "unauthorized_client" {
				t.Errorf("error = %v, want unauthorized_client", got)
			}
		})
	}
}

// TestClientCredentialsIgnoresRequestedScope pins the static scope policy:
// the grant has no consent step, so a requested scope parameter must not
// widen (or change) the configured scopes.
func TestClientCredentialsIgnoresRequestedScope(t *testing.T) {
	ts, _ := testIDPClients(t, []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}, nil)

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"openid profile email"}}
	resp := postTokenBasic(t, ts.URL+"/token", form, "fake-hr-mcp-service", "a-confidential-secret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: status = %d, body = %v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["scope"]; got != "fake-hr:read fake-hr:write" {
		t.Errorf("scope = %v, want the configured scopes despite the request", got)
	}
}

// TestClientCredentialsRevocable pins that the M2M access token is tracked:
// /revoke with the client's credentials denies the jti, and a subsequent
// verify rejects the token.
func TestClientCredentialsRevocable(t *testing.T) {
	ts, _ := testIDPClients(t, []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}, nil)

	resp := ccToken(t, ts.URL+"/token", "fake-hr-mcp-service", "a-confidential-secret")
	tokens := decodeJSON(t, resp)
	token := tokens["access_token"].(string)

	verifyTokenString(t, token, ts.URL)

	revoke := postForm(t, http.DefaultClient, ts.URL+"/revoke", url.Values{
		"client_id":     {"fake-hr-mcp-service"},
		"client_secret": {"a-confidential-secret"},
		"token":         {token},
	})
	_ = revoke.Body.Close()
	if revoke.StatusCode != http.StatusOK {
		t.Fatalf("POST /revoke: status = %d", revoke.StatusCode)
	}
	revoked := decodeJSON(t, postForm(t, http.DefaultClient, ts.URL+"/introspect", url.Values{
		"client_id":     {"fake-hr-mcp-service"},
		"client_secret": {"a-confidential-secret"},
		"token":         {token},
	}))
	if revoked["active"] != false {
		t.Errorf("introspection of a revoked token = %v, want active=false", revoked["active"])
	}
}

// TestClientCredentialsServiceClientWithoutUsersPins the registry rules for
// M2M-only clients: no users and no redirect URIs are accepted, while an
// interactive client without users is still refused at startup.
func TestClientCredentialsServiceClientWithoutUsers(t *testing.T) {
	t.Run("M2M-only client starts without users and redirects", func(t *testing.T) {
		ts, _ := testIDPClients(t, []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}, nil)
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})
	t.Run("interactive client still requires users", func(t *testing.T) {
		c := testConfidentialClient(t, "a-confidential-secret")
		c.Users = nil
		if _, err := newClientRegistry([]Client{c}); err == nil {
			t.Error("interactive client without users must be refused")
		}
	})
	t.Run("interactive client still requires redirect_uris", func(t *testing.T) {
		c := testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")
		c.GrantTypes = []string{GrantClientCredentials, GrantAuthorizationCode}
		if err := c.validate(); err == nil {
			t.Error("client_credentials + authorization_code without redirect_uris must be refused")
		}
	})
}

// TestClientCredentialsValidation pins the clients-file validation of the
// new fields.
func TestClientCredentialsValidation(t *testing.T) {
	base := func(t *testing.T) Client { return testServiceClient(t, "svc", "a-confidential-secret") }
	for _, tc := range []struct {
		name    string
		mutate  func(*Client)
		wantErr string
	}{
		{"client_credentials for a public client", func(c *Client) {
			c.Type = TypePublic
			c.ClientSecret = ""
		}, "requires the confidential profile"},
		{"grant without configured scopes", func(c *Client) {
			c.ClientCredentialsScopes = nil
		}, "non-empty client_credentials_scopes"},
		{"scopes without the grant", func(c *Client) {
			c.GrantTypes = nil
		}, "client_credentials_scopes are set but the"},
		{"unknown grant name", func(c *Client) {
			c.GrantTypes = []string{"implicit"}
		}, "invalid grant type"},
		{"duplicate grant name", func(c *Client) {
			c.GrantTypes = []string{GrantClientCredentials, GrantClientCredentials}
		}, "duplicate grant type"},
		{"scope with whitespace", func(c *Client) {
			c.ClientCredentialsScopes = []string{"fake-hr read"}
		}, "whitespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base(t)
			tc.mutate(&c)
			err := c.validate()
			if err == nil {
				t.Fatalf("validate = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
	t.Run("default grants stay backward compatible", func(t *testing.T) {
		c := testConfidentialClient(t, "a-confidential-secret")
		if !c.AllowsGrant(GrantAuthorizationCode) || !c.AllowsGrant(GrantRefreshToken) {
			t.Error("clients without grant_types must default to authorization_code + refresh_token")
		}
		if c.AllowsGrant(GrantClientCredentials) {
			t.Error("client_credentials must stay opt-in")
		}
	})
}

// discoveryJSON fetches a discovery document and decodes it.
func discoveryJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d", url, resp.StatusCode)
	}
	return decodeJSON(t, resp)
}

// TestDiscoveryGrantTypesAndOAuthMetadata pins the discovery additions:
// client_credentials is advertised only when a client is opted in, and the
// RFC 8414 metadata path serves the same document.
func TestDiscoveryGrantTypesAndOAuthMetadata(t *testing.T) {
	for _, tc := range []struct {
		name          string
		clients       func(t *testing.T) []Client
		wantGrantList []string
	}{
		{"without M2M client", func(t *testing.T) []Client { return nil },
			[]string{"authorization_code", "refresh_token"}},
		{"with M2M client", func(t *testing.T) []Client {
			return []Client{testServiceClient(t, "fake-hr-mcp-service", "a-confidential-secret")}
		},
			[]string{"authorization_code", "refresh_token", "client_credentials"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, _ := testIDPClients(t, tc.clients(t), nil)
			d := discoveryJSON(t, ts.URL+"/.well-known/openid-configuration")
			got, _ := d["grant_types_supported"].([]any)
			if len(got) != len(tc.wantGrantList) {
				t.Fatalf("grant_types_supported = %v, want %v", got, tc.wantGrantList)
			}
			for i, want := range tc.wantGrantList {
				if got[i] != want {
					t.Errorf("grant_types_supported = %v, want %v", got, tc.wantGrantList)
					break
				}
			}
			// The RFC 8414 path must mirror the OIDC document.
			oidc := discoveryJSON(t, ts.URL+"/.well-known/openid-configuration")
			oauth := discoveryJSON(t, ts.URL+"/.well-known/oauth-authorization-server")
			if !reflect.DeepEqual(oidc, oauth) {
				t.Error("oauth-authorization-server metadata differs from openid-configuration")
			}
		})
	}
}
