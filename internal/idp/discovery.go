package idp

import "net/http"

// grantTypesSupported lists the token-endpoint grants this provider
// implements. The client_credentials grant (RFC 6749 §4.4) is advertised
// only when at least one registered client is enabled for it.
func (s *Server) grantTypesSupported() []string {
	grants := []string{GrantAuthorizationCode, GrantRefreshToken}
	if s.clients.anyClientCredentials() {
		grants = append(grants, GrantClientCredentials)
	}
	return grants
}

// handleDiscovery serves the OIDC discovery document. Clients fetch
// <issuer>/.well-known/openid-configuration to learn the
// endpoint URLs and the jwks_uri used for JWT validation.
// The same document is served at /.well-known/oauth-authorization-server,
// the RFC 8414 metadata path that OAuth-only (non-OIDC) clients probe.
func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.discoveryDocument())
}

// discoveryDocument assembles the OIDC discovery metadata. It is shared by
// the discovery endpoints and the /readyz readiness self-check.
func (s *Server) discoveryDocument() map[string]any {
	// Client authentication methods are provider-wide metadata: "none" is
	// always available (public clients identify themselves with client_id
	// only); the secret-based methods are advertised when at least one
	// registered client is confidential.
	clientAuthMethods := []string{"none"}
	if s.clients.anyConfidential() {
		clientAuthMethods = append(clientAuthMethods, "client_secret_basic", "client_secret_post")
	}
	return map[string]any{
		"issuer":                                        s.cfg.Issuer,
		"authorization_endpoint":                        s.cfg.Issuer + "/authorize",
		"token_endpoint":                                s.cfg.Issuer + "/token",
		"jwks_uri":                                      s.cfg.Issuer + "/jwks",
		"userinfo_endpoint":                             s.cfg.Issuer + "/userinfo",
		"revocation_endpoint":                           s.cfg.Issuer + "/revoke",
		"introspection_endpoint":                        s.cfg.Issuer + "/introspect",
		"end_session_endpoint":                          s.cfg.Issuer + "/end_session",
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         s.grantTypesSupported(),
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"token_endpoint_auth_methods_supported":         clientAuthMethods,
		"revocation_endpoint_auth_methods_supported":    clientAuthMethods,
		"introspection_endpoint_auth_methods_supported": clientAuthMethods,
		"code_challenge_methods_supported":              []string{"S256"},
		"scopes_supported":                              s.scopesSupported(),
		"claims_supported": []string{
			// Exactly the claims minidp actually issues. auth_time was
			// previously advertised but never embedded in any token.
			// client_id is the RFC 9068 access-token claim.
			"iss", "sub", "aud", "exp", "iat", "client_id", "nonce",
			"preferred_username", "email", "name",
		},
	}
}

// scopesSupported assembles the advertised scope set: the built-in OIDC
// scopes plus every client's registered custom delegated scopes (OIDC
// Discovery §5.2 — the advertised set is what requests are validated
// against).
func (s *Server) scopesSupported() []string {
	return append([]string{"openid", "profile", "email"}, s.clients.delegatedScopes()...)
}

// handleJWKS serves the JSON Web Key Set with the RSA public signing key.
// Resource servers verify access-token signatures against this key set.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.keys.JWKS())
}
