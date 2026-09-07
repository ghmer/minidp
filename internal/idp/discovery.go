package idp

import "net/http"

// handleDiscovery serves the OIDC discovery document. Clients fetch
// <issuer>/.well-known/openid-configuration to learn the
// endpoint URLs and the jwks_uri used for JWT validation.
func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	// Client authentication methods are provider-wide metadata: "none" is
	// always available (public clients identify themselves with client_id
	// only); the secret-based methods are advertised when at least one
	// registered client is confidential.
	clientAuthMethods := []string{"none"}
	if s.clients.anyConfidential() {
		clientAuthMethods = append(clientAuthMethods, "client_secret_basic", "client_secret_post")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                        s.cfg.Issuer,
		"authorization_endpoint":                        s.cfg.Issuer + "/authorize",
		"token_endpoint":                                s.cfg.Issuer + "/token",
		"jwks_uri":                                      s.cfg.Issuer + "/jwks",
		"userinfo_endpoint":                             s.cfg.Issuer + "/userinfo",
		"revocation_endpoint":                           s.cfg.Issuer + "/revoke",
		"introspection_endpoint":                        s.cfg.Issuer + "/introspect",
		"end_session_endpoint":                          s.cfg.Issuer + "/end_session",
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"token_endpoint_auth_methods_supported":         clientAuthMethods,
		"revocation_endpoint_auth_methods_supported":    clientAuthMethods,
		"introspection_endpoint_auth_methods_supported": clientAuthMethods,
		"code_challenge_methods_supported":              []string{"S256"},
		"scopes_supported":                              []string{"openid", "profile", "email"},
		"claims_supported": []string{
			// Exactly the claims minidp actually issues. auth_time was
			// previously advertised but never embedded in any token.
			"iss", "sub", "aud", "exp", "iat", "nonce",
			"preferred_username", "email", "name",
		},
	})
}

// handleJWKS serves the JSON Web Key Set with the RSA public signing key.
// Resource servers verify access-token signatures against this key set.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.key.JWKS())
}
