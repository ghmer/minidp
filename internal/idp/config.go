// Package idp is a minimal OIDC/OAuth2 identity provider that speaks the
// public-client Authorization Code flow with PKCE. It is designed to be
// drop-in compatible with the OAuth2/OIDC client used by
// github.com/ghmer/rego-adventure (oidc-client-ts on the front-end, JWKS-based
// validation on the back-end).
package idp

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all tunable IdP settings. Every field is overridable through an
// environment variable so the user identity ("rego"/"adventure" by default) and
// every URL can be configured without recompiling.
type Config struct {
	// Host is the interface the HTTP server binds to.
	Host string
	// Port is the TCP port the HTTP server listens on.
	Port string
	// Issuer is the authoritative "iss" value written into every JWT and
	// published in the discovery document. rego-adventure compares this against
	// its AUTH_ISSUER, so it must line up with whatever the relying party expects.
	Issuer string
	// Username / Password are the single user accepted by the IdP.
	Username string
	Password string
	// AccessTokenTTL is how long an access_token (and id_token) stays valid.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh_token stays valid.
	RefreshTokenTTL time.Duration
	// AllowedRedirects restricts the redirect_uri values honoured on /authorize.
	// When empty, any well-formed http(s) redirect_uri is accepted.
	AllowedRedirects []string
	// Title / Subtitle are rendered on rego-adventure-styled login form.
	Title    string
	Subtitle string
	// RSAPeM, when set, is a path to a PKCS#1 PEM private key. When empty a
	// fresh RSA-2048 key is generated at startup (tokens then die on restart).
	RSAPeM string
}

// LoadConfig builds a Config from environment variables, applying the documented
// rego-adventure-compatible defaults.
func LoadConfig() Config {
	cfg := Config{
		Host:            envOr("IDP_HOST", "0.0.0.0"),
		Port:            envOr("IDP_PORT", "8080"),
		Issuer:          envOr("IDP_ISSUER", "http://localhost:8080"),
		Username:        envOr("IDP_USERNAME", "rego"),
		Password:        envOr("IDP_PASSWORD", "adventure"),
		AccessTokenTTL:  envDurationSeconds("IDP_ACCESS_TOKEN_TTL", 3600),
		RefreshTokenTTL: envDurationSeconds("IDP_REFRESH_TOKEN_TTL", 7200),
		Title:           envOr("IDP_TITLE", "Rego Adventure"),
		Subtitle:        envOr("IDP_SUBTITLE", "Sign in to begin the adventure"),
		RSAPeM:          os.Getenv("IDP_RSA_PEM"),
	}
	if raw := os.Getenv("ALLOWED_REDIRECTS"); raw != "" {
		for _, r := range strings.Split(raw, ",") {
			if r = strings.TrimSpace(r); r != "" {
				cfg.AllowedRedirects = append(cfg.AllowedRedirects, r)
			}
		}
	}
	return cfg
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurationSeconds(key string, def int) time.Duration {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(def) * time.Second
}
