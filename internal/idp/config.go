// Package idp is a minimal multi-client OIDC/OAuth2 identity provider. Every
// registered client — declared in the clients file, with its own redirect
// policy, audience and user accounts — speaks the Authorization Code flow
// with PKCE for public clients and, for confidential clients, the
// confidential-client flow with client authentication (client_secret_basic /
// client_secret_post) at the token endpoint. It implements the standard
// endpoints (discovery, JWKS, userinfo, introspection, revocation) so any
// standards-compliant OAuth2/OIDC client library works out of the box —
// browser SPAs using libraries such as oidc-client-ts as well as backend
// resource servers that validate tokens against the published JWKS.
package idp

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the tunable IdP settings. Server placement, key material,
// token lifetimes and rate limiting come from environment variables; the
// registered clients (profile, secrets, redirect policies, audiences,
// accounts) come exclusively from the clients file.
type Config struct {
	// Host is the interface the HTTP server binds to.
	Host string
	// Port is the TCP port the HTTP server listens on.
	Port string
	// Issuer is the authoritative "iss" value written into every JWT and
	// published in the discovery document. Relying parties compare it against
	// the issuer they configured, so it must line up with whatever the client
	// expects.
	Issuer string
	// ClientsFile is the JSON array of registered clients, managed with the
	// clientctl tool. Each entry carries its own profile (public or
	// confidential), redirect policy, audience and user accounts. Changes
	// take effect on restart. It is the only client registration source:
	// the single-client environment variables of earlier versions were
	// removed.
	ClientsFile string
	// AccessTokenTTL is how long an access_token (and id_token) stays valid.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh_token stays valid.
	RefreshTokenTTL time.Duration
	// Title / Subtitle are rendered on the login form.
	Title    string
	Subtitle string
	// RSAPeM, when set, is a path to a PKCS#1/PKCS#8 PEM private key. It takes
	// precedence over KeyDir.
	RSAPeM string
	// KeyDir, when set, makes the IdP persist its signing key: on first start a
	// fresh RSA-2048 key is generated and written to <KeyDir>/minidp-rsa.pem
	// (mode 0600); afterwards it is loaded from there. Mount this directory as
	// a volume (Docker) or generate the key into a Secret (Kubernetes) so
	// tokens stay valid across restarts and replicas.
	KeyDir string
	// TrustedProxies is a list of CIDR ranges (TRUSTED_PROXIES) whose
	// X-Forwarded-For header is honoured when resolving the client IP for rate
	// limiting and audit logs. Empty means: trust no proxy, use the socket
	// address.
	TrustedProxies []string
	// LoginRateLimit is the number of login attempts (POST /authorize and
	// POST /login) allowed per minute and client IP.
	LoginRateLimit int
}

// LoadConfig builds a Config from environment variables, applying the
// documented defaults. It fails fast on misconfiguration that would silently
// weaken security (no clients file, removed single-client or single-user
// variables, unreadable key material, invalid proxy CIDRs).
func LoadConfig() (Config, error) {
	accessTokenTTL, err := envDurationSeconds("IDP_ACCESS_TOKEN_TTL", 3600)
	if err != nil {
		return Config{}, err
	}
	refreshTokenTTL, err := envDurationSeconds("IDP_REFRESH_TOKEN_TTL", 7200)
	if err != nil {
		return Config{}, err
	}
	loginRateLimit, err := envInt("IDP_LOGIN_RATE_LIMIT", 20)
	if err != nil {
		return Config{}, err
	}
	if err := rejectRemovedVariables(); err != nil {
		return Config{}, err
	}
	cfg := Config{
		Host:            envOr("IDP_HOST", "0.0.0.0"),
		Port:            envOr("IDP_PORT", "8080"),
		Issuer:          envOr("IDP_ISSUER", "http://localhost:8080"),
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		Title:           envOr("IDP_TITLE", "minidp"),
		Subtitle:        envOr("IDP_SUBTITLE", "Sign in to continue"),
		RSAPeM:          os.Getenv("IDP_RSA_PEM"),
		KeyDir:          os.Getenv("IDP_KEY_DIR"),
		LoginRateLimit:  loginRateLimit,
		ClientsFile:     os.Getenv("IDP_CLIENTS_FILE"),
	}
	if cfg.ClientsFile == "" {
		return cfg, fmt.Errorf("IDP_CLIENTS_FILE is not set: minidp registers its clients (profiles, redirect policies, audiences and users) in a clients file; create one (see clientctl and clients.json.example) and point IDP_CLIENTS_FILE at it")
	}
	proxies, err := parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return cfg, err
	}
	cfg.TrustedProxies = proxies
	return cfg, nil
}

// removedVariables are the variables of earlier versions that no longer have
// any effect. They are rejected loudly instead of being ignored: a silently
// ignored credential or redirect policy would let an operator believe their
// configuration still governs who can sign in and where codes are sent.
// The single-user credential variables predate the users file; the
// single-client variables predate the clients file.
var removedVariables = []string{
	// Single-user credentials (removed when the users file became the only
	// account source; obsolete since the clients file).
	"IDP_USERNAME", "IDP_PASSWORD", "IDP_PASSWORD_BCRYPT", "IDP_PASSWORD_FILE",
	// Single-client registration (replaced by the clients file).
	"IDP_CLIENT_ID", "IDP_AUDIENCE", "IDP_CLIENT_SECRET", "ALLOWED_REDIRECTS",
	"IDP_ALLOWED_ORIGINS", "IDP_USERS_FILE", "MINIDP_MODE",
}

func rejectRemovedVariables() error {
	for _, removed := range removedVariables {
		if os.Getenv(removed) != "" {
			return fmt.Errorf("%s is no longer supported: register clients in the IDP_CLIENTS_FILE clients file (see clientctl and clients.json.example)", removed)
		}
	}
	return nil
}

// parseTrustedProxies validates a comma-separated list of CIDR ranges.
func parseTrustedProxies(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []string
	for _, cidr := range strings.Split(raw, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid CIDR range %q in TRUSTED_PROXIES: %w", cidr, err)
		}
		out = append(out, cidr)
	}
	if len(out) > 0 {
		slog.Info("trusted proxies configured", "proxies", out)
	}
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDurationSeconds(key string, def int) (time.Duration, error) {
	n, err := envInt(key, def)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

// envInt parses a positive integer environment variable, falling back to def
// only when the variable is unset or empty. A set but unparseable or
// non-positive value is an error: the package contract is to fail fast on
// misconfiguration instead of silently weakening a security control.
func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: must be a whole number", key, v)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid %s %q: must be positive", key, v)
	}
	return n, nil
}
