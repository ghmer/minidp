// Package idp is a minimal OIDC/OAuth2 identity provider that speaks the
// public-client Authorization Code flow with PKCE. It is designed to be
// drop-in compatible with the OAuth2/OIDC client used by
// github.com/ghmer/rego-adventure (oidc-client-ts on the front-end, JWKS-based
// validation on the back-end).
package idp

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
	// PasswordBcrypt, when set, is a bcrypt hash of the password; the plaintext
	// then never needs to appear in configuration or manifests.
	PasswordBcrypt string
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

// LoadConfig builds a Config from environment variables, applying the documented
// rego-adventure-compatible defaults. It fails fast on misconfiguration that
// would silently weaken security (unreadable secret files, invalid proxy CIDRs,
// conflicting password sources).
func LoadConfig() (Config, error) {
	cfg := Config{
		Host:            envOr("IDP_HOST", "0.0.0.0"),
		Port:            envOr("IDP_PORT", "8080"),
		Issuer:          envOr("IDP_ISSUER", "http://localhost:8080"),
		Username:        envOr("IDP_USERNAME", "rego"),
		AccessTokenTTL:  envDurationSeconds("IDP_ACCESS_TOKEN_TTL", 3600),
		RefreshTokenTTL: envDurationSeconds("IDP_REFRESH_TOKEN_TTL", 7200),
		Title:           envOr("IDP_TITLE", "Rego Adventure"),
		Subtitle:        envOr("IDP_SUBTITLE", "Sign in to begin the adventure"),
		RSAPeM:          os.Getenv("IDP_RSA_PEM"),
		KeyDir:          os.Getenv("IDP_KEY_DIR"),
		LoginRateLimit:  envInt("IDP_LOGIN_RATE_LIMIT", 20),
	}
	if raw := os.Getenv("ALLOWED_REDIRECTS"); raw != "" {
		for _, r := range strings.Split(raw, ",") {
			if r = strings.TrimSpace(r); r != "" {
				cfg.AllowedRedirects = append(cfg.AllowedRedirects, r)
			}
		}
	}

	// Credential source resolution. Exactly one source should be configured;
	// bcrypt wins over a password file, both win over the plaintext default.
	bcryptHash := os.Getenv("IDP_PASSWORD_BCRYPT")
	passwordFile := os.Getenv("IDP_PASSWORD_FILE")
	plainPassword := os.Getenv("IDP_PASSWORD")
	switch {
	case bcryptHash != "":
		if plainPassword != "" {
			return cfg, fmt.Errorf("IDP_PASSWORD and IDP_PASSWORD_BCRYPT are both set; configure exactly one password source")
		}
		cfg.PasswordBcrypt = bcryptHash
	case passwordFile != "":
		if plainPassword != "" {
			return cfg, fmt.Errorf("IDP_PASSWORD and IDP_PASSWORD_FILE are both set; configure exactly one password source")
		}
		// Scope the read to the directory holding the secret file so a crafted
		// path cannot traverse outside it (gosec G304/G703).
		dir, name := filepath.Split(filepath.Clean(passwordFile))
		if dir == "" {
			dir = "."
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return cfg, fmt.Errorf("open password file directory %q: %w", dir, err)
		}
		defer func() { _ = root.Close() }()
		f, err := root.Open(name)
		if err != nil {
			return cfg, fmt.Errorf("read IDP_PASSWORD_FILE: %w", err)
		}
		raw, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return cfg, fmt.Errorf("read IDP_PASSWORD_FILE: %w", err)
		}
		cfg.Password = strings.TrimSpace(string(raw))
		if cfg.Password == "" {
			return cfg, fmt.Errorf("IDP_PASSWORD_FILE %q is empty", passwordFile)
		}
	default:
		cfg.Password = envOr("IDP_PASSWORD", "adventure")
	}

	proxies, err := parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return cfg, err
	}
	cfg.TrustedProxies = proxies
	return cfg, nil
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

func envDurationSeconds(key string, def int) time.Duration {
	return time.Duration(envInt(key, def)) * time.Second
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
