// Package idp is a minimal OIDC/OAuth2 identity provider that speaks the
// public-client Authorization Code flow with PKCE. It is designed to be
// drop-in compatible with the OAuth2/OIDC client used by
// github.com/ghmer/rego-adventure (oidc-client-ts on the front-end, JWKS-based
// validation on the back-end).
package idp

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
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
	// Username / Password are the single user accepted by the IdP (used in
	// single-user mode; empty in multi-user mode when UsersFile is set).
	Username string
	Password string
	// PasswordBcrypt, when set, is a bcrypt hash of the password; the plaintext
	// then never needs to appear in configuration or manifests.
	PasswordBcrypt string
	// UsersFile, when set, switches the IdP to multi-user mode: the file is a
	// JSON array of User entries with bcrypt password hashes, managed with the
	// minidp-users tool. It takes precedence over the single-user credentials,
	// which must then not be configured at all. Changes take effect on restart.
	UsersFile string
	// AccessTokenTTL is how long an access_token (and id_token) stays valid.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh_token stays valid.
	RefreshTokenTTL time.Duration
	// AllowedRedirects restricts the redirect_uri values honoured on /authorize.
	// When empty, any well-formed http(s) redirect_uri is accepted.
	AllowedRedirects []string
	// AllowedOrigins is the explicit CORS origin allowlist (IDP_ALLOWED_ORIGINS).
	// Origins are additionally derived from the ALLOWED_REDIRECTS entries.
	// Only allowlisted origins are reflected with credentials; any other
	// Origin header receives no CORS grant at all.
	AllowedOrigins []string
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
	// ClientSecret (IDP_CLIENT_SECRET), when set, makes /introspect and
	// /revoke require client authentication: HTTP Basic auth with any
	// username and this secret as the password, or a client_secret form
	// field. Unset leaves both endpoints open (bounded risk: tokens are
	// 256-bit random, but an open /revoke is a free probe endpoint).
	ClientSecret string
	// LoginRateLimit is the number of login attempts (POST /authorize and
	// POST /login) allowed per minute and client IP.
	LoginRateLimit int
}

// LoadConfig builds a Config from environment variables, applying the documented
// rego-adventure-compatible defaults. It fails fast on misconfiguration that
// would silently weaken security (unreadable secret files, invalid proxy CIDRs,
// conflicting password sources).
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
	cfg := Config{
		Host:            envOr("IDP_HOST", "0.0.0.0"),
		Port:            envOr("IDP_PORT", "8080"),
		Issuer:          envOr("IDP_ISSUER", "http://localhost:8080"),
		Username:        envOr("IDP_USERNAME", "rego"),
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		Title:           envOr("IDP_TITLE", "Rego Adventure"),
		Subtitle:        envOr("IDP_SUBTITLE", "Sign in to begin the adventure"),
		RSAPeM:          os.Getenv("IDP_RSA_PEM"),
		KeyDir:          os.Getenv("IDP_KEY_DIR"),
		LoginRateLimit:  loginRateLimit,
		ClientSecret:    os.Getenv("IDP_CLIENT_SECRET"),
	}
	if raw := os.Getenv("ALLOWED_REDIRECTS"); raw != "" {
		for _, r := range strings.Split(raw, ",") {
			if r = strings.TrimSpace(r); r == "" {
				continue
			}
			// Fail fast on entries that could never be honoured safely: in
			// allowlist mode redirectURIAllowed is a plain string comparison,
			// so a typo'd or non-http(s) entry would otherwise be accepted
			// silently (e.g. a javascript: URI in the allowlist).
			u, err := url.Parse(r)
			if err != nil {
				return cfg, fmt.Errorf("invalid ALLOWED_REDIRECTS entry %q: %w", r, err)
			}
			if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
				return cfg, fmt.Errorf("invalid ALLOWED_REDIRECTS entry %q: must be an absolute http(s) URL with a host", r)
			}
			cfg.AllowedRedirects = append(cfg.AllowedRedirects, r)
		}
	}
	if raw := os.Getenv("IDP_ALLOWED_ORIGINS"); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if o = strings.TrimSpace(o); o != "" {
				cfg.AllowedOrigins = append(cfg.AllowedOrigins, o)
			}
		}
	}

	// Credential source resolution. IDP_USERS_FILE enables multi-user mode and
	// excludes the single-user sources; otherwise exactly one single-user
	// source should be configured.
	usersFile := os.Getenv("IDP_USERS_FILE")
	bcryptHash := os.Getenv("IDP_PASSWORD_BCRYPT")
	passwordFile := os.Getenv("IDP_PASSWORD_FILE")
	plainPassword := os.Getenv("IDP_PASSWORD")
	if usersFile != "" {
		// A fixed order keeps the reported conflicting variable deterministic.
		for _, c := range []struct{ key, val string }{
			{"IDP_USERNAME", os.Getenv("IDP_USERNAME")},
			{"IDP_PASSWORD", plainPassword},
			{"IDP_PASSWORD_BCRYPT", bcryptHash},
			{"IDP_PASSWORD_FILE", passwordFile},
		} {
			if c.val != "" {
				return cfg, fmt.Errorf("%s is set together with IDP_USERS_FILE; configure either multi-user mode or a single user, not both", c.key)
			}
		}
		cfg.UsersFile = usersFile
		cfg.Username = "" // multi-user mode has no single configured identity
	} else {
		// Username is already resolved in the struct literal above.
		if err := loadSingleUserCredentials(&cfg, bcryptHash, passwordFile, plainPassword); err != nil {
			return cfg, err
		}
	}

	proxies, err := parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return cfg, err
	}
	cfg.TrustedProxies = proxies
	return cfg, nil
}

// loadSingleUserCredentials resolves the password for single-user mode:
// bcrypt hash wins over a password file, both win over the plaintext default.
func loadSingleUserCredentials(cfg *Config, bcryptHash, passwordFile, plainPassword string) error {
	switch {
	case bcryptHash != "":
		if plainPassword != "" {
			return fmt.Errorf("IDP_PASSWORD and IDP_PASSWORD_BCRYPT are both set; configure exactly one password source")
		}
		cfg.PasswordBcrypt = bcryptHash
	case passwordFile != "":
		if plainPassword != "" {
			return fmt.Errorf("IDP_PASSWORD and IDP_PASSWORD_FILE are both set; configure exactly one password source")
		}
		// The read is scoped via os.Root so a crafted path cannot traverse
		// outside the file's directory (gosec G304/G703).
		raw, err := readScopedFile(passwordFile)
		if err != nil {
			return fmt.Errorf("read IDP_PASSWORD_FILE: %w", err)
		}
		cfg.Password = strings.TrimSpace(string(raw))
		if cfg.Password == "" {
			return fmt.Errorf("IDP_PASSWORD_FILE %q is empty", passwordFile)
		}
	default:
		cfg.Password = envOr("IDP_PASSWORD", "adventure")
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
