// Package idp is a minimal OIDC/OAuth2 identity provider that speaks the
// Authorization Code flow with PKCE for public clients and, in
// MINIDP_MODE=confidential, the confidential-client flow with client
// authentication (client_secret_basic / client_secret_post) at the token
// endpoint. It is designed to be
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

// ClientMode is the type of the single registered OAuth client. It selects
// which RFC 6749 client profile the provider serves.
type ClientMode string

const (
	// ModePublic serves the public-client profile: the client cannot keep a
	// secret, PKCE (S256) is mandatory at /authorize and the token endpoint
	// accepts only client_id identification.
	ModePublic ClientMode = "public"
	// ModeConfidential serves the confidential-client profile: /token
	// requires client authentication (client_secret_basic or
	// client_secret_post), PKCE becomes optional, and /introspect//revoke
	// require the secret.
	ModeConfidential ClientMode = "confidential"
)

// Config holds all tunable IdP settings. Every field is overridable through an
// environment variable so the registered client, the user accounts and every
// URL can be configured without recompiling.
type Config struct {
	// Host is the interface the HTTP server binds to.
	Host string
	// Port is the TCP port the HTTP server listens on.
	Port string
	// Issuer is the authoritative "iss" value written into every JWT and
	// published in the discovery document. rego-adventure compares this against
	// its AUTH_ISSUER, so it must line up with whatever the relying party expects.
	Issuer string
	// ClientID is the one registered OAuth client (IDP_CLIENT_ID). minidp is a
	// single-client provider for public PKCE clients: only this client_id is
	// accepted at /authorize and /token, and the redirect policy below is its
	// registration. Requests for any other client are rejected.
	ClientID string
	// Audience is the "aud" value written into every access and id token
	// (IDP_AUDIENCE). It defaults to ClientID. Resource servers (userinfo,
	// introspection) reject tokens whose audience does not match, so a token
	// can never be minted for — or accepted at — an arbitrary audience.
	Audience string
	// UsersFile is the JSON array of User entries with bcrypt password hashes,
	// managed with the minidp-users tool. It is the only credential source:
	// single-user env credentials were removed. Changes take effect on restart.
	UsersFile string
	// AccessTokenTTL is how long an access_token (and id_token) stays valid.
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh_token stays valid.
	RefreshTokenTTL time.Duration
	// AllowedRedirects is the registered redirect_uri set of the single
	// configured client (ALLOWED_REDIRECTS). Requests are honoured only for
	// these exact values; the policy is mandatory and minidp fails to start
	// without it, so no open default exists.
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
	// Mode (MINIDP_MODE, "public" or "confidential") selects the client
	// profile of the single registered client. "public" (default) requires
	// PKCE and forbids IDP_CLIENT_SECRET; "confidential" requires
	// IDP_CLIENT_SECRET and authenticates the client at /token.
	Mode ClientMode
	// ClientSecret (IDP_CLIENT_SECRET) is the registered client's credential
	// in MINIDP_MODE=confidential: /token then requires client
	// authentication — HTTP Basic (RFC 6749 §2.3.1, client_secret_basic) or
	// a client_id/client_secret form body (client_secret_post) — PKCE
	// becomes optional for the client, and the same secret gates /introspect
	// and /revoke. In MINIDP_MODE=public the secret must be unset.
	ClientSecret string
	// LoginRateLimit is the number of login attempts (POST /authorize and
	// POST /login) allowed per minute and client IP.
	LoginRateLimit int
}

// LoadConfig builds a Config from environment variables, applying the documented
// rego-adventure-compatible defaults. It fails fast on misconfiguration that
// would silently weaken security (no redirect policy, no users file, removed
// legacy variables, unreadable secret files, invalid proxy CIDRs).
func LoadConfig() (Config, error) {
	cfg, err := baseConfig()
	if err != nil {
		return Config{}, err
	}
	if err := cfg.validateMode(); err != nil {
		return cfg, err
	}
	// The token audience defaults to the registered client id, matching what
	// rego-adventure expects (AUTH_AUDIENCE = AUTH_CLIENT_ID). A distinct
	// resource audience can be configured with IDP_AUDIENCE.
	cfg.Audience = envOr("IDP_AUDIENCE", cfg.ClientID)
	if err := cfg.loadRedirectPolicy(); err != nil {
		return cfg, err
	}
	cfg.loadAllowedOrigins()
	if err := cfg.loadUsersFile(); err != nil {
		return cfg, err
	}
	proxies, err := parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return cfg, err
	}
	cfg.TrustedProxies = proxies
	return cfg, nil
}

// baseConfig reads the environment into the scalar Config fields. It rejects
// the removed single-user credential variables loudly instead of ignoring
// them: a silently ignored credential would let an operator believe their
// configuration still governs who can sign in.
func baseConfig() (Config, error) {
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
	if err := rejectRemovedCredentials(); err != nil {
		return Config{}, err
	}
	return Config{
		Host:            envOr("IDP_HOST", "0.0.0.0"),
		Port:            envOr("IDP_PORT", "8080"),
		Issuer:          envOr("IDP_ISSUER", "http://localhost:8080"),
		ClientID:        envOr("IDP_CLIENT_ID", "rego-adventure"),
		Mode:            ClientMode(os.Getenv("MINIDP_MODE")),
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		Title:           envOr("IDP_TITLE", "Rego Adventure"),
		Subtitle:        envOr("IDP_SUBTITLE", "Sign in to begin the adventure"),
		RSAPeM:          os.Getenv("IDP_RSA_PEM"),
		KeyDir:          os.Getenv("IDP_KEY_DIR"),
		LoginRateLimit:  loginRateLimit,
		ClientSecret:    os.Getenv("IDP_CLIENT_SECRET"),
	}, nil
}

// removedCredentials are the single-user credential variables that were
// removed when the users file became the only account source.
var removedCredentials = []string{"IDP_USERNAME", "IDP_PASSWORD", "IDP_PASSWORD_BCRYPT", "IDP_PASSWORD_FILE"}

func rejectRemovedCredentials() error {
	for _, removed := range removedCredentials {
		if os.Getenv(removed) != "" {
			return fmt.Errorf("%s is no longer supported: manage accounts in the IDP_USERS_FILE users file (see minidp-users)", removed)
		}
	}
	return nil
}

// validateMode enforces the MINIDP_MODE contract. The mode decides the client
// profile and is validated together with the client secret because the two
// are two halves of one registration: a secret without the confidential mode
// would be silently dead config, a confidential mode without a secret would
// authenticate every caller.
func (c *Config) validateMode() error {
	switch c.Mode {
	case "", ModePublic:
		c.Mode = ModePublic
		if c.ClientSecret != "" {
			return fmt.Errorf("IDP_CLIENT_SECRET is set but MINIDP_MODE is %q: a public client must not have a secret; set MINIDP_MODE=confidential or unset IDP_CLIENT_SECRET", c.Mode)
		}
	case ModeConfidential:
		if c.ClientSecret == "" {
			return fmt.Errorf("MINIDP_MODE=%s requires IDP_CLIENT_SECRET to be set: the client must have a credential to authenticate with", ModeConfidential)
		}
		if len(c.ClientSecret) < 16 {
			// Loud warning, not an error: the operator may accept the risk,
			// but a secret governing the token endpoint should be
			// cryptographically random (RFC 9700 §2.4 wants ≥128 bits).
			slog.Warn("IDP_CLIENT_SECRET is shorter than 16 characters: use a cryptographically random secret of at least 128 bits for a confidential client")
		}
	default:
		return fmt.Errorf("invalid MINIDP_MODE %q: must be %q or %q", string(c.Mode), ModePublic, ModeConfidential)
	}
	return nil
}

// loadRedirectPolicy parses ALLOWED_REDIRECTS into the registered redirect
// set. The redirect policy IS the client registration of the single
// configured client; an empty allowlist must not fall back to "any host"
// (that would send authorization codes to arbitrary URLs).
func (c *Config) loadRedirectPolicy() error {
	if raw := os.Getenv("ALLOWED_REDIRECTS"); raw != "" {
		for _, r := range strings.Split(raw, ",") {
			if err := c.addRedirect(r); err != nil {
				return err
			}
		}
	}
	if len(c.AllowedRedirects) == 0 {
		return fmt.Errorf("ALLOWED_REDIRECTS is empty: declare the registered redirect_uri values of client %q", c.ClientID)
	}
	return nil
}

// addRedirect validates and appends one ALLOWED_REDIRECTS entry. Fail fast on
// entries that could never be honoured safely: in allowlist mode
// redirectURIAllowed is a plain string comparison, so a typo'd or non-http(s)
// entry would otherwise be accepted silently (e.g. a javascript: URI in the
// allowlist).
func (c *Config) addRedirect(raw string) error {
	r := strings.TrimSpace(raw)
	if r == "" {
		return nil
	}
	u, err := url.Parse(r)
	if err != nil {
		return fmt.Errorf("invalid ALLOWED_REDIRECTS entry %q: %w", r, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("invalid ALLOWED_REDIRECTS entry %q: must be an absolute http(s) URL with a host", r)
	}
	c.AllowedRedirects = append(c.AllowedRedirects, r)
	return nil
}

// loadAllowedOrigins parses the explicit CORS origin allowlist
// (IDP_ALLOWED_ORIGINS).
func (c *Config) loadAllowedOrigins() {
	raw := os.Getenv("IDP_ALLOWED_ORIGINS")
	if raw == "" {
		return
	}
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.AllowedOrigins = append(c.AllowedOrigins, o)
		}
	}
}

// loadUsersFile reads the mandatory users file path. Accounts come from the
// users file; there is no fallback credential.
func (c *Config) loadUsersFile() error {
	c.UsersFile = os.Getenv("IDP_USERS_FILE")
	if c.UsersFile == "" {
		return fmt.Errorf("IDP_USERS_FILE is not set: minidp has no built-in accounts, create a users file (see minidp-users) and point IDP_USERS_FILE at it")
	}
	return nil
}

// Confidential reports whether the single registered client is a confidential
// client (MINIDP_MODE=confidential). Confidential clients must authenticate at
// the token endpoint (client_secret_basic or client_secret_post) and may use
// the flow without PKCE; public clients cannot keep secrets and must always
// use PKCE.
func (c Config) Confidential() bool { return c.Mode == ModeConfidential }

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
