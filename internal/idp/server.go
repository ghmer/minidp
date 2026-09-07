package idp

import (
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// authContext captures the per-request context that is carried from the
// authorization endpoint through to token issuance. Family identifies the
// refresh-token chain started by one authorization (empty for a new chain).
type authContext struct {
	Sub      string
	ClientID string
	Scopes   []string
	Nonce    string
	Family   string
}

// subject identifies the authenticated user carried through to token
// issuance. Email and Name come from the client's users in the clients file.
type subject struct {
	Sub   string
	Email string
	Name  string
}

// Server is the in-memory OIDC provider.
type Server struct {
	cfg            Config
	key            *signingKey
	store          *store
	template       *loginTemplate
	csrf           *csrfManager
	limiter        *loginLimiter
	clients        *clientRegistry
	allowedOrigins map[string]bool
}

// New constructs a Server, resolving the signing key, the registered clients
// (each with its own accounts), and compiling the login template.
func New(cfg Config) (*Server, error) {
	key, err := NewSigningKey(cfg.RSAPeM, cfg.KeyDir)
	if err != nil {
		return nil, err
	}
	tmpl, err := newLoginTemplate(cfg.Title, cfg.Subtitle)
	if err != nil {
		return nil, err
	}
	clients, err := LoadClients(cfg.ClientsFile)
	if err != nil {
		return nil, err
	}
	csrfSecret := make([]byte, 32)
	if _, err := rand.Read(csrfSecret); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:            cfg,
		key:            key,
		store:          newStore(),
		template:       tmpl,
		csrf:           newCSRFManager(csrfSecret, 15*time.Minute),
		limiter:        newLimiter(cfg.LoginRateLimit),
		clients:        clients,
		allowedOrigins: clients.allowedOrigins(),
	}
	slog.Info("minidp starting",
		"issuer", cfg.Issuer,
		"clients", strings.Join(clients.clientIDs(), ", "),
		"users", clients.userCount(),
		"accessTTL", cfg.AccessTokenTTL,
		"refreshTTL", cfg.RefreshTokenTTL,
		"loginRateLimit", cfg.LoginRateLimit,
	)
	switch {
	case cfg.RSAPeM != "":
		slog.Info("signing key loaded from PEM file", "path", cfg.RSAPeM)
	case cfg.KeyDir != "":
		slog.Info("signing key managed in key dir", "dir", cfg.KeyDir)
	default:
		slog.Warn("using an ephemeral signing key: all tokens become invalid on restart; " +
			"set IDP_KEY_DIR or IDP_RSA_PEM for production use")
	}
	return s, nil
}

// Handler returns the fully wired HTTP handler with CORS middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Discovery + keys.
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /oauth2/jwks", s.handleJWKS)
	mux.HandleFunc("GET /jwks", s.handleJWKS)

	// Authorization endpoint: GET renders the login form, POST performs the
	// credential check and redirects the browser to the client with a code.
	mux.HandleFunc("GET /authorize", s.handleAuthorizeGet)
	mux.HandleFunc("POST /authorize", s.handleAuthorizePost)
	// A bare landing page for when someone just hits the IdP root. Sign-in
	// happens exclusively through a client's /authorize flow; there is no
	// standalone credential check (users belong to clients).
	mux.HandleFunc("GET /", s.handleLanding)
	mux.HandleFunc("GET /login", s.handleLanding)

	// RFC 6749 token endpoint.
	mux.HandleFunc("POST /token", s.handleToken)

	// Supporting OIDC/OAuth2 endpoints.
	mux.HandleFunc("GET /userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("POST /revoke", s.handleRevoke)
	mux.HandleFunc("GET /end_session", s.handleEndSession)

	// Static assets for the login page.
	mux.HandleFunc("GET /login.css", s.handleStaticCSS)
	mux.HandleFunc("GET /logo.svg", s.handleStaticLogo)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return s.withCORS(mux)
}

// authenticate verifies the credentials against a client's user store.
// Unknown users are checked against a dummy bcrypt hash so that response
// timing does not reveal which usernames exist.
func (s *Server) authenticate(client *registeredClient, username, password string) (subject, bool) {
	u, ok := client.users.Lookup(username)
	if !ok {
		_ = verifyHash(client.users.DummyHash(), password)
		return subject{}, false
	}
	if !verifyHash(u.PasswordHash, password) {
		return subject{}, false
	}
	return subject{Sub: u.Username, Email: u.Email, Name: u.Name}, true
}

// clientIP resolves the client IP for rate limiting and audit logs. When the
// socket peer is a trusted proxy (TRUSTED_PROXIES), the X-Forwarded-For chain
// is walked from right to left and the rightmost entry NOT belonging to a
// trusted proxy is used: standard proxies append the real client address, so
// an attacker-supplied leftmost entry ("X-Forwarded-For: <random>, <real>")
// can neither select nor rotate the rate-limit key. X-Real-IP is honoured only
// when X-Forwarded-For is absent (proxies that set it overwrite the header).
// Without a trusted proxy, the socket address itself is used.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil || !s.ipTrusted(ip) {
		return host
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return s.forwardedClientIP(xff, host)
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		if realIP := net.ParseIP(real); realIP != nil && !s.ipTrusted(realIP) {
			return real
		}
	}
	return host
}

// forwardedClientIP walks the X-Forwarded-For chain from right to left and
// returns the rightmost entry that is not itself a trusted proxy. Malformed
// entries are skipped: they cannot be the real client address. When the whole
// chain consists of trusted proxies, the most specific address we can vouch
// for is the socket peer itself (host).
func (s *Server) forwardedClientIP(xff, host string) string {
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		cIP := net.ParseIP(candidate)
		if cIP == nil {
			continue // malformed entry: cannot be the real client, keep walking
		}
		if !s.ipTrusted(cIP) {
			return candidate
		}
	}
	return host
}

func (s *Server) ipTrusted(ip net.IP) bool {
	for _, cidr := range s.cfg.TrustedProxies {
		if _, network, err := net.ParseCIDR(cidr); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// contentSecurityPolicy for the login HTML. The page uses no inline scripts
// or styles, so a strict policy without 'unsafe-inline' is possible.
const contentSecurityPolicy = "default-src 'self'; style-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'self'"

// withCORS wraps next with security headers and CORS handling. Browser-based
// clients (e.g. SPAs using oidc-client-ts) exchange the code for tokens
// cross-origin with credentials, which disallows a wildcard — so the request
// Origin is reflected ONLY when it is on the allowlist (hosts of every
// client's redirect URIs plus the clients' explicit allowed_origins). Any
// other origin receives no CORS grant and the browser blocks the response.
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if origin := r.Header.Get("Origin"); origin != "" && s.allowedOrigins[strings.TrimSuffix(origin, "/")] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, errCode, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

func writeAuthError(w http.ResponseWriter, errCode, desc string) {
	writeError(w, http.StatusBadRequest, errCode, desc)
}

// parseScopes splits a space-delimited scope string, defaulting to "openid".
func parseScopes(raw string) []string {
	if raw == "" {
		return []string{"openid"}
	}
	parts := strings.Fields(raw)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"openid"}
	}
	return out
}
