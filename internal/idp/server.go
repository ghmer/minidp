package idp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// authContext captures the per-request context that is carried from the
// authorization endpoint through to token issuance.
type authContext struct {
	Sub         string
	ClientID    string
	RedirectURI string
	Scopes      []string
	Nonce       string
}

// Server is the in-memory OIDC provider.
type Server struct {
	cfg      Config
	key      *signingKey
	store    *store
	template *loginTemplate
	csrf     *csrfManager
	limiter  *loginLimiter
}

// New constructs a Server, resolving the signing key (persisted, loaded or
// ephemeral), the credential source, and compiling the login template.
func New(cfg Config) (*Server, error) {
	key, err := NewSigningKey(cfg.RSAPeM, cfg.KeyDir)
	if err != nil {
		return nil, err
	}
	tmpl, err := newLoginTemplate(cfg.Title, cfg.Subtitle)
	if err != nil {
		return nil, err
	}
	csrfSecret := make([]byte, 32)
	if _, err := rand.Read(csrfSecret); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		key:      key,
		store:    newStore(),
		template: tmpl,
		csrf:     newCSRFManager(csrfSecret, 15*time.Minute),
		limiter:  newLimiter(cfg.LoginRateLimit),
	}
	slog.Info("minidp starting",
		"issuer", cfg.Issuer,
		"user", cfg.Username,
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
	if cfg.PasswordBcrypt == "" && cfg.Password == "adventure" && len(cfg.AllowedRedirects) == 0 {
		slog.Warn("running with the default demo credentials and an open redirect policy; " +
			"set IDP_PASSWORD_BCRYPT / IDP_PASSWORD_FILE and ALLOWED_REDIRECTS for production use")
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
	// A bare landing / login page for when someone just hits the IdP root.
	mux.HandleFunc("GET /", s.handleLanding)
	mux.HandleFunc("GET /login", s.handleLanding)
	mux.HandleFunc("POST /login", s.handleBareLogin)

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

// authenticate checks the supplied credentials against the configured user and
// returns the subject identifier when they match. Both the username and the
// password checks run in constant time.
func (s *Server) authenticate(username, password string) (string, bool) {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.Username)) == 1
	passOK := s.checkPassword(password)
	if !userOK || !passOK {
		return "", false
	}
	return s.cfg.Username, true
}

// checkPassword verifies the password against the configured credential
// source. The plaintext path compares SHA-256 digests in constant time (also
// sidestepping length differences); the bcrypt path delegates to bcrypt, which
// is constant-time by design.
func (s *Server) checkPassword(password string) bool {
	if s.cfg.PasswordBcrypt != "" {
		return bcrypt.CompareHashAndPassword([]byte(s.cfg.PasswordBcrypt), []byte(password)) == nil
	}
	want := sha256.Sum256([]byte(s.cfg.Password))
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// clientIP resolves the client IP for rate limiting and audit logs. When the
// socket peer is a trusted proxy (TRUSTED_PROXIES), the first
// X-Forwarded-For entry — or X-Real-IP — is used; otherwise the socket
// address itself, so spoofed forwarding headers cannot bypass rate limiting.
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
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
		}
	}
	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		return real
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

// redirectURIAllowed reports whether an incoming redirect_uri may be used.
func (s *Server) redirectURIAllowed(raw string) bool {
	if len(s.cfg.AllowedRedirects) == 0 {
		u, err := url.Parse(raw)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
	}
	for _, allowed := range s.cfg.AllowedRedirects {
		if allowed == raw {
			return true
		}
	}
	return false
}

// contentSecurityPolicy for the login HTML. The page uses no inline scripts
// or styles, so a strict policy without 'unsafe-inline' is possible.
const contentSecurityPolicy = "default-src 'self'; style-src 'self'; img-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'self'"

// withCORS wraps next with security headers and CORS handling. The IdP
// reflects the request Origin so the browser-based rego-adventure client can
// perform the cross-origin code-for-token exchange with credentials (which
// disallows a wildcard).
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		origin := r.Header.Get("Origin")
		if origin != "" {
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
