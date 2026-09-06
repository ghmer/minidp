package idp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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
}

// New constructs a Server, loading or generating the RSA signing key and
// compiling the login template.
func New(cfg Config) (*Server, error) {
	key, err := NewSigningKey(cfg.RSAPeM)
	if err != nil {
		return nil, err
	}
	tmpl, err := newLoginTemplate(cfg.Title, cfg.Subtitle)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		key:      key,
		store:    newStore(),
		template: tmpl,
	}
	slog.Info("minidp starting",
		"issuer", cfg.Issuer,
		"user", cfg.Username,
		"accessTTL", cfg.AccessTokenTTL,
		"refreshTTL", cfg.RefreshTokenTTL,
	)
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
// returns the subject identifier (the username) when they match.
func (s *Server) authenticate(username, password string) (string, bool) {
	if username == s.cfg.Username && password == s.cfg.Password {
		return s.cfg.Username, true
	}
	return "", false
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

// withCORS wraps next so the browser-based rego-adventure client can perform the
// cross-origin code-for-token exchange. The IdP reflects the request Origin so
// credentials may be sent (which disallows a wildcard).
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
