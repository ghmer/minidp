package idp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// authCodeTTL is how long an authorization code stays redeemable (RFC 6749
// recommends a maximum of 10 minutes).
const authCodeTTL = 10 * time.Minute

// csrfCookie carries the per-browser nonce that login-form CSRF tokens are
// bound to. SameSite=Lax keeps it off cross-site POSTs entirely; HttpOnly
// keeps it away from JavaScript.
const csrfCookie = "minidp-login"

// oauthParamKeys are the authorization-request parameters echoed through the
// login form as hidden inputs so the POST /authorize round-trip keeps the full
// OAuth2 context (PKCE challenge, nonce, state, ...).
var oauthParamKeys = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "prompt", "login_hint",
	"max_age", "response_mode", "display", "ui_locales", "acr_values",
}

// oauthHiddenFields converts the authorize query into hidden form fields.
func oauthHiddenFields(q url.Values) []loginField {
	fields := make([]loginField, 0, len(oauthParamKeys))
	for _, key := range oauthParamKeys {
		if v := q.Get(key); v != "" {
			fields = append(fields, loginField{Name: key, Value: v})
		}
	}
	return fields
}

// csrfNonce extracts and decodes the browser nonce from the CSRF cookie. It
// returns nil when the cookie is absent or malformed, which makes verification
// fail closed.
func csrfNonce(r *http.Request) []byte {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || cookie.Value == "" {
		return nil
	}
	nonce, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil
	}
	return nonce
}

// oauthParamsOf extracts the OAuth2 parameters relevant for CSRF binding from
// a request: the query for GET (initial render) and the echoed form fields for
// POST (verification), merged via r.Form so both sides produce the same
// fingerprint.
func oauthParamsOf(r *http.Request) url.Values {
	_ = r.ParseForm() // r.Form merges query and body; errors yield an empty set
	out := url.Values{}
	for _, key := range oauthParamKeys {
		if vals, ok := r.Form[key]; ok {
			out[key] = vals
		}
	}
	return out
}

// validateAuthorizeRequest checks the authorization request and returns a
// human-readable problem description, or "" when the request is acceptable.
func (s *Server) validateAuthorizeRequest(q url.Values) string {
	if q.Get("response_type") != "code" {
		return "Unsupported response_type; only \"code\" (authorization code flow) is supported."
	}
	if q.Get("client_id") == "" {
		return "Missing client_id."
	}
	if q.Get("redirect_uri") == "" {
		return "Missing redirect_uri."
	}
	if !s.redirectURIAllowed(q.Get("redirect_uri")) {
		return "The redirect_uri is not allowed for this client."
	}
	if q.Get("code_challenge") == "" {
		return "Missing code_challenge: this IdP requires PKCE for public clients."
	}
	// RFC 9700 (OAuth 2.0 Security BCP) mandates S256; plain offers no
	// protection over the wire and a browser SPA can always do S256.
	if m := q.Get("code_challenge_method"); m != "S256" {
		return "Unsupported code_challenge_method; only S256 is supported."
	}
	return ""
}

// renderLoginPage renders the login form (or an error message page). A fresh
// per-browser nonce is generated and delivered in an HttpOnly SameSite cookie;
// the form's CSRF token is signed over that nonce, so a token obtained by one
// browser cannot be replayed from another.
func (s *Server) renderLoginPage(w http.ResponseWriter, r *http.Request, status int, data loginData) {
	if data.Action != "" {
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// #nosec G124 -- Secure is deliberately conditional on the issuer scheme
		// (https => true) so the plain-HTTP demo deployment keeps working; all
		// other attributes are strictly set.
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookie,
			Value:    base64.RawURLEncoding.EncodeToString(nonce),
			Path:     "/",
			MaxAge:   int(s.csrf.ttl.Seconds()),
			HttpOnly: true,
			Secure:   strings.HasPrefix(s.cfg.Issuer, "https://"),
			SameSite: http.SameSiteLaxMode,
		})
		data.CSRFToken = s.csrf.issue(data.Action, oauthParamsOf(r), nonce)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.template.render(w, data); err != nil {
		// The headers and possibly part of the body are already sent, so a
		// clean error page is impossible; log the details and show the user
		// nothing internal.
		slog.Error("login template render failed", "error", err)
		_, _ = w.Write([]byte("<!-- render failed -->\nInternal error."))
	}
}

// handleAuthorizeGet renders the login form for an authorization request.
func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if problem := s.validateAuthorizeRequest(q); problem != "" {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: problem})
		return
	}
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Action: "/authorize",
		Hidden: oauthHiddenFields(q),
	})
}

// handleAuthorizePost authenticates the user and, on success, redirects the
// browser back to the client with a single-use authorization code.
func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.limiter.allow(ip) {
		slog.Warn("login rate limited", "ip", ip)
		s.renderLoginPage(w, r, http.StatusTooManyRequests, loginData{
			Action: "/authorize",
			Error:  "Too many sign-in attempts. Please wait a minute and try again.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: "Malformed form submission."})
		return
	}
	form := r.PostForm

	// The CSRF token must be valid before anything else is processed, so a
	// crafted cross-site form cannot smuggle attacker-chosen OAuth2 parameters
	// through an authenticated user's browser. The token is bound to the nonce
	// cookie of the browser that rendered the form; a token pre-fetched by an
	// attacker does not match the victim's cookie.
	if !s.csrf.verify("/authorize", oauthParamsOf(r), csrfNonce(r), form.Get("csrf_token")) {
		slog.Warn("login rejected: invalid CSRF token", "ip", ip)
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{
			Action: "/authorize",
			Error:  "Your sign-in session expired or the request was tampered with. Please start again.",
			Hidden: oauthHiddenFields(form),
		})
		return
	}

	// Re-validate the OAuth2 context that was echoed through the form.
	q := url.Values{}
	for _, f := range oauthHiddenFields(form) {
		q.Set(f.Name, f.Value)
	}
	if problem := s.validateAuthorizeRequest(q); problem != "" {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: problem})
		return
	}

	who, ok := s.authenticate(form.Get("username"), form.Get("password"))
	if !ok {
		slog.Warn("login failed", "ip", ip, "user", form.Get("username"))
		s.renderLoginPage(w, r, http.StatusUnauthorized, loginData{
			Action:   "/authorize",
			Error:    "Invalid username or password.",
			Username: form.Get("username"),
			Hidden:   oauthHiddenFields(form),
		})
		return
	}
	slog.Info("login succeeded", "ip", ip, "user", who.Sub)

	code := s.store.addCode(&authCode{
		Sub:                 who.Sub,
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
		Scopes:              parseScopes(q.Get("scope")),
	}, authCodeTTL)
	slog.Info("authorization code issued", "client", q.Get("client_id"), "redirect", q.Get("redirect_uri"))

	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: "Invalid redirect_uri."})
		return
	}
	params := target.Query()
	params.Set("code", code)
	if state := q.Get("state"); state != "" {
		params.Set("state", state)
	}
	target.RawQuery = params.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

// handleLanding renders the bare login page for direct visits to the IdP root.
func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	s.renderLoginPage(w, r, http.StatusOK, loginData{Action: "/login"})
}

// handleBareLogin authenticates a direct (non-OAuth2) login from the landing
// page. It issues no tokens; tokens always require a real authorize request.
func (s *Server) handleBareLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.limiter.allow(ip) {
		slog.Warn("login rate limited", "ip", ip)
		s.renderLoginPage(w, r, http.StatusTooManyRequests, loginData{
			Action: "/login",
			Error:  "Too many sign-in attempts. Please wait a minute and try again.",
		})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: "Malformed form submission."})
		return
	}
	form := r.PostForm
	if !s.csrf.verify("/login", oauthParamsOf(r), csrfNonce(r), form.Get("csrf_token")) {
		slog.Warn("login rejected: invalid CSRF token", "ip", ip)
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{
			Action: "/login",
			Error:  "Your sign-in session expired or the request was tampered with. Please start again.",
		})
		return
	}
	who, ok := s.authenticate(form.Get("username"), form.Get("password"))
	if !ok {
		slog.Warn("login failed", "ip", ip, "user", form.Get("username"))
		s.renderLoginPage(w, r, http.StatusUnauthorized, loginData{
			Action:   "/login",
			Error:    "Invalid username or password.",
			Username: form.Get("username"),
		})
		return
	}
	slog.Info("login succeeded", "ip", ip, "user", who.Sub)
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Action:  "/login",
		Message: "Signed in as " + who.Sub + ". This page issues tokens only via the /authorize endpoint.",
	})
}

// handleToken implements the RFC 6749 token endpoint for the
// authorization_code and refresh_token grants.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthError(w, "invalid_request", "Malformed form body.")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.handleCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshGrant(w, r)
	case "":
		writeAuthError(w, "invalid_request", "Missing grant_type.")
	default:
		writeAuthError(w, "unsupported_grant_type", "Only authorization_code and refresh_token are supported.")
	}
}

// verifyPKCE checks the code_verifier against the stored challenge. Only
// S256 is accepted (RFC 9700); an absent method is treated as S256 for
// robustness, anything else fails closed.
func verifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		// No PKCE was requested at authorization time.
		return true
	}
	if verifier == "" {
		return false
	}
	if method != "" && method != "S256" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pkceS256(verifier)), []byte(challenge)) == 1
}

// handleCodeGrant redeems an authorization code for a token set.
func (s *Server) handleCodeGrant(w http.ResponseWriter, r *http.Request) {
	form := r.PostForm
	code := form.Get("code")
	if code == "" {
		writeAuthError(w, "invalid_request", "Missing code.")
		return
	}
	ac := s.store.takeCode(code)
	if ac == nil {
		slog.Warn("code rejected: unknown, expired or already redeemed", "ip", s.clientIP(r))
		writeAuthError(w, "invalid_grant", "Unknown, expired or already redeemed authorization code.")
		return
	}
	// RFC 6749 §4.1.3: the token request must repeat client_id (public
	// clients cannot authenticate) and the same redirect_uri that was used in
	// the authorization request (which this IdP always requires).
	clientID := form.Get("client_id")
	if clientID == "" {
		writeAuthError(w, "invalid_request", "Missing client_id.")
		return
	}
	if clientID != ac.ClientID {
		writeAuthError(w, "invalid_grant", "client_id does not match the authorization request.")
		return
	}
	redirectURI := form.Get("redirect_uri")
	if redirectURI == "" {
		writeAuthError(w, "invalid_request", "Missing redirect_uri.")
		return
	}
	if redirectURI != ac.RedirectURI {
		writeAuthError(w, "invalid_grant", "redirect_uri does not match the authorization request.")
		return
	}
	if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, form.Get("code_verifier")) {
		slog.Warn("code rejected: PKCE verification failed", "ip", s.clientIP(r), "client", ac.ClientID)
		writeAuthError(w, "invalid_grant", "PKCE verification failed.")
		return
	}

	resp, err := s.issueTokens(&authContext{
		Sub:      ac.Sub,
		ClientID: ac.ClientID,
		Scopes:   ac.Scopes,
		Nonce:    ac.Nonce,
		Family:   randomToken(), // a fresh authorization starts a new refresh chain
	})
	if err != nil {
		slog.Error("token issuance failed", "grant", "authorization_code", "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "The token could not be issued.")
		return
	}
	slog.Info("tokens issued", "grant", "authorization_code", "client", ac.ClientID, "sub", ac.Sub)
	writeJSON(w, http.StatusOK, resp)
}

// handleRefreshGrant exchanges a refresh token for a fresh token set. Refresh
// tokens are single-use: the presented token is consumed and a new one returned.
func (s *Server) handleRefreshGrant(w http.ResponseWriter, r *http.Request) {
	token := r.PostForm.Get("refresh_token")
	if token == "" {
		writeAuthError(w, "invalid_request", "Missing refresh_token.")
		return
	}
	// RFC 6749 §6: a public client must identify itself with client_id.
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		writeAuthError(w, "invalid_request", "Missing client_id.")
		return
	}
	// Consume the token first (single lookup, no validity oracle), then check
	// that it belongs to the presenting client. On a mismatch the whole token
	// family is dropped — a mismatched client_id on a valid token is a theft
	// signal.
	entry, reused := s.store.takeRefresh(token)
	if entry == nil {
		if reused {
			// RFC 9700 §4.14.2: a replayed refresh token is treated as theft;
			// takeRefresh has already revoked the whole family.
			slog.Warn("refresh token REUSE detected: token family revoked", "ip", s.clientIP(r))
		} else {
			slog.Warn("refresh token rejected: unknown, expired or already used", "ip", s.clientIP(r))
		}
		writeAuthError(w, "invalid_grant", "Unknown, expired or already used refresh token.")
		return
	}
	if clientID != entry.ClientID {
		slog.Warn("refresh rejected: client_id mismatch", "ip", s.clientIP(r), "client", clientID)
		s.store.revokeFamily(entry.Family)
		writeAuthError(w, "invalid_grant", "client_id does not match the refresh token.")
		return
	}

	resp, err := s.issueTokens(&authContext{
		Sub:      entry.Sub,
		ClientID: entry.ClientID,
		Scopes:   entry.Scopes,
		Nonce:    entry.Nonce,
		Family:   entry.Family,
	})
	if err != nil {
		slog.Error("token issuance failed", "grant", "refresh_token", "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "The token could not be issued.")
		return
	}
	slog.Info("tokens issued", "grant", "refresh_token", "client", entry.ClientID, "sub", entry.Sub)
	writeJSON(w, http.StatusOK, resp)
}

// verifyAccessToken parses and validates a signed JWT issued by this IdP. It
// enforces RS256, the configured issuer and the expiry.
func (s *Server) verifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return &s.key.key.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return claims, nil
}

// bearerToken extracts the Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

// handleUserinfo returns the claims of the authenticated user for a valid
// access token.
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAccessToken(bearerToken(r))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or missing access token.")
		return
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if email == "" {
		email = sub + "@example.com"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                sub,
		"preferred_username": sub,
		"email":              email,
	})
}

// handleIntrospect reports whether a token is currently valid (RFC 7662).
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	claims, err := s.verifyAccessToken(r.PostForm.Get("token"))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	writeJSON(w, http.StatusOK, map[string]any{
		"active":   true,
		"sub":      sub,
		"scope":    scope,
		"iss":      claims["iss"],
		"aud":      claims["aud"],
		"exp":      claims["exp"],
		"iat":      claims["iat"],
		"username": sub,
	})
}

// handleRevoke revokes a refresh token (RFC 7009). Per the spec it responds
// 200 even when the token is unknown, to avoid leaking token validity.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	s.store.revokeToken(r.PostForm.Get("token"))
	w.WriteHeader(http.StatusOK)
}

// handleEndSession implements a minimal logout. A post_logout_redirect_uri is
// honoured only when it exactly matches an entry of the configured redirect
// allowlist, and the redirect always targets the allowlist entry itself — never
// the user-supplied string — so the endpoint cannot be abused for open
// redirects (gosec G710).
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if target != "" {
		for _, allowed := range s.cfg.AllowedRedirects {
			if subtle.ConstantTimeCompare([]byte(allowed), []byte(target)) == 1 {
				http.Redirect(w, r, allowed, http.StatusFound)
				return
			}
		}
	}
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Action:  "/login",
		Message: "You have been signed out.",
	})
}

// handleStaticCSS serves the embedded rego-adventure themed stylesheet.
func (s *Server) handleStaticCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(s.template.css)
}

// handleStaticLogo serves the embedded Rego Adventure logo.
func (s *Server) handleStaticLogo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(s.template.logo)
}
