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
// login form as hidden inputs so the POST /authorize round-trip keeps the
// OAuth2 context (PKCE challenge, nonce, state, ...). login_hint is accepted
// (it pre-fills the username field); unsupported parameters such as
// prompt=consent, max_age, response_mode, display, ui_locales and acr_values
// are rejected at the authorize endpoint instead of being silently ignored
// (review finding M3).
var oauthParamKeys = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "login_hint",
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

// supportedScopes is the scope policy of the IdP: exactly what discovery
// advertises. Requests for anything else are rejected with invalid_scope
// instead of copying unvalidated scopes into tokens (review finding M1).
var supportedScopes = map[string]bool{"openid": true, "profile": true, "email": true}

// validateClientBinding checks the parameters that decide whether an error may
// be delivered via redirect: an unknown client_id or an unregistered
// redirect_uri must be reported on an HTML page — redirecting to an
// unvalidated URI would be an open redirect (RFC 6749 §4.1.2.1). minidp is a
// single-client provider: only the registered client may start a flow, and
// only against its registered redirect URIs (review findings H1/H2).
func (s *Server) validateClientBinding(q url.Values) string {
	if q.Get("client_id") == "" {
		return "Missing client_id."
	}
	if q.Get("client_id") != s.cfg.ClientID {
		return "Unknown client_id: this provider serves a single registered client."
	}
	if q.Get("redirect_uri") == "" {
		return "Missing redirect_uri."
	}
	if !s.redirectURIAllowed(q.Get("redirect_uri")) {
		return "The redirect_uri is not registered for this client."
	}
	return ""
}

// validateAuthorizeRequest checks everything that can be reported to the
// client's redirect_uri and returns an OAuth error code with a
// human-readable description, or "" when the request is acceptable.
func (s *Server) validateAuthorizeRequest(q url.Values) (code, description string) {
	if q.Get("response_type") != "code" {
		return "unsupported_response_type", `Unsupported response_type; only "code" (authorization code flow) is supported.`
	}
	// RFC 9700 (OAuth 2.0 Security BCP) mandates S256; plain offers no
	// protection over the wire and a browser SPA can always do S256.
	challenge := q.Get("code_challenge")
	if challenge == "" {
		return "invalid_request", "Missing code_challenge: this IdP requires PKCE for public clients."
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		return "invalid_request", "Unsupported code_challenge_method; only S256 is supported."
	}
	if !validPKCEChallenge(challenge) {
		return "invalid_request", "Malformed code_challenge: expected 43-128 base64url characters (S256 digest)."
	}
	// Unsupported OIDC parameters are rejected explicitly instead of being
	// accepted and ignored (review finding M3).
	switch p := q.Get("prompt"); p {
	case "":
	case "login":
		// Matches the actual behaviour: the login form is always rendered.
	case "none":
		// No browser session is ever kept, so interaction is always required;
		// answering login_required is the OIDC-correct response.
		return "login_required", "Interactive authentication is required."
	default:
		return "invalid_request", "Unsupported prompt value; only \"login\" and \"none\" are supported."
	}
	if v := q.Get("response_mode"); v != "" && v != "query" {
		return "invalid_request", "Unsupported response_mode; only the default query mode is supported."
	}
	for _, p := range []string{"max_age", "acr_values", "display", "ui_locales"} {
		if q.Get(p) != "" {
			return "invalid_request", fmt.Sprintf("Unsupported parameter %q.", p)
		}
	}
	for _, sc := range parseScopes(q.Get("scope")) {
		if !supportedScopes[sc] {
			return "invalid_scope", fmt.Sprintf("Unsupported scope %q; supported scopes: openid profile email.", sc)
		}
	}
	return "", ""
}

// registeredRedirect returns the registered redirect policy entry equal to
// raw (constant-time comparison), or "". Callers redirect to the returned
// entry itself — never to the user-supplied string (gosec G710).
func (s *Server) registeredRedirect(raw string) string {
	for _, allowed := range s.cfg.AllowedRedirects {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(raw)) == 1 {
			return allowed
		}
	}
	return ""
}

// authorizeErrorRedirect delivers a redirectable OAuth error to the client's
// registered redirect_uri (RFC 6749 §4.1.2.1), echoing the state parameter.
func (s *Server) authorizeErrorRedirect(w http.ResponseWriter, r *http.Request, q url.Values, code, description string) {
	target, err := url.Parse(s.registeredRedirect(q.Get("redirect_uri")))
	if err != nil || target.String() == "" {
		// Unreachable: the redirect_uri passed validateClientBinding, but the
		// error page is the safe fallback either way.
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: "Invalid redirect_uri."})
		return
	}
	params := target.Query()
	params.Set("error", code)
	params.Set("error_description", description)
	if state := q.Get("state"); state != "" {
		params.Set("state", state)
	}
	target.RawQuery = params.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// validPKCEVerifier enforces the RFC 7636 §4.1 syntax: 43-128 characters of
// the unreserved set [A-Za-z0-9-._~].
func validPKCEVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// validPKCEChallenge enforces the RFC 7636 §4.2 shape: 43-128 base64url
// characters (an S256 digest is exactly 43, unpadded).
func validPKCEChallenge(c string) bool {
	if len(c) < 43 || len(c) > 128 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

// nonceBytes is the length of the per-browser CSRF nonce.
const nonceBytes = 32

// renderLoginPage renders the login form (or an error message page). A fresh
// per-browser nonce is generated and delivered in an HttpOnly SameSite cookie;
// the form's CSRF token is signed over that nonce, so a token obtained by one
// browser cannot be replayed from another.
//
// The nonce is only minted when the browser does not already carry a valid
// one: re-rendering (a failed login, a second tab) reuses the existing nonce
// and keeps forms rendered earlier valid, instead of silently invalidating
// every previously issued form. The token itself is freshly signed per render
// and expires with the manager TTL either way.
func (s *Server) renderLoginPage(w http.ResponseWriter, r *http.Request, status int, data loginData) {
	if data.Action != "" {
		nonce := csrfNonce(r)
		if len(nonce) != nonceBytes {
			nonce = make([]byte, nonceBytes)
			if _, err := rand.Read(nonce); err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			// Secure is set unconditionally: minidp is deployed either on
			// https (TLS-terminating proxy) or on plain-HTTP localhost, where
			// Chrome and Firefox honour the "potentially trustworthy origin"
			// exception (W3C Secure Contexts). Safari implements no localhost
			// exception — use Chrome/Firefox or TLS there.
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookie,
				Value:    base64.RawURLEncoding.EncodeToString(nonce),
				Path:     "/",
				MaxAge:   int(s.csrf.ttl.Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
		}
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
	if problem := s.validateClientBinding(q); problem != "" {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: problem})
		return
	}
	if code, description := s.validateAuthorizeRequest(q); code != "" {
		s.authorizeErrorRedirect(w, r, q, code, description)
		return
	}
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Action: "/authorize",
		Hidden: oauthHiddenFields(q),
		// login_hint pre-fills the username field (OIDC Core §3.1.2.1).
		Username: q.Get("login_hint"),
	})
}

// handleAuthorizePost authenticates the user and, on success, redirects the
// browser back to the client with a single-use authorization code.
func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.limiter.allow(ip) {
		slog.Warn("login rate limited", "ip", ip)
		// Carry the OAuth2 context through the re-render (like every other
		// error branch) so a retry after the cooldown submits a complete form.
		s.renderLoginPage(w, r, http.StatusTooManyRequests, loginData{
			Action: "/authorize",
			Error:  "Too many sign-in attempts. Please wait a minute and try again.",
			Hidden: oauthHiddenFields(oauthParamsOf(r)),
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

	// Re-validate the OAuth2 context that was echoed through the form. The
	// client binding decides whether a failure is shown on the page or
	// redirected; all remaining errors go to the registered redirect_uri.
	q := url.Values{}
	for _, f := range oauthHiddenFields(form) {
		q.Set(f.Name, f.Value)
	}
	if problem := s.validateClientBinding(q); problem != "" {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: problem})
		return
	}
	if code, description := s.validateAuthorizeRequest(q); code != "" {
		s.authorizeErrorRedirect(w, r, q, code, description)
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

	// Redirect to the registered entry itself, never the user-supplied
	// string (gosec G710).
	target, err := url.Parse(s.registeredRedirect(q.Get("redirect_uri")))
	if err != nil || target.String() == "" {
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
//
// Deliberately NOT rate limited: the tokens redeemed here (codes, refresh
// tokens) are 256-bit random and single-use, so guessing cannot succeed and
// a limit would only enable a denial-of-service against legitimate clients.
// The attacker-guessable entry point — the login form's credential check — is
// rate limited via clientIP (see handleAuthorizePost/handleBareLogin).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// RFC 6749 §5.1: token responses (success AND error) must not be cached.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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
// S256 is accepted (RFC 9700); the verifier must satisfy the RFC 7636
// syntax/length rules, and an absent method is treated as S256 for
// robustness, anything else fails closed.
func verifyPKCE(challenge, method, verifier string) bool {
	if challenge == "" {
		// No PKCE was requested at authorization time.
		return true
	}
	if !validPKCEVerifier(verifier) {
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
	// the authorization request (which this IdP always requires). The
	// presenting client must also be the one registered client.
	clientID := form.Get("client_id")
	if clientID == "" {
		writeAuthError(w, "invalid_request", "Missing client_id.")
		return
	}
	if clientID != s.cfg.ClientID {
		writeAuthError(w, "invalid_grant", "Unknown client_id.")
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
	// RFC 6749 §6: a public client must identify itself with client_id. Only
	// the registered client is accepted — checked before the token is
	// consumed so a foreign client cannot burn a stolen refresh token.
	clientID := r.PostForm.Get("client_id")
	if clientID == "" {
		writeAuthError(w, "invalid_request", "Missing client_id.")
		return
	}
	if clientID != s.cfg.ClientID {
		slog.Warn("refresh rejected: unknown client_id", "ip", s.clientIP(r), "client", clientID)
		writeAuthError(w, "invalid_grant", "Unknown client_id.")
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
		s.store.revokeFamilyTokens(entry.Family)
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

// parseAccessToken parses and validates a signed JWT access token issued by
// this IdP: RS256 only, the configured issuer, a required expiry and the RFC
// 9068 "at+jwt" typ header — an id_token (typ JWT) is never accepted as a
// bearer access token (review finding H3). The jti revocation denylist is
// always honoured. When requireAudience is true the token must carry the
// configured audience, so tokens minted for any other audience are rejected
// at the resource endpoints (review finding H4).
func (s *Server) parseAccessToken(tokenString string, requireAudience bool) (jwt.MapClaims, error) {
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
	if typ, _ := token.Header["typ"].(string); typ != typAccessToken {
		return nil, fmt.Errorf("invalid token: not an access token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	aud, _ := claims.GetAudience()
	if len(aud) == 0 {
		return nil, fmt.Errorf("invalid token: missing audience")
	}
	if requireAudience && !audContains(aud, s.cfg.Audience) {
		return nil, fmt.Errorf("invalid token: audience not accepted here")
	}
	if jti, _ := claims["jti"].(string); jti != "" && s.store.isDeniedJTI(jti) {
		return nil, fmt.Errorf("invalid token: revoked")
	}
	return claims, nil
}

func audContains(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

// verifyAccessToken is the resource-endpoint check: signature, access-token
// profile, issuer, expiry and the configured audience must all hold.
func (s *Server) verifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	return s.parseAccessToken(tokenString, true)
}

// parseIDTokenHint validates an id_token_hint for /end_session. Per OIDC
// RP-Initiated Logout the hint's signature and issuer are verified, but an
// EXPIRED hint still identifies the token family to revoke — so expiry and
// audience are deliberately not enforced here (review finding M6). The
// registered-claims validation is disabled and the issuer is checked
// manually instead.
func (s *Server) parseIDTokenHint(hint string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(hint, func(t *jwt.Token) (any, error) {
		return &s.key.key.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithoutClaimsValidation(), // expiry is intentionally not enforced
	)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if typ, _ := token.Header["typ"].(string); typ != typIDToken {
		return nil, fmt.Errorf("invalid token: not an id token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	if iss, _ := claims["iss"].(string); iss != s.cfg.Issuer {
		return nil, fmt.Errorf("invalid token: foreign issuer")
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

// requireClientAuth enforces client authentication on the introspection and
// revocation endpoints when IDP_CLIENT_SECRET is configured (RFC 7662
// strongly recommends authenticating introspection; an open /revoke is a free
// probe endpoint). Accepted: HTTP Basic auth (any username, the configured
// secret as password) or a client_secret form field. Unconfigured -> open.
func (s *Server) requireClientAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.ClientSecret == "" {
		return true
	}
	secret := []byte(s.cfg.ClientSecret)
	if _, pw, ok := r.BasicAuth(); ok && subtle.ConstantTimeCompare([]byte(pw), secret) == 1 {
		return true
	}
	_ = r.ParseForm()
	if pw := r.PostForm.Get("client_secret"); pw != "" && subtle.ConstantTimeCompare([]byte(pw), secret) == 1 {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="minidp"`)
	writeError(w, http.StatusUnauthorized, "invalid_client", "Client authentication required.")
	return false
}

// handleUserinfo returns the claims of the authenticated user for a valid
// access token. The token must carry the configured audience, the access
// token profile (typ at+jwt) and the openid scope; profile claims are
// released according to the granted scopes and resolved from the users-file
// record — never synthesised (review findings H3/H4/M2/L2).
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAccessToken(bearerToken(r))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or missing access token.")
		return
	}
	// A token without a scope claim grants nothing: fail closed.
	scopeRaw, _ := claims["scope"].(string)
	if scopeRaw == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		writeError(w, http.StatusForbidden, "insufficient_scope", "The openid scope is required for UserInfo.")
		return
	}
	scopes := parseScopes(scopeRaw)
	if !hasScope(scopes, "openid") {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		writeError(w, http.StatusForbidden, "insufficient_scope", "The openid scope is required for UserInfo.")
		return
	}
	sub, _ := claims["sub"].(string)
	wantProfile := hasScope(scopes, "profile")
	wantEmail := hasScope(scopes, "email")
	out := map[string]any{"sub": sub}
	// Authoritative record first; the scope-gated token claims are the
	// fallback for subjects that have since been removed from the file.
	var username, email string
	if u, ok := s.users.Lookup(sub); ok {
		if wantProfile {
			username = u.Username
		}
		if wantEmail {
			email = u.Email
		}
	} else {
		if wantProfile {
			username, _ = claims["preferred_username"].(string)
		}
		if wantEmail {
			email, _ = claims["email"].(string)
		}
	}
	if wantProfile && username != "" {
		out["preferred_username"] = username
	}
	if wantEmail && email != "" {
		out["email"] = email
	}
	writeJSON(w, http.StatusOK, out)
}

// handleIntrospect reports whether a token is currently valid (RFC 7662).
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if !s.requireClientAuth(w, r) {
		return
	}
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

// handleRevoke revokes refresh tokens (RFC 7009) and access tokens. Per the
// spec it responds 200 even when the token is unknown, to avoid leaking token
// validity. Access tokens are stateless JWTs: when the presented token is a
// valid access token of this IdP, its jti is put on the denylist until its
// natural expiry, so /userinfo and /introspect reject it immediately.
// (Without this, a revoked session's access token would stay valid for its
// full TTL.)
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireClientAuth(w, r) {
		return
	}
	_ = r.ParseForm()
	token := r.PostForm.Get("token")
	if token != "" {
		// Any audience is accepted here: /revoke must be able to deny tokens
		// minted under a previous audience configuration, too.
		if claims, err := s.parseAccessToken(token, false); err == nil {
			if jti, _ := claims["jti"].(string); jti != "" {
				until := time.Now().Add(s.cfg.AccessTokenTTL) // fail-safe horizon
				if exp, _ := claims.GetExpirationTime(); exp != nil {
					until = exp.Time
				}
				s.store.denyJTI(jti, until)
				slog.Info("access token denied by revocation", "sub", claims["sub"])
			}
		} else {
			s.store.revokeToken(token)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleEndSession implements a minimal logout. A post_logout_redirect_uri is
// honoured only when it exactly matches an entry of the configured redirect
// allowlist, and the redirect always targets the allowlist entry itself — never
// the user-supplied string — so the endpoint cannot be abused for open
// redirects (gosec G710).
//
// Logout is only as real as the tokens it kills: when the caller passes an
// id_token_hint (the OIDC end-session parameter), the hint's sid claim
// identifies the token family of that authorization, and the whole family is
// revoked — refresh tokens deleted and live access tokens denied by jti.
// Without a hint there is no session cookie to identify a caller, so no
// server-side state is dropped.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	if hint := r.URL.Query().Get("id_token_hint"); hint != "" {
		// The hint is verified laxly (signature + issuer, no expiry): an
		// expired id_token_hint still identifies the session to terminate.
		if claims, err := s.parseIDTokenHint(hint); err == nil {
			if sid, _ := claims["sid"].(string); sid != "" {
				s.store.revokeFamilyTokens(sid)
				slog.Info("logout: token family revoked", "sub", claims["sub"])
			}
		}
	}
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if target != "" {
		if allowed := s.registeredRedirect(target); allowed != "" {
			http.Redirect(w, r, allowed, http.StatusFound)
			return
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
