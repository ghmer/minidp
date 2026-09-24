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

// clientForAuthorize resolves the registered client behind an authorization
// request and checks the parameters that decide whether an error may be
// delivered via redirect: an unknown client_id or an unregistered
// redirect_uri must be reported on an HTML page — redirecting to an
// unvalidated URI would be an open redirect (RFC 6749 §4.1.2.1). Only
// registered clients may start a flow, and only against their own registered
// redirect URIs (review findings H1/H2).
func (s *Server) clientForAuthorize(q url.Values) (*registeredClient, string) {
	if q.Get("client_id") == "" {
		return nil, "Missing client_id."
	}
	client := s.clients.lookup(q.Get("client_id"))
	if client == nil {
		return nil, "Unknown client_id."
	}
	if q.Get("redirect_uri") == "" {
		return client, "Missing redirect_uri."
	}
	if !client.redirectURIAllowed(q.Get("redirect_uri")) {
		return client, "The redirect_uri is not registered for this client."
	}
	return client, ""
}

// validateAuthorizeRequest checks everything that can be reported to the
// client's redirect_uri and returns an OAuth error code with a
// human-readable description, or "" when the request is acceptable.
func (s *Server) validateAuthorizeRequest(client *registeredClient, q url.Values) (code, description string) {
	if q.Get("response_type") != "code" {
		return "unsupported_response_type", `Unsupported response_type; only "code" (authorization code flow) is supported.`
	}
	if code, description := s.validatePKCEParams(client, q); code != "" {
		return code, description
	}
	if code, description := validatePrompt(q); code != "" {
		return code, description
	}
	if v := q.Get("response_mode"); v != "" && v != "query" {
		return "invalid_request", "Unsupported response_mode; only the default query mode is supported."
	}
	for _, p := range []string{"max_age", "acr_values", "display", "ui_locales"} {
		if q.Get(p) != "" {
			return "invalid_request", fmt.Sprintf("Unsupported parameter %q.", p)
		}
	}
	return validateScopes(q.Get("scope"))
}

// validatePKCEParams checks the PKCE parameters of an authorize request:
// mandatory for public clients (RFC 9700); optional but validated when a
// confidential client chooses to use it. The token endpoint re-verifies
// whatever challenge was stored with the code.
func (s *Server) validatePKCEParams(client *registeredClient, q url.Values) (code, description string) {
	challenge := q.Get("code_challenge")
	if challenge == "" {
		if !client.Confidential() {
			return "invalid_request", "Missing code_challenge: PKCE is required for public clients."
		}
		// Confidential client without PKCE: accepted, the secret is the
		// client's proof of identity at the token endpoint.
		return "", ""
	}
	// RFC 9700 (OAuth 2.0 Security BCP) mandates S256; plain offers no
	// protection over the wire and a browser SPA can always do S256.
	if m := q.Get("code_challenge_method"); m != "S256" {
		return "invalid_request", "Unsupported code_challenge_method; only S256 is supported."
	}
	if !validPKCEChallenge(challenge) {
		return "invalid_request", "Malformed code_challenge: expected 43-128 base64url characters (S256 digest)."
	}
	return "", ""
}

// validatePrompt rejects unsupported OIDC prompt values explicitly instead of
// accepting and ignoring them (review finding M3).
func validatePrompt(q url.Values) (code, description string) {
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
	return "", ""
}

// validateScopes checks the requested scopes against the IdP policy
// (review finding M1).
func validateScopes(raw string) (code, description string) {
	for _, sc := range parseScopes(raw) {
		if !supportedScopes[sc] {
			return "invalid_scope", fmt.Sprintf("Unsupported scope %q; supported scopes: openid profile email.", sc)
		}
	}
	return "", ""
}

// registeredRedirect returns the registered redirect_uri of the named client
// equal to raw (constant-time comparison), or "". Callers redirect to the
// returned entry itself — never to the user-supplied string (gosec G710);
// the allowlist is resolved through the server's registry, so it always
// traces back to the loaded clients file.
func (s *Server) registeredRedirect(clientID, raw string) string {
	for _, allowed := range s.clients.redirects[clientID] {
		if constantTimeEqual(allowed, raw) {
			return allowed
		}
	}
	return ""
}

// registeredLogoutRedirect returns the registered post_logout_redirect_uri of
// the named client equal to raw (constant-time comparison), or "".
func (s *Server) registeredLogoutRedirect(clientID, raw string) string {
	for _, allowed := range s.clients.logoutRedirects[clientID] {
		if constantTimeEqual(allowed, raw) {
			return allowed
		}
	}
	return ""
}

// authorizeErrorRedirect delivers a redirectable OAuth error to the client's
// registered redirect_uri (RFC 6749 §4.1.2.1), echoing the state parameter.
func (s *Server) authorizeErrorRedirect(w http.ResponseWriter, r *http.Request, client *registeredClient, q url.Values, code, description string) {
	s.redirectToClient(w, r, client, q, map[string]string{"error": code, "error_description": description})
}

// redirectToClient sends the browser back to the client's registered
// redirect_uri with extra query parameters (an error pair or the issued code)
// and the echoed state. It targets the registered entry itself, never the
// user-supplied string (gosec G710).
func (s *Server) redirectToClient(w http.ResponseWriter, r *http.Request, client *registeredClient, q url.Values, extra map[string]string) {
	target, err := url.Parse(s.registeredRedirect(client.ID(), q.Get("redirect_uri")))
	if err != nil || target.String() == "" {
		// Unreachable: the redirect_uri passed validateClientBinding, but the
		// error page is the safe fallback either way.
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: "Invalid redirect_uri."})
		return
	}
	params := target.Query()
	for key, value := range extra {
		params.Set(key, value)
	}
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
		if !pkceVerifierChar(v[i]) {
			return false
		}
	}
	return true
}

// pkceVerifierChar reports whether c is in the RFC 7636 §4.1 unreserved set
// [A-Za-z0-9-._~].
func pkceVerifierChar(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~':
		return true
	}
	return false
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
	client, problem := s.clientForAuthorize(q)
	if problem != "" {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: problem})
		return
	}
	if code, description := s.validateAuthorizeRequest(client, q); code != "" {
		s.authorizeErrorRedirect(w, r, client, q, code, description)
		return
	}
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Action: "/authorize",
		Hidden: oauthHiddenFields(q),
		// login_hint pre-fills the username field (OIDC Core §3.1.2.1).
		Username: q.Get("login_hint"),
	})
}

// renderAuthorizeError re-renders the login form with an error message,
// carrying the OAuth2 context through the hidden fields so a retry submits a
// complete form.
func (s *Server) renderAuthorizeError(w http.ResponseWriter, r *http.Request, form url.Values, status int, message string) {
	s.renderLoginPage(w, r, status, loginData{
		Action: "/authorize",
		Error:  message,
		Hidden: oauthHiddenFields(form),
	})
}

// oauthContextOf rebuilds the OAuth2 context (client_id, redirect_uri, state,
// PKCE challenge, ...) from the hidden fields echoed through the login form.
func oauthContextOf(form url.Values) url.Values {
	q := url.Values{}
	for _, f := range oauthHiddenFields(form) {
		q.Set(f.Name, f.Value)
	}
	return q
}

// handleAuthorizePost authenticates the user and, on success, redirects the
// browser back to the client with a single-use authorization code.
func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
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
		s.renderAuthorizeError(w, r, form, http.StatusBadRequest, "Your sign-in session expired or the request was tampered with. Please start again.")
		return
	}

	// Rate limiting happens only AFTER CSRF validation (review finding F5):
	// junk POSTs without a valid CSRF token cannot burn the IP budget of a
	// legitimate user sharing the same NAT. Brute-force attempts still carry
	// a browser-issued CSRF token and are throttled below.
	if !s.limiter.allow(ip) {
		slog.Warn("login rate limited", "ip", ip)
		s.renderAuthorizeError(w, r, form, http.StatusTooManyRequests, "Too many sign-in attempts. Please wait a minute and try again.")
		return
	}

	who, client, q, ok := s.authorizeContext(w, r, form, ip)
	if !ok {
		return
	}
	slog.Info("login succeeded", "ip", ip, "user", who.Sub, "client", client.ID())
	s.completeAuthorize(w, r, client, form, q, who.Sub)
}

// authorizeContext re-validates the OAuth2 context echoed through the form
// and authenticates the submitted credentials against the client's own user
// store. On any failure it renders the appropriate error (page or redirect)
// and reports ok=false. The client binding decides whether a failure is shown
// on the page or redirected; all remaining errors go to the client's
// registered redirect_uri.
func (s *Server) authorizeContext(w http.ResponseWriter, r *http.Request, form url.Values, ip string) (who subject, client *registeredClient, q url.Values, ok bool) {
	q = oauthContextOf(form)
	client, problem := s.clientForAuthorize(q)
	if problem != "" {
		s.renderLoginPage(w, r, http.StatusBadRequest, loginData{Message: problem})
		return subject{}, nil, nil, false
	}
	if code, description := s.validateAuthorizeRequest(client, q); code != "" {
		s.authorizeErrorRedirect(w, r, client, q, code, description)
		return subject{}, nil, nil, false
	}
	who, ok = s.authenticate(client, form.Get("username"), form.Get("password"))
	if !ok {
		slog.Warn("login failed", "ip", ip, "user", form.Get("username"), "client", client.ID())
		s.renderLoginPage(w, r, http.StatusUnauthorized, loginData{
			Action:   "/authorize",
			Error:    "Invalid username or password.",
			Username: form.Get("username"),
			Hidden:   oauthHiddenFields(form),
		})
		return subject{}, nil, nil, false
	}
	return who, client, q, true
}

// completeAuthorize issues a single-use authorization code for the
// authenticated user and redirects the browser back to the client. Failures
// re-render the login form.
func (s *Server) completeAuthorize(w http.ResponseWriter, r *http.Request, client *registeredClient, form, q url.Values, sub string) {
	code, err := s.store.addCode(&authCode{
		Sub:                 sub,
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
		Scopes:              parseScopes(q.Get("scope")),
	}, authCodeTTL)
	if err != nil {
		slog.Error("authorization code generation failed", "error", err)
		s.renderAuthorizeError(w, r, form, http.StatusInternalServerError, "Internal error. Please start again.")
		return
	}
	slog.Info("authorization code issued", "client", q.Get("client_id"), "redirect", q.Get("redirect_uri"))
	s.redirectToClient(w, r, client, q, map[string]string{"code": code})
}

// handleLanding renders the landing page for direct visits to the IdP root.
// Sign-in happens exclusively through a registered client's /authorize flow:
// users belong to clients, so there is no standalone login form here.
func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Message: "This is the identity provider of a registered OAuth2/OIDC client. " +
			"Sign in happens through your application's authorization request to /authorize.",
	})
}

// authenticateClient authenticates or identifies the client presenting a
// request to the token endpoint (RFC 6749 §2.3, RFC 9700 §2.3).
//
//   - Confidential client: client_secret_basic — HTTP Basic with
//     form-urlencoded credentials per RFC 6749 §2.3.1 — or
//     client_secret_post (client_id + client_secret form fields). The secret
//     is looked up by the presented client_id and compared in constant time;
//     credentials are only ever checked against the one client they name. If
//     a Basic-authenticated request also carries a form client_id that
//     differs from the authenticated one, it is rejected (RFC 9700 §2.3.2).
//   - Public client: no authentication is possible; the client_id form field
//     is mere identification (a Basic header for a public client carries no
//     credential and is ignored, matching RFC 6749 §2.3 for clients without
//     a secret).
//
// An authentication ATTEMPT for an unknown client_id answers RFC 6749 §5.2
// invalid_client; a bare identification with an unknown client_id answers
// invalid_grant (the grant cannot be bound). On failure the response has
// already been written. Failures are logged for audit/IDS purposes but
// deliberately NOT rate limited — see the handleToken rationale.
func (s *Server) authenticateClient(w http.ResponseWriter, r *http.Request) (*registeredClient, bool) {
	if rawID, rawPW, basic := r.BasicAuth(); basic {
		return s.authClientBasic(w, r, rawID, rawPW)
	}
	return s.identifyFormClient(w, r)
}

// identifyFormClient handles the form-based profile: the client_id form
// field either identifies a public client (no credentials possible) or names
// the confidential client whose client_secret form credential is verified.
func (s *Server) identifyFormClient(w http.ResponseWriter, r *http.Request) (*registeredClient, bool) {
	id := r.PostForm.Get("client_id")
	if id == "" {
		writeAuthError(w, "invalid_request", "Missing client_id.")
		return nil, false
	}
	client := s.clients.lookup(id)
	if client == nil {
		if r.PostForm.Get("client_secret") != "" {
			// An authentication attempt for an unregistered client.
			s.rejectClient(w, r, "client_secret_post")
			return nil, false
		}
		writeAuthError(w, "invalid_grant", "Unknown client_id.")
		return nil, false
	}
	if client.Confidential() && !constantTimeEqual(r.PostForm.Get("client_secret"), client.secret()) {
		s.rejectClient(w, r, "client_secret_post")
		return nil, false
	}
	return client, true
}

// authClientBasic implements client_secret_basic: HTTP Basic with
// form-urlencoded credentials (RFC 6749 §2.3.1). The client named by the
// Basic username is resolved first; only its own secret is compared, in
// constant time. A Basic header naming a public client carries no credential:
// identification then happens via the form body, exactly as without the
// header.
func (s *Server) authClientBasic(w http.ResponseWriter, r *http.Request, rawID, rawPW string) (*registeredClient, bool) {
	// RFC 6749 §2.3.1: client_id and secret are
	// application/x-www-form-urlencoded before being placed in the Basic
	// credentials, so they are decoded first.
	id, idErr := url.QueryUnescape(rawID)
	pw, pwErr := url.QueryUnescape(rawPW)
	if idErr != nil || pwErr != nil {
		s.rejectClient(w, r, "client_secret_basic")
		return nil, false
	}
	client := s.clients.lookup(id)
	if client == nil {
		s.rejectClient(w, r, "client_secret_basic")
		return nil, false
	}
	if !client.Confidential() {
		return s.identifyFormClient(w, r)
	}
	if !constantTimeEqual(pw, client.secret()) {
		s.rejectClient(w, r, "client_secret_basic")
		return nil, false
	}
	// A Basic-authenticated request must not smuggle a different
	// identification through the form body (RFC 9700 §2.3.2).
	if formID := r.PostForm.Get("client_id"); formID != "" && formID != client.ID() {
		s.rejectClient(w, r, "client_secret_basic")
		return nil, false
	}
	return client, true
}

// rejectClient logs a failed token-endpoint client authentication and writes
// the RFC 6749 §5.2 invalid_client response.
func (s *Server) rejectClient(w http.ResponseWriter, r *http.Request, method string) {
	s.tokenClientAuthFailed(r, method)
	s.invalidClient(w)
}

// tokenClientAuthFailed logs a failed token-endpoint client authentication.
// Log only, by design: limiting would hand attackers a denial-of-service
// against the token endpoint, while audit consumers get a distinct,
// greppable message.
func (s *Server) tokenClientAuthFailed(r *http.Request, method string) {
	slog.Warn("token endpoint client authentication failed", "ip", s.clientIP(r), "auth_method", method)
}

// invalidClient writes the RFC 6749 §5.2 invalid_client error. The
// WWW-Authenticate header is always sent: clients attempting Basic auth are
// required to receive it, and it is harmless for client_secret_post clients.
func (s *Server) invalidClient(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="minidp", error="invalid_client"`)
	writeError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
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
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r)
	case "":
		writeAuthError(w, "invalid_request", "Missing grant_type.")
	default:
		writeAuthError(w, "unsupported_grant_type",
			"Only authorization_code, refresh_token and client_credentials are supported.")
	}
}

// handleClientCredentialsGrant implements the machine-to-machine grant
// (RFC 6749 §4.4): the confidential client authenticates with its own
// credentials and receives an access token minted for itself. There is no
// user context: the token's subject is the client id, the audience and the
// scopes come exclusively from the client's registration (audience field,
// client_credentials_scopes), and no id_token or refresh token is issued.
//
// RFC 6749 §4.4.2 allows the client to send a scope parameter, but minidp
// resolves the scopes statically from the clients file — there is no login
// or consent step that could approve a runtime request, so the parameter is
// ignored and the configured scopes are granted.
func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}
	if !client.Confidential() || !client.AllowsGrant(GrantClientCredentials) {
		// The client either cannot keep a secret (public profile) or is not
		// opted in to the grant: both are policy, not authentication,
		// failures (RFC 6749 §5.2 unauthorized_client).
		writeAuthError(w, "unauthorized_client",
			"The client is not authorized to use the client_credentials grant.")
		return
	}
	s.issueAndWriteClientCredentials(w, client)
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
	// Client authentication/identification happens BEFORE the code is
	// consumed, so a failed or unauthenticated request cannot burn the
	// one-time code (RFC 6749 §4.1.3, RFC 9700 §4.4.1).
	//
	// RFC 6749 §4.1.3: the token request must repeat client_id (public
	// clients cannot authenticate; confidential clients present Basic or
	// client_secret_post credentials).
	client, ok := s.authenticateClient(w, r)
	if !ok {
		return
	}
	ac := s.store.takeCode(code)
	if ac == nil {
		slog.Warn("code rejected: unknown, expired or already redeemed", "ip", s.clientIP(r))
		writeAuthError(w, "invalid_grant", "Unknown, expired or already redeemed authorization code.")
		return
	}
	if !s.validateCodeGrant(w, r, form, ac, client) {
		return
	}

	// A fresh authorization starts a new refresh chain. A crypto/rand failure
	// here degrades to a 500 instead of panicking the process (finding F6).
	family, err := randomToken()
	if err != nil {
		slog.Error("token issuance failed", "grant", "authorization_code", "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "The token could not be issued.")
		return
	}
	s.issueAndWriteTokens(w, "authorization_code", &authContext{
		Sub:      ac.Sub,
		ClientID: ac.ClientID,
		Scopes:   ac.Scopes,
		Nonce:    ac.Nonce,
		Family:   family,
	})
}

// validateCodeGrant checks that the presenting client owns the redeemed code
// and that redirect_uri and the PKCE verifier match the authorization
// request. It writes the OAuth error itself and reports ok=false on any
// mismatch.
func (s *Server) validateCodeGrant(w http.ResponseWriter, r *http.Request, form url.Values, ac *authCode, client *registeredClient) bool {
	if client.ID() != ac.ClientID {
		writeAuthError(w, "invalid_grant", "client_id does not match the authorization request.")
		return false
	}
	redirectURI := form.Get("redirect_uri")
	switch {
	case redirectURI == "":
		writeAuthError(w, "invalid_request", "Missing redirect_uri.")
		return false
	case redirectURI != ac.RedirectURI:
		writeAuthError(w, "invalid_grant", "redirect_uri does not match the authorization request.")
		return false
	}
	if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, form.Get("code_verifier")) {
		slog.Warn("code rejected: PKCE verification failed", "ip", s.clientIP(r), "client", ac.ClientID)
		writeAuthError(w, "invalid_grant", "PKCE verification failed.")
		return false
	}
	return true
}

// issueAndWriteTokens mints a fresh token set for ctx and writes the JSON
// response; a failure degrades to a 500 instead of panicking the process
// (finding F6).
func (s *Server) issueAndWriteTokens(w http.ResponseWriter, grant string, ctx *authContext) {
	resp, err := s.issueTokens(ctx)
	if err != nil {
		slog.Error("token issuance failed", "grant", grant, "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "The token could not be issued.")
		return
	}
	slog.Info("tokens issued", "grant", grant, "client", ctx.ClientID, "sub", ctx.Sub)
	writeJSON(w, http.StatusOK, resp)
}

// issueAndWriteClientCredentials mints and writes the client_credentials
// grant response; a failure degrades to a 500 instead of panicking the
// process (finding F6).
func (s *Server) issueAndWriteClientCredentials(w http.ResponseWriter, client *registeredClient) {
	resp, err := s.issueClientCredentialsTokens(client)
	if err != nil {
		slog.Error("token issuance failed", "grant", "client_credentials", "client", client.ID(), "error", err)
		writeError(w, http.StatusInternalServerError, "server_error", "The token could not be issued.")
		return
	}
	slog.Info("tokens issued", "grant", "client_credentials", "client", client.ID(), "sub", client.ID())
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
	// RFC 6749 §6: a public client must identify itself with client_id; a
	// confidential client MUST authenticate (Basic or client_secret_post).
	// Authentication happens before the token is consumed so a foreign
	// client cannot burn a stolen refresh token.
	client, ok := s.authenticateClient(w, r)
	if !ok {
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
	if client.ID() != entry.ClientID {
		slog.Warn("refresh rejected: client_id mismatch", "ip", s.clientIP(r), "client", client.ID())
		s.store.revokeFamilyTokens(entry.Family)
		writeAuthError(w, "invalid_grant", "client_id does not match the refresh token.")
		return
	}

	s.issueAndWriteTokens(w, "refresh_token", &authContext{
		Sub:      entry.Sub,
		ClientID: entry.ClientID,
		Scopes:   entry.Scopes,
		Nonce:    entry.Nonce,
		Family:   entry.Family,
	})
}

// parseAccessToken parses and validates a signed JWT access token issued by
// this IdP: RS256 only, the configured issuer, a required expiry and the RFC
// 9068 "at+jwt" typ header — an id_token (typ JWT) is never accepted as a
// bearer access token (review finding H3). The jti revocation denylist is
// always honoured. When requireAudience is true the token must carry the
// audience of one of the registered clients, so tokens minted for any other
// audience are rejected at the resource endpoints (review finding H4).
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
	if requireAudience && !s.clients.audienceAllowed(aud) {
		return nil, fmt.Errorf("invalid token: audience not accepted here")
	}
	if jti, _ := claims["jti"].(string); jti != "" && s.store.isDeniedJTI(jti) {
		return nil, fmt.Errorf("invalid token: revoked")
	}
	return claims, nil
}

// verifyAccessToken is the resource-endpoint check: signature, access-token
// profile, issuer, expiry and a registered client's audience must all hold.
func (s *Server) verifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	return s.parseAccessToken(tokenString, true)
}

// parseIDTokenHint validates an id_token_hint for /end_session and returns
// the registered client the hint belongs to. Per OIDC RP-Initiated Logout
// the hint's signature and issuer are verified, and an EXPIRED hint still
// identifies the token family to revoke — so expiry is deliberately not
// enforced here (review finding M6). The audience is, however, checked: a
// signed id_token minted for a different audience is not a logout hint this
// provider has to honour (review finding F4). The registered-claims
// validation is disabled and issuer/audience are checked manually instead.
func (s *Server) parseIDTokenHint(hint string) (jwt.MapClaims, *registeredClient, error) {
	token, err := jwt.Parse(hint, func(t *jwt.Token) (any, error) {
		return &s.key.key.PublicKey, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithoutClaimsValidation(), // expiry is intentionally not enforced
	)
	if err != nil || !token.Valid {
		return nil, nil, fmt.Errorf("invalid token")
	}
	if typ, _ := token.Header["typ"].(string); typ != typIDToken {
		return nil, nil, fmt.Errorf("invalid token: not an id token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid claims")
	}
	if iss, _ := claims["iss"].(string); iss != s.cfg.Issuer {
		return nil, nil, fmt.Errorf("invalid token: foreign issuer")
	}
	aud, _ := claims.GetAudience()
	if len(aud) == 0 {
		return nil, nil, fmt.Errorf("invalid token: missing audience")
	}
	// The audience identifies the registered client the hint belongs to; the
	// post-logout redirect policy of THAT client governs the logout redirect.
	client := s.clients.clientForAudience(aud[0])
	if client == nil {
		return nil, nil, fmt.Errorf("invalid token: audience not accepted here")
	}
	return claims, client, nil
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
// revocation endpoints whenever the deployment has at least one confidential
// client (RFC 7662 strongly recommends authenticating introspection; an open
// /revoke is a free probe endpoint). Accepted: HTTP Basic auth
// (client_id as username, the client's secret as password) or a
// client_id/client_secret form pair — always checked against the named
// client's own secret, in constant time. When every registered client is
// public there is no secret to check and both endpoints are open.
//
// Documented trade-off (review finding F1): in an all-public deployment
// /revoke is an unauthenticated write operation, so anyone who merely
// OBSERVES a bearer token can revoke that session (denial of service for the
// victim: refresh family revoked, live access tokens denied via jti). Public
// clients have no secret to authenticate with and sender-constraining (DPoP)
// is out of scope for minidp; see the README section "Security trade-offs".
func (s *Server) requireClientAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.clients.anyConfidential() {
		return true
	}
	if id, pw, ok := r.BasicAuth(); ok {
		if id, err := url.QueryUnescape(id); err == nil {
			if client := s.clients.lookup(id); client != nil && client.Confidential() &&
				constantTimeEqual(pw, client.secret()) {
				return true
			}
		}
	}
	_ = r.ParseForm()
	if id := r.PostForm.Get("client_id"); id != "" {
		if client := s.clients.lookup(id); client != nil && client.Confidential() &&
			constantTimeEqual(r.PostForm.Get("client_secret"), client.secret()) {
			return true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="minidp"`)
	writeError(w, http.StatusUnauthorized, "invalid_client", "Client authentication required.")
	return false
}

// invalidTokenResponse writes the RFC 6750 invalid_token bearer error.
func invalidTokenResponse(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or missing access token.")
}

// insufficientScope writes the RFC 6750 insufficient_scope bearer error for
// a token without the openid scope.
func insufficientScope(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
	writeError(w, http.StatusForbidden, "insufficient_scope", "The openid scope is required for UserInfo.")
}

// handleUserinfo returns the claims of the authenticated user for a valid
// access token. The token must carry the configured audience, the access
// token profile (typ at+jwt) and the openid scope; profile claims are
// released according to the granted scopes and resolved from the users-file
// record — never synthesised (review findings H3/H4/M2/L2). `name` is
// emitted alongside preferred_username so the response matches the
// claims_supported advertised by discovery (review finding F3).
func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	claims, err := s.verifyAccessToken(bearerToken(r))
	if err != nil {
		invalidTokenResponse(w)
		return
	}
	// A token without a scope claim grants nothing: fail closed.
	scopeRaw, _ := claims["scope"].(string)
	scopes := parseScopes(scopeRaw)
	if !hasScope(scopes, "openid") {
		insufficientScope(w)
		return
	}
	writeJSON(w, http.StatusOK, s.userinfoClaims(claims, scopes))
}

// userinfoClaims assembles the UserInfo response for the token's subject.
// The token's audience identifies the registered client whose user store
// holds the authoritative record; the scope-gated token claims are the
// fallback for subjects that have since been removed from the clients file.
// The access token carries no name claim, so for such subjects the name is
// simply omitted (an absent claim is never fabricated).
func (s *Server) userinfoClaims(claims jwt.MapClaims, scopes []string) map[string]any {
	sub, _ := claims["sub"].(string)
	wantProfile := hasScope(scopes, "profile")
	wantEmail := hasScope(scopes, "email")
	out := map[string]any{"sub": sub}
	var store UserStore
	if aud, _ := claims.GetAudience(); len(aud) > 0 {
		if client := s.clients.clientForAudience(aud[0]); client != nil {
			store = client.users
		}
	}
	if store != nil {
		if u, ok := store.Lookup(sub); ok {
			addScopeClaims(out, wantProfile, wantEmail, u.Username, u.Name, u.Email)
			return out
		}
	}
	username, _ := claims["preferred_username"].(string)
	email, _ := claims["email"].(string)
	addScopeClaims(out, wantProfile, wantEmail, username, "", email)
	return out
}

// addScopeClaims copies profile/email claims into out according to the
// granted scopes, omitting empty values (an absent claim is never
// fabricated).
func addScopeClaims(out map[string]any, wantProfile, wantEmail bool, username, name, email string) {
	if wantProfile && username != "" {
		out["preferred_username"] = username
	}
	if wantProfile && name != "" {
		out["name"] = name
	}
	if wantEmail && email != "" {
		out["email"] = email
	}
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
// honoured only when it exactly matches an entry of the redirecting client's
// post_logout_redirect_uris allowlist, and the redirect always targets the
// allowlist entry itself — never the user-supplied string — so the endpoint
// cannot be abused for open redirects (gosec G710). The client is resolved
// from the id_token_hint's audience (preferred) or the client_id parameter;
// without a resolvable client there is no redirect.
//
// Logout is only as real as the tokens it kills: when the caller passes an
// id_token_hint (the OIDC end-session parameter), the hint's sid claim
// identifies the token family of that authorization, and the whole family is
// revoked — refresh tokens deleted and live access tokens denied by jti.
// Without a hint there is no session cookie to identify a caller, so no
// server-side state is dropped.
func (s *Server) handleEndSession(w http.ResponseWriter, r *http.Request) {
	var client *registeredClient
	if hint := r.URL.Query().Get("id_token_hint"); hint != "" {
		// The hint is verified for signature, issuer and audience; expiry is
		// deliberately not enforced: an expired id_token_hint still identifies
		// the session to terminate (review findings M6/F4).
		if claims, hintClient, err := s.parseIDTokenHint(hint); err == nil {
			client = hintClient
			if sid, _ := claims["sid"].(string); sid != "" {
				s.store.revokeFamilyTokens(sid)
				slog.Info("logout: token family revoked", "sub", claims["sub"], "client", client.ID())
			}
		}
	}
	if client == nil {
		if id := r.URL.Query().Get("client_id"); id != "" {
			client = s.clients.lookup(id)
		}
	}
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if target != "" && client != nil {
		if allowed := s.registeredLogoutRedirect(client.ID(), target); allowed != "" {
			http.Redirect(w, r, allowed, http.StatusFound)
			return
		}
	}
	s.renderLoginPage(w, r, http.StatusOK, loginData{
		Message: "You have been signed out.",
	})
}

// handleStaticCSS serves the active login stylesheet: the embedded default or
// an operator-provided override from the assets directory.
func (s *Server) handleStaticCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(s.template.css)
}

// handleStaticLogo serves the active logo: the embedded default or an
// operator-provided override from the assets directory.
func (s *Server) handleStaticLogo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write(s.template.logo)
}
