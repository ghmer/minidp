package idp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ClientType selects the RFC 6749 client profile of a registered client.
type ClientType string

const (
	// TypePublic is the public-client profile: the client cannot keep a
	// secret, PKCE (S256) is mandatory at /authorize and the token endpoint
	// accepts only client_id identification.
	TypePublic ClientType = "public"
	// TypeConfidential is the confidential-client profile: /token requires
	// client authentication (client_secret_basic or client_secret_post),
	// PKCE becomes optional, and /introspect//revoke accept the client's
	// credentials.
	TypeConfidential ClientType = "confidential"
)

// Client is one registered OAuth2/OIDC client in the clients file. Each
// client carries its own redirect policy, its own audience and its own user
// accounts, so a client's users can never sign in to another client's flow.
type Client struct {
	// ClientID is the OAuth client identifier presented at /authorize and
	// /token.
	ClientID string `json:"client_id"`
	// Type selects the RFC 6749 profile: public (mandatory PKCE, no secret)
	// or confidential (client authentication with the secret).
	Type ClientType `json:"type"`
	// ClientSecret is the credential of a confidential client, compared in
	// constant time at /token and honoured by /introspect and /revoke. It
	// must be empty for public clients.
	ClientSecret string `json:"client_secret,omitempty"`
	// Audience is the "aud" value written into the client's tokens. It
	// defaults to the client id.
	Audience string `json:"audience,omitempty"`
	// RedirectURIs are the registered authorization-response targets. The
	// policy is mandatory; requests are honoured only for these exact values.
	RedirectURIs []string `json:"redirect_uris"`
	// PostLogoutRedirectURIs are the targets /end_session may redirect to
	// after a logout. Optional: with no entries, logout renders a
	// confirmation page instead of redirecting.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// AllowedOrigins are extra explicit CORS origins granted to this client
	// in addition to the hosts of its redirect URIs.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// Users are the accounts that may sign in for this client. Passwords are
	// stored as bcrypt hashes; every other client's users are invisible to
	// this client's login form.
	Users []User `json:"users"`
}

// Confidential reports whether the client uses the confidential profile.
func (c Client) Confidential() bool { return c.Type == TypeConfidential }

// MarshalJSON serializes a client for the clients file. Implementing the
// marshaler explicitly keeps the on-disk format in one place. The
// client_secret is intentionally part of that format (the token endpoint
// compares it in constant time), so it is written verbatim — which is why the
// file must stay mode 0600 (SaveClients enforces this).
func (c Client) MarshalJSON() ([]byte, error) {
	type plain Client
	return json.Marshal(plain(c))
}

// validate checks one client entry when the clients file is loaded or saved.
func (c Client) validate() error {
	if err := c.validateIdentity(); err != nil {
		return err
	}
	if err := c.validateProfile(); err != nil {
		return err
	}
	if err := c.validateURLs(); err != nil {
		return err
	}
	// The users array is validated structurally (duplicates, hashes, roles).
	// A client without users is a transient state the clientctl tool may
	// write (client created, user not yet added); the IdP refuses to start
	// with one, and the tool warns about it.
	if err := validateUserSlice(c.Users); err != nil {
		return fmt.Errorf("client %q: %w", c.ClientID, err)
	}
	return nil
}

// validateIdentity checks the client_id shape: non-empty, whitespace-free
// (client_id travels through forms, URLs and logs).
func (c Client) validateIdentity() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return fmt.Errorf("client_id must not be empty")
	}
	if c.ClientID != strings.TrimSpace(c.ClientID) {
		return fmt.Errorf("client_id %q must not have leading or trailing whitespace", c.ClientID)
	}
	if strings.ContainsAny(c.ClientID, " \t\r\n") {
		return fmt.Errorf("client_id %q must not contain whitespace", c.ClientID)
	}
	return nil
}

// validateProfile checks the profile/secret combination: a public client must
// not carry a dead secret; a confidential client needs one.
func (c Client) validateProfile() error {
	switch c.Type {
	case TypePublic:
		if c.ClientSecret != "" {
			return fmt.Errorf("client %q: a public client must not have a client_secret", c.ClientID)
		}
	case TypeConfidential:
		if c.ClientSecret == "" {
			return fmt.Errorf("client %q: a confidential client requires a client_secret " +
				"(generate one with: openssl rand -base64 32)", c.ClientID)
		}
		if len(c.ClientSecret) < 16 {
			// Loud warning, not an error: the operator may accept the risk,
			// but a secret governing the token endpoint should be
			// cryptographically random (RFC 9700 §2.4 wants ≥128 bits).
			slog.Warn("client secret is shorter than 16 characters: use a cryptographically random secret of at least 128 bits for a confidential client", "client", c.ClientID)
		}
	default:
		return fmt.Errorf("client %q: invalid type %q: must be %q or %q", c.ClientID, string(c.Type), TypePublic, TypeConfidential)
	}
	if a := c.audience(); strings.ContainsAny(a, " \t\r\n") {
		return fmt.Errorf("client %q: audience %q must not contain whitespace", c.ClientID, a)
	}
	return nil
}

// validateURLs checks the redirect, post-logout and origin lists.
func (c Client) validateURLs() error {
	if len(c.RedirectURIs) == 0 {
		return fmt.Errorf("client %q: at least one redirect_uri is required", c.ClientID)
	}
	for _, raw := range c.RedirectURIs {
		if _, err := validateAbsoluteHTTPURL(raw, "redirect_uri"); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	for _, raw := range c.PostLogoutRedirectURIs {
		if _, err := validateAbsoluteHTTPURL(raw, "post_logout_redirect_uri"); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	for _, raw := range c.AllowedOrigins {
		if _, err := validateAbsoluteHTTPURL(raw, "allowed_origin"); err != nil {
			return fmt.Errorf("client %q: %w", c.ClientID, err)
		}
	}
	return nil
}

// audience returns the token audience, defaulting to the client id.
func (c Client) audience() string {
	if c.Audience != "" {
		return c.Audience
	}
	return c.ClientID
}

// validateAbsoluteHTTPURL enforces the shape every registered URL must have:
// an absolute http(s) URL with a host and no fragment. Allowlist comparisons
// are plain string equality, so a malformed entry could otherwise never be
// honoured (or worse, be honoured for a different URL than intended).
func validateAbsoluteHTTPURL(raw, what string) (string, error) {
	r := strings.TrimSpace(raw)
	if r == "" {
		return "", fmt.Errorf("%s must not be empty", what)
	}
	u, err := url.Parse(r)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", what, r, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid %s %q: must be an absolute http(s) URL with a host", what, r)
	}
	return r, nil
}

// ReadClients parses and fully validates a clients file into a Client slice.
// Shared with the clientctl tool.
func ReadClients(path string) ([]Client, error) {
	raw, err := readScopedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read clients file: %w", err)
	}
	var clients []Client
	if err := json.Unmarshal(raw, &clients); err != nil {
		return nil, fmt.Errorf("clients file %q is not a valid JSON array of clients: %w", path, err)
	}
	if err := validateClientSlice(clients); err != nil {
		return nil, fmt.Errorf("clients file %q: %w", path, err)
	}
	return clients, nil
}

// validateClientSlice validates every entry and rejects duplicate client ids.
// An empty slice is structurally valid (the clientctl tool creates files
// incrementally); starting the IdP with one is refused by the registry.
func validateClientSlice(clients []Client) error {
	seen := make(map[string]bool, len(clients))
	for i, c := range clients {
		if err := c.validate(); err != nil {
			return fmt.Errorf("entry %d (client %q): %w", i, c.ClientID, err)
		}
		if seen[c.ClientID] {
			return fmt.Errorf("duplicate client_id %q", c.ClientID)
		}
		seen[c.ClientID] = true
	}
	return nil
}

// SaveClients validates and writes the clients file atomically (temp file +
// rename, mode 0600). Used by the clientctl tool. The file holds client
// secrets and password hashes, so it must stay private.
func SaveClients(path string, clients []Client) error {
	if err := validateClientSlice(clients); err != nil {
		return err
	}
	data, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return saveJSONFile(path, data)
}

// registeredClient is a validated client entry with its resolved user store.
type registeredClient struct {
	client Client
	users  UserStore
	// explicitOrigins are the client's own CORS origin entries, normalised
	// (trailing slash stripped) for comparison against request origins.
	explicitOrigins map[string]bool
}

// ID returns the client's OAuth client identifier.
func (rc *registeredClient) ID() string { return rc.client.ClientID }

// Audience returns the audience written into this client's tokens.
func (rc *registeredClient) Audience() string { return rc.client.audience() }

// Confidential reports the client's RFC 6749 profile.
func (rc *registeredClient) Confidential() bool { return rc.client.Confidential() }

// secret returns the client's credential (empty for public clients).
func (rc *registeredClient) secret() string { return rc.client.ClientSecret }

// userCount returns the number of accounts registered for this client.
func (rc *registeredClient) userCount() int { return rc.users.Count() }

// redirectURIAllowed reports whether raw is a registered redirect_uri of
// this client (exact string comparison; there is deliberately no open
// fallback).
func (rc *registeredClient) redirectURIAllowed(raw string) bool {
	for _, allowed := range rc.client.RedirectURIs {
		if allowed == raw {
			return true
		}
	}
	return false
}

// constantTimeEqual compares two strings without leaking where the first
// difference occurs.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// clientRegistry is the in-memory index of the registered clients built from
// the clients file at startup. Lookups are by client_id; the union sets back
// the provider-wide metadata (CORS origins, accepted token audiences, client
// authentication methods).
type clientRegistry struct {
	byID            map[string]*registeredClient
	ids             []string
	// redirects and logoutRedirects hold the per-client allowlists keyed by
	// client id, so the redirect-target selection at the HTTP layer resolves
	// them from the server's own registry (never through a request-derived
	// client value — the returned entry must always trace back to the
	// loaded file, not to user input).
	redirects       map[string][]string
	logoutRedirects map[string][]string
	audiences       map[string]bool
	origins         map[string]bool
	hasConfidential bool
}

// LoadClients reads and validates a clients file and indexes it into the
// account/registration backend of the IdP. Secrets are never logged.
func LoadClients(path string) (*clientRegistry, error) {
	clients, err := ReadClients(path)
	if err != nil {
		return nil, err
	}
	r, err := newClientRegistry(clients)
	if err != nil {
		return nil, err
	}
	for _, id := range r.ids {
		rc := r.byID[id]
		slog.Info("client registered",
			"client", rc.ID(),
			"type", string(rc.client.Type),
			"audience", rc.Audience(),
			"redirect_uris", len(rc.client.RedirectURIs),
			"users", rc.userCount(),
		)
	}
	slog.Info("clients file loaded", "path", path, "clients", len(r.ids))
	return r, nil
}

// newClientRegistry indexes validated client entries. It derives each
// client's user store (with per-client timing equalisation) and the
// provider-wide union sets.
func newClientRegistry(clients []Client) (*clientRegistry, error) {
	if len(clients) == 0 {
		return nil, fmt.Errorf("clients file contains no clients: register at least one client (see clientctl)")
	}
	r := &clientRegistry{
		byID:            make(map[string]*registeredClient, len(clients)),
		redirects:       make(map[string][]string, len(clients)),
		logoutRedirects: make(map[string][]string, len(clients)),
		audiences:       make(map[string]bool, len(clients)),
		origins:         make(map[string]bool),
	}
	for _, c := range clients {
		if len(c.Users) == 0 {
			return nil, fmt.Errorf("client %q has no users: add at least one account (clientctl user add)", c.ClientID)
		}
		if _, dup := r.byID[c.ClientID]; dup {
			return nil, fmt.Errorf("duplicate client_id %q", c.ClientID)
		}
		rc := &registeredClient{
			client: c,
			users:  newStaticUserStore(c.Users),
		}
		rc.explicitOrigins = make(map[string]bool, len(c.AllowedOrigins))
		for _, o := range c.AllowedOrigins {
			rc.explicitOrigins[strings.TrimSuffix(o, "/")] = true
		}
		// CORS: every host of a redirect URI is granted (browser SPAs
		// exchange codes cross-origin with credentials), plus the client's
		// explicit origins.
		for _, raw := range c.RedirectURIs {
			if u, err := url.Parse(raw); err == nil && u.Host != "" {
				r.origins[u.Scheme+"://"+u.Host] = true
			}
		}
		for o := range rc.explicitOrigins {
			r.origins[o] = true
		}
		r.byID[c.ClientID] = rc
		r.ids = append(r.ids, c.ClientID)
		r.redirects[c.ClientID] = c.RedirectURIs
		r.logoutRedirects[c.ClientID] = c.PostLogoutRedirectURIs
		r.audiences[rc.Audience()] = true
		if rc.Confidential() {
			r.hasConfidential = true
		}
	}
	return r, nil
}

// lookup returns the registered client with the given client_id, or nil.
func (r *clientRegistry) lookup(clientID string) *registeredClient {
	return r.byID[clientID]
}

// clientIDs returns the registered ids in file order (for startup logging).
func (r *clientRegistry) clientIDs() []string { return r.ids }

// anyConfidential reports whether at least one registered client is
// confidential. The introspection and revocation endpoints require client
// authentication only when a secret exists that could authenticate anybody.
func (r *clientRegistry) anyConfidential() bool { return r.hasConfidential }

// audienceAllowed reports whether one of the token's audiences belongs to a
// registered client. Resource endpoints (userinfo, introspection) accept
// tokens minted for ANY registered client: a bearer token carries no client
// context, and it was minted by this provider for one of its clients.
func (r *clientRegistry) audienceAllowed(aud []string) bool {
	for _, a := range aud {
		if r.audiences[a] {
			return true
		}
	}
	return false
}

// clientForAudience returns the first registered client whose audience equals
// aud (used to resolve the client behind an id_token_hint at /end_session).
// Audiences should be unique per client; with duplicates the first client in
// file order wins for the logout redirect policy.
func (r *clientRegistry) clientForAudience(aud string) *registeredClient {
	for _, id := range r.ids {
		if rc := r.byID[id]; rc.Audience() == aud {
			return rc
		}
	}
	return nil
}

// allowedOrigins returns the provider-wide CORS origin allowlist: the hosts
// of every client's redirect URIs plus every client's explicit origins. Only
// these origins are reflected with credentials (see withCORS).
func (r *clientRegistry) allowedOrigins() map[string]bool { return r.origins }

// userCount returns the total number of accounts across all clients (for
// startup logging).
func (r *clientRegistry) userCount() int {
	n := 0
	for _, id := range r.ids {
		n += r.byID[id].userCount()
	}
	return n
}

// staticUserStore is the account backend of one registered client: the users
// array of its clients-file entry, read once at startup; changes take effect
// on restart.
type staticUserStore struct {
	byName    map[string]User
	dummyHash string
}

// newStaticUserStore indexes one client's users and derives the timing
// equalisation hash from the accounts' own bcrypt cost.
func newStaticUserStore(users []User) *staticUserStore {
	cost := bcrypt.DefaultCost
	if len(users) > 0 {
		cost = bcryptCostOf(users[0].PasswordHash)
	}
	s := &staticUserStore{
		byName:    make(map[string]User, len(users)),
		dummyHash: newDummyHash(cost),
	}
	for _, u := range users {
		s.byName[u.Username] = u
	}
	return s
}

// Lookup returns the user with the given username.
func (s *staticUserStore) Lookup(username string) (User, bool) {
	u, ok := s.byName[username]
	return u, ok
}

// Count returns the number of accounts.
func (s *staticUserStore) Count() int { return len(s.byName) }

// DummyHash returns the timing-equalisation hash (cost derived at load time).
func (s *staticUserStore) DummyHash() string { return s.dummyHash }
