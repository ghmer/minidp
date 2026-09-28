package idp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
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

// OAuth2 grant types a client may be registered for (RFC 6749). Clients
// without an explicit grant_types entry keep the historic default:
// GrantAuthorizationCode and GrantRefreshToken.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
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
	// constant time at /token and honored by /introspect and /revoke. It
	// must be empty for public clients.
	ClientSecret string `json:"client_secret,omitempty"`
	// Audience is the "aud" value written into the client's tokens. It
	// defaults to the client id.
	Audience string `json:"audience,omitempty"`
	// GrantTypes are the OAuth2 grants the client may use at /token.
	// Optional; the default is ["authorization_code", "refresh_token"] so
	// pre-grant registrations behave exactly as before. client_credentials
	// is the machine-to-machine grant (RFC 6749 §4.4) and is opt-in per
	// client; it requires the confidential profile.
	GrantTypes []string `json:"grant_types,omitempty"`
	// ClientCredentialsScopes are the scopes released on the client's
	// client_credentials access tokens. There is no login or consent step
	// for that grant, so scopes cannot be requested at token time: they
	// must be configured statically here (and be non-empty when the
	// client_credentials grant is enabled).
	ClientCredentialsScopes []string `json:"client_credentials_scopes,omitempty"`
	// AllowedScopes are the custom, resource-specific delegated scopes the
	// client may request at /authorize in addition to the built-in OIDC
	// scopes (openid, profile, email). Each entry must reference the
	// client's own audience in the resource-scope form
	// api://<audience>/<name> (e.g. api://policy-api/access_as_user); the
	// name part is the permission released into the access token's scope
	// claim. Requests for anything outside this list fail with
	// invalid_scope — the provider never reflects arbitrary
	// resource/scope strings.
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	// ClientCredentialsRoles are the Entra-style app roles released in the
	// roles claim of this client's client_credentials (app-only) access
	// tokens. They must be configured statically — there is no consent step
	// for the grant — and, when the clients file defines a role registry for
	// the client's audience, must be a subset of that registry.
	ClientCredentialsRoles []string `json:"client_credentials_roles,omitempty"`
	// RedirectURIs are the registered authorization-response targets. The
	// policy is mandatory; requests are honored only for these exact values.
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

// ResourceDefinition describes one target API (audience) and the app roles
// that may be assigned for it — the optional role registry used to validate
// client_credentials_roles and user role assignments. An audience without a
// definition imposes no role constraint, so existing files keep working.
type ResourceDefinition struct {
	Audience string   `json:"audience"`
	AppRoles []string `json:"app_roles"`
}

// ClientsFile bundles the parsed clients file: the registered clients plus
// the optional per-audience role registry.
type ClientsFile struct {
	Clients   []Client
	Resources []ResourceDefinition
}

// Confidential reports whether the client uses the confidential profile.
func (c Client) Confidential() bool { return c.Type == TypeConfidential }

// grants resolves the client's enabled grants: the configured list, or the
// historic default for registrations without an explicit one.
func (c Client) grants() []string {
	if len(c.GrantTypes) == 0 {
		return []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	return c.GrantTypes
}

// AllowsGrant reports whether the client may use the given OAuth2 grant at
// the token endpoint.
func (c Client) AllowsGrant(grant string) bool {
	return slices.Contains(c.grants(), grant)
}

// Interactive reports whether the client participates in the browser-based
// authorization_code or refresh_token flows — the only grants with user
// context, and therefore the only ones that need redirect URIs and accounts.
func (c Client) Interactive() bool {
	return c.AllowsGrant(GrantAuthorizationCode) || c.AllowsGrant(GrantRefreshToken)
}

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
	// A client without users is either a transient state the clientctl tool
	// may write for an interactive client (client created, user not yet
	// added; the IdP refuses to start with one) or a legitimate
	// machine-to-machine client without interactive accounts.
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
			return fmt.Errorf("client %q: a confidential client requires a client_secret "+
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
	if err := c.validateGrants(); err != nil {
		return err
	}
	if err := c.validateCCRoles(); err != nil {
		return err
	}
	return c.validateAllowedScopes()
}

// validateCCRoles checks the app-role list for the client_credentials grant:
// whitespace-free, non-empty, duplicate-free entries, and the roles are only
// valid when the grant itself is enabled (mirroring the client_credentials
// scopes rule).
func (c Client) validateCCRoles() error {
	if len(c.ClientCredentialsRoles) == 0 {
		return nil
	}
	if !c.AllowsGrant(GrantClientCredentials) {
		return fmt.Errorf("client %q: client_credentials_roles are set but the client_credentials grant is not enabled", c.ClientID)
	}
	seen := make(map[string]bool, len(c.ClientCredentialsRoles))
	for _, role := range c.ClientCredentialsRoles {
		if role == "" || role != strings.TrimSpace(role) || strings.ContainsAny(role, " \t\r\n") {
			return fmt.Errorf("client %q: client_credentials role %q must not be empty, whitespace-padded or contain whitespace",
				c.ClientID, role)
		}
		if seen[role] {
			return fmt.Errorf("client %q: duplicate client_credentials role %q", c.ClientID, role)
		}
		seen[role] = true
	}
	return nil
}

// validateGrants checks the grant_types / client_credentials_scopes pair:
// known grant names, the machine-to-machine grant only for confidential
// clients, statically configured (non-empty) scopes for it, and no scopes
// entry without the grant.
func (c Client) validateGrants() error {
	hasCC := false
	seen := make(map[string]bool, len(c.GrantTypes))
	for _, g := range c.GrantTypes {
		switch g {
		case GrantAuthorizationCode, GrantRefreshToken:
		case GrantClientCredentials:
			hasCC = true
		default:
			return fmt.Errorf("client %q: invalid grant type %q: must be %q, %q or %q",
				c.ClientID, g, GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials)
		}
		if seen[g] {
			return fmt.Errorf("client %q: duplicate grant type %q", c.ClientID, g)
		}
		seen[g] = true
	}
	if !hasCC {
		if len(c.ClientCredentialsScopes) > 0 {
			return fmt.Errorf("client %q: client_credentials_scopes are set but the %q grant is not enabled",
				c.ClientID, GrantClientCredentials)
		}
		return nil
	}
	if !c.Confidential() {
		return fmt.Errorf("client %q: the %q grant requires the confidential profile "+
			"(client authentication at the token endpoint, RFC 6749 §4.4)",
			c.ClientID, GrantClientCredentials)
	}
	if len(c.ClientCredentialsScopes) == 0 {
		return fmt.Errorf("client %q: the %q grant requires a non-empty client_credentials_scopes list "+
			"(there is no login step, so scopes cannot be requested at token time)",
			c.ClientID, GrantClientCredentials)
	}
	for _, sc := range c.ClientCredentialsScopes {
		if strings.TrimSpace(sc) == "" || sc != strings.TrimSpace(sc) || strings.ContainsAny(sc, " \t\r\n") {
			return fmt.Errorf("client %q: client_credentials_scope %q must not be empty, whitespace-padded or contain whitespace",
				c.ClientID, sc)
		}
	}
	return nil
}

// validateAllowedScopes checks the client's custom delegated scope list
// (review finding M1's resource-scope counterpart): each entry must be
// whitespace-free, must use the api://<authority>/<name> resource-scope
// form, and its authority must reference the client's own audience (an
// optional api:// prefix on the audience is ignored on both sides), so a
// client can never request authorization for a foreign resource.
func (c Client) validateAllowedScopes() error {
	wantAuthority := strings.TrimPrefix(c.audience(), "api://")
	for _, sc := range c.AllowedScopes {
		if sc == "" || sc != strings.TrimSpace(sc) || strings.ContainsAny(sc, " \t\r\n") {
			return fmt.Errorf("client %q: allowed_scope %q must not be empty, whitespace-padded or contain whitespace",
				c.ClientID, sc)
		}
		authority, name, ok := strings.Cut(strings.TrimPrefix(sc, "api://"), "/")
		if !ok || authority == "" || name == "" {
			return fmt.Errorf("client %q: allowed_scope %q must have the api://<audience>/<name> form",
				c.ClientID, sc)
		}
		if authority != wantAuthority {
			return fmt.Errorf("client %q: allowed_scope %q must reference the client's own audience %q",
				c.ClientID, sc, wantAuthority)
		}
	}
	return nil
}

// validateURLs checks the redirect, post-logout and origin lists. A
// redirect_uri is required only for clients with an interactive grant: a
// purely machine-to-machine client (client_credentials only) never sends the
// browser anywhere. Extra lists stay validated whenever present.
func (c Client) validateURLs() error {
	if c.Interactive() && len(c.RedirectURIs) == 0 {
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
// honored (or worse, be honored for a different URL than intended).
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
// Shared with the clientctl tool. Files may also carry the optional role
// registry; use ReadClientsFile when it must be preserved.
func ReadClients(path string) ([]Client, error) {
	file, err := ReadClientsFile(path)
	if err != nil {
		return nil, err
	}
	return file.Clients, nil
}

// ReadClientsFile parses and fully validates a clients file in either form:
// the legacy bare JSON array of clients (no role registry) or the object
// form {"clients": [...], "resources": [...]}.
func ReadClientsFile(path string) (*ClientsFile, error) {
	raw, err := readScopedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read clients file: %w", err)
	}
	file := &ClientsFile{}
	switch firstNonSpace(raw) {
	case '[':
		var clients []Client
		if err := json.Unmarshal(raw, &clients); err != nil {
			return nil, fmt.Errorf("clients file %q is not a valid JSON array of clients: %w", path, err)
		}
		file.Clients = clients
	case '{':
		var doc struct {
			Clients   *[]Client            `json:"clients"`
			Resources []ResourceDefinition `json:"resources"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("clients file %q is not a valid JSON clients document: %w", path, err)
		}
		if doc.Clients == nil {
			return nil, fmt.Errorf("clients file %q is an object but carries no clients array", path)
		}
		file.Clients = *doc.Clients
		file.Resources = doc.Resources
	default:
		return nil, fmt.Errorf("clients file %q is neither a JSON array of clients nor a clients document", path)
	}
	if err := validateClientSlice(file.Clients); err != nil {
		return nil, fmt.Errorf("clients file %q: %w", path, err)
	}
	if err := validateResourceRegistry(file.Resources, file.Clients); err != nil {
		return nil, fmt.Errorf("clients file %q: %w", path, err)
	}
	return file, nil
}

// firstNonSpace returns the first non-whitespace byte of the document, or 0
// for an empty document.
func firstNonSpace(raw []byte) byte {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b
		}
	}
	return 0
}

// validateResourceRegistry validates the optional per-audience role
// registry and its cross-references: audiences and role names must be
// whitespace-free and unique, and — for every audience that has a
// definition — the client_credentials_roles and user role assignments of
// the clients targeting that audience must be subsets of the defined roles.
// Audiences without a definition impose no constraint.
func validateResourceRegistry(resources []ResourceDefinition, clients []Client) error {
	roles := make(map[string]map[string]bool, len(resources))
	seenAudience := make(map[string]bool, len(resources))
	for _, res := range resources {
		if res.Audience == "" || strings.ContainsAny(res.Audience, " \t\r\n") {
			return fmt.Errorf("resource audience %q must be non-empty and free of whitespace", res.Audience)
		}
		if seenAudience[res.Audience] {
			return fmt.Errorf("duplicate resource audience %q", res.Audience)
		}
		seenAudience[res.Audience] = true
		if len(res.AppRoles) == 0 {
			return fmt.Errorf("resource %q must define at least one app role", res.Audience)
		}
		defined := make(map[string]bool, len(res.AppRoles))
		for _, role := range res.AppRoles {
			if role == "" || strings.ContainsAny(role, " \t\r\n") {
				return fmt.Errorf("resource %q: app role %q must be non-empty and free of whitespace", res.Audience, role)
			}
			if defined[role] {
				return fmt.Errorf("resource %q: duplicate app role %q", res.Audience, role)
			}
			defined[role] = true
		}
		roles[res.Audience] = defined
	}
	for _, c := range clients {
		defined, hasRegistry := roles[c.audience()]
		if !hasRegistry {
			continue
		}
		for _, role := range c.ClientCredentialsRoles {
			if !defined[role] {
				return fmt.Errorf("client %q: client_credentials role %q is not defined for audience %q",
					c.ClientID, role, c.audience())
			}
		}
		for _, u := range c.Users {
			for _, role := range u.Roles {
				if !defined[role] {
					return fmt.Errorf("client %q: user %q holds role %q, which is not defined for audience %q",
						c.ClientID, u.Username, role, c.audience())
				}
			}
		}
	}
	return nil
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

// ValidateClient checks one client entry against the clients-file rules and
// returns its validation error. Exported for the clientctl tool: it can
// pre-flight a mutated in-memory entry before a save, instead of letting the
// save-time slice validation report the problem.
func ValidateClient(c Client) error { return c.validate() }

// SaveClients validates and writes the clients file atomically (temp file +
// rename, mode 0600) in the legacy bare-array form. Used by the clientctl
// tool and tests. The file holds client secrets and password hashes, so it
// must stay private.
func SaveClients(path string, clients []Client) error {
	return SaveClientsFile(path, &ClientsFile{Clients: clients})
}

// SaveClientsFile validates and writes a clients file atomically (temp file
// + rename, mode 0600). Files without a role registry are written in the
// legacy bare-array form; with a registry the object form is used.
func SaveClientsFile(path string, file *ClientsFile) error {
	if err := validateClientSlice(file.Clients); err != nil {
		return err
	}
	if err := validateResourceRegistry(file.Resources, file.Clients); err != nil {
		return err
	}
	var data []byte
	var err error
	if len(file.Resources) == 0 {
		data, err = json.MarshalIndent(file.Clients, "", "  ")
	} else {
		data, err = json.MarshalIndent(struct {
			Clients   []Client             `json:"clients"`
			Resources []ResourceDefinition `json:"resources"`
		}{file.Clients, file.Resources}, "", "  ")
	}
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return saveJSONFile(path, data)
}

// registeredClient is a validated client entry with its resolved user store.
type registeredClient struct {
	users UserStore
	// explicitOrigins are the client's own CORS origin entries, normalised
	// (trailing slash stripped) for comparison against request origins.
	explicitOrigins map[string]bool
	client          Client
}

// ID returns the client's OAuth client identifier.
func (rc *registeredClient) ID() string { return rc.client.ClientID }

// Audience returns the audience written into this client's tokens.
func (rc *registeredClient) Audience() string { return rc.client.audience() }

// Confidential reports the client's RFC 6749 profile.
func (rc *registeredClient) Confidential() bool { return rc.client.Confidential() }

// allowsGrant reports whether this client may use the given OAuth2 grant at
// the token endpoint.
func (rc *registeredClient) AllowsGrant(grant string) bool { return rc.client.AllowsGrant(grant) }

// clientCredentialsScopes returns the statically configured scopes for this
// client's client_credentials access tokens (validated non-empty at load).
func (rc *registeredClient) clientCredentialsScopes() []string {
	return rc.client.ClientCredentialsScopes
}

// clientCredentialsRoles returns the app roles released on this client's
// client_credentials access tokens (validated against the optional role
// registry at load).
func (rc *registeredClient) clientCredentialsRoles() []string {
	return rc.client.ClientCredentialsRoles
}

// resolveClientCredentialsScopes maps the requested scope parameter onto the
// client's statically configured permissions (Entra ID /.default semantics):
// an absent parameter and the audience's .default form — with or without the
// api:// prefix — grant the full configured list, an exact configured entry
// grants that single permission, and anything else is rejected so the grant
// never issues unconfigured scopes.
func (rc *registeredClient) resolveClientCredentialsScopes(requested string) ([]string, bool) {
	configured := rc.clientCredentialsScopes()
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return configured, true
	}
	audience := strings.TrimPrefix(rc.Audience(), "api://")
	if requested == audience+"/.default" || requested == "api://"+audience+"/.default" {
		return configured, true
	}
	for _, sc := range configured {
		if sc == requested {
			return []string{sc}, true
		}
	}
	return nil, false
}

// allowsScope reports whether sc is one of the client's registered custom
// delegated scopes. The built-in OIDC scopes are governed by the
// provider-wide policy, not by this allowlist.
func (rc *registeredClient) allowsScope(sc string) bool {
	return slices.Contains(rc.client.AllowedScopes, sc)
}

// secret returns the client's credential (empty for public clients).
func (rc *registeredClient) secret() string { return rc.client.ClientSecret }

// userCount returns the number of accounts registered for this client.
func (rc *registeredClient) userCount() int { return rc.users.Count() }

// redirectURIAllowed reports whether raw is a registered redirect_uri of
// this client (exact string comparison; there is deliberately no open
// fallback).
func (rc *registeredClient) redirectURIAllowed(raw string) bool {
	return slices.Contains(rc.client.RedirectURIs, raw)
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
	byID map[string]*registeredClient
	// redirects and logoutRedirects hold the per-client allowlists keyed by
	// client id, so the redirect-target selection at the HTTP layer resolves
	// them from the server's own registry (never through a request-derived
	// client value — the returned entry must always trace back to the
	// loaded file, not to user input).
	redirects       map[string][]string
	logoutRedirects map[string][]string
	audiences       map[string]bool
	origins         map[string]bool
	ids             []string
	hasConfidential bool
}

// LoadClients reads and validates a clients file and indexes it into the
// account/registration backend of the IdP. Secrets are never logged.
func LoadClients(path string) (*clientRegistry, error) {
	file, err := ReadClientsFile(path)
	if err != nil {
		return nil, err
	}
	r, err := newClientRegistry(file.Clients)
	if err != nil {
		return nil, err
	}
	for _, id := range r.ids {
		rc := r.byID[id]
		slog.Info("client registered",
			"client", rc.ID(),
			"type", string(rc.client.Type),
			"grants", strings.Join(rc.client.grants(), ","),
			"audience", rc.Audience(),
			"redirect_uris", len(rc.client.RedirectURIs),
			"users", rc.userCount(),
		)
	}
	slog.Info("clients file loaded", "path", path, "clients", len(r.ids))
	return r, nil
}

// newClientRegistry indexes validated client entries. It derives each
// client's user store (with per-client timing equalization) and the
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
		if c.Interactive() && len(c.Users) == 0 {
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

// anyClientCredentials reports whether at least one registered client is
// enabled for the client_credentials grant. Discovery advertises the grant
// only when a client could actually use it.
func (r *clientRegistry) anyClientCredentials() bool {
	for _, id := range r.ids {
		if r.byID[id].AllowsGrant(GrantClientCredentials) {
			return true
		}
	}
	return false
}

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

// delegatedScopes returns the union of all clients' registered custom
// delegated scopes in deterministic file order — the provider-wide set
// discovery advertises in scopes_supported alongside the OIDC scopes.
func (r *clientRegistry) delegatedScopes() []string {
	var out []string
	seen := make(map[string]bool)
	for _, id := range r.ids {
		for _, sc := range r.byID[id].client.AllowedScopes {
			if !seen[sc] {
				seen[sc] = true
				out = append(out, sc)
			}
		}
	}
	return out
}

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
// equalization hash from the accounts' own bcrypt cost.
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

// DummyHash returns the timing-equalization hash (cost derived at load time).
func (s *staticUserStore) DummyHash() string { return s.dummyHash }
