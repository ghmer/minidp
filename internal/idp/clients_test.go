package idp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testHash derives a cheap bcrypt hash for test fixtures.
func testHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password, bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return h
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// validClient returns a client entry that passes every validation check.
func validClient(t *testing.T) Client {
	t.Helper()
	return Client{
		ClientID:     "app",
		Type:         TypePublic,
		RedirectURIs: []string{"https://app.example.com/callback"},
		Users: []User{
			{Username: "alice", PasswordHash: testHash(t, "alice-password")},
		},
	}
}

func TestClientStoreLookup(t *testing.T) {
	users := []User{
		{Username: "alice", PasswordHash: testHash(t, "wonderland"), Email: "alice@example.com", Name: "Alice", Roles: []string{"admin", "auditor"}},
		{Username: "bob", PasswordHash: testHash(t, "builder")},
	}
	store := newStaticUserStore(users)
	if store.Count() != 2 {
		t.Fatalf("Count = %d, want 2", store.Count())
	}
	alice, ok := store.Lookup("alice")
	if !ok || alice.Email != "alice@example.com" || alice.Name != "Alice" {
		t.Fatalf("Lookup(alice) = %+v, ok = %v", alice, ok)
	}
	if len(alice.Roles) != 2 || alice.Roles[0] != "admin" || alice.Roles[1] != "auditor" {
		t.Errorf("Lookup(alice).Roles = %v, want [admin auditor]", alice.Roles)
	}
	if !verifyHash(alice.PasswordHash, "wonderland") {
		t.Error("alice's hash does not verify her password")
	}
	if _, ok := store.Lookup("nobody"); ok {
		t.Error("Lookup for an unknown user must fail")
	}
}

func TestClientValidation(t *testing.T) {
	mutated := func(change func(*Client)) Client {
		c := validClient(t)
		change(&c)
		return c
	}
	for name, tc := range map[string]Client{
		"empty client_id":     mutated(func(c *Client) { c.ClientID = "  " }),
		"whitespace id":       mutated(func(c *Client) { c.ClientID = " app " }),
		"space inside id":     mutated(func(c *Client) { c.ClientID = "my app" }),
		"missing type":        mutated(func(c *Client) { c.Type = "" }),
		"unknown type":        mutated(func(c *Client) { c.Type = "hybrid" }),
		"public with secret":  mutated(func(c *Client) { c.ClientSecret = "leaked-secret" }),
		"confidential secret": mutated(func(c *Client) { c.Type = TypeConfidential; c.ClientSecret = "" }),
		"whitespace audience": mutated(func(c *Client) { c.Audience = "my api" }),
		"no redirects":        mutated(func(c *Client) { c.RedirectURIs = nil }),
		"relative redirect":   mutated(func(c *Client) { c.RedirectURIs = []string{"/callback"} }),
		"javascript redirect": mutated(func(c *Client) { c.RedirectURIs = []string{"javascript:alert(1)"} }),
		"fragment redirect":   mutated(func(c *Client) { c.RedirectURIs = []string{"https://x.example/cb#frag"} }),
		"bad post-logout":     mutated(func(c *Client) { c.PostLogoutRedirectURIs = []string{"http://"} }),
		"bad origin":          mutated(func(c *Client) { c.AllowedOrigins = []string{"not a url"} }),
		"plaintext password":  mutated(func(c *Client) { c.Users = []User{{Username: "a", PasswordHash: "secret"}} }),
		"empty username": mutated(func(c *Client) {
			c.Users = []User{{Username: "  ", PasswordHash: "$2a$10$0123456789012345678901234567890123456789012345678901234"}}
		}),
		"duplicate users": mutated(func(c *Client) {
			c.Users = []User{
				{Username: "a", PasswordHash: "$2a$10$0123456789012345678901234567890123456789012345678901234"},
				{Username: "a", PasswordHash: "$2a$10$0123456789012345678901234567890123456789012345678901234"},
			}
		}),
		"duplicate role": mutated(func(c *Client) {
			c.Users = []User{{Username: "a", PasswordHash: "$2a$10$0123456789012345678901234567890123456789012345678901234", Roles: []string{"x", "x"}}}
		}),
	} {
		if err := tc.validate(); err == nil {
			t.Errorf("%s: expected a validation error, got none", name)
		}
	}
	// The unmutated entry and a valid confidential variant pass.
	if err := validClient(t).validate(); err != nil {
		t.Errorf("valid public client rejected: %v", err)
	}
	confidential := validClient(t)
	confidential.Type = TypeConfidential
	confidential.ClientSecret = "a-confidential-secret"
	if err := confidential.validate(); err != nil {
		t.Errorf("valid confidential client rejected: %v", err)
	}
}

func TestReadClientsErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"malformed json": `[{"client_id": "app",`,
		"not an array":   `{"client_id": "app"}`,
		"duplicate ids": `[{"client_id": "app", "type": "public", "redirect_uris": ["https://a.example/cb"], "users": [{"username": "u", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234"}]},` +
			`{"client_id": "app", "type": "public", "redirect_uris": ["https://b.example/cb"], "users": [{"username": "u", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234"}]}]`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, name+"-clients.json")
		writeFile(t, path, content)
		if _, err := ReadClients(path); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
	if _, err := ReadClients(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error for a missing clients file")
	}
}

func TestSaveClientsRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	clients := []Client{validClient(t), validClient(t)}
	clients[1].ClientID = "second"
	clients[1].Type = TypeConfidential
	clients[1].ClientSecret = "a-confidential-secret"
	if err := SaveClients(path, clients); err != nil {
		t.Fatalf("SaveClients: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("clients file mode = %o, want 600 (it holds secrets)", perm)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files were not cleaned up, found %d entries", len(entries))
	}

	// The saved file is valid JSON with the expected entries, and the secret
	// survives the round trip (list/show never print it, but the file must
	// keep it).
	decoded, err := ReadClients(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(decoded) != 2 || decoded[0].ClientID != "app" || decoded[1].ClientSecret != "a-confidential-secret" {
		t.Fatalf("unexpected contents: %+v", decoded)
	}
}

func TestSaveClientsRejectsInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	bad := validClient(t)
	bad.ClientSecret = "leaked"
	if err := SaveClients(filepath.Join(dir, "c.json"), []Client{bad}); err == nil {
		t.Error("expected an error for a public client with a secret")
	}
	empty := validClient(t)
	empty.Users = nil
	if err := SaveClients(filepath.Join(dir, "c.json"), []Client{empty}); err != nil {
		t.Errorf("a client without users is a valid transient state for the tool: %v", err)
	}
	// Nothing may have been written by the failed attempts.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("failed saves must not leave files behind (the successful one may exist), found %d", len(entries))
	}
}

// TestRegistryRefusesUnusableStates pins the startup-only rules: the file
// format tolerates transient states the clientctl tool writes, but the IdP
// refuses to start with them.
func TestRegistryRefusesUnusableStates(t *testing.T) {
	if _, err := newClientRegistry(nil); err == nil {
		t.Error("expected an error for an empty registry")
	}
	userless := validClient(t)
	userless.Users = nil
	if _, err := newClientRegistry([]Client{userless}); err == nil {
		t.Error("expected an error for a client without users")
	}
	if _, err := newClientRegistry([]Client{validClient(t), validClient(t)}); err == nil {
		t.Error("expected an error for duplicate client ids")
	}
}

func TestClientRegistry(t *testing.T) {
	public := validClient(t)
	confidential := validClient(t)
	confidential.ClientID = "conf"
	confidential.Audience = "conf-api"
	confidential.Type = TypeConfidential
	confidential.ClientSecret = "a-confidential-secret"
	confidential.RedirectURIs = []string{"https://conf.example.com/cb"}
	confidential.AllowedOrigins = []string{"https://conf-spa.example.com"}
	registry, err := newClientRegistry([]Client{public, confidential})
	if err != nil {
		t.Fatalf("newClientRegistry: %v", err)
	}

	if got := registry.lookup("app"); got == nil || got.ID() != "app" {
		t.Errorf("lookup(app) = %v", got)
	}
	if registry.lookup("missing") != nil {
		t.Error("lookup of an unknown id must return nil")
	}
	if registry.anyConfidential() == false {
		t.Error("registry must report the confidential client")
	}

	// Audience defaults to the client id; an explicit audience is kept.
	app := registry.lookup("app")
	if app.Audience() != "app" {
		t.Errorf("audience of app = %q, want the client id", app.Audience())
	}
	conf := registry.lookup("conf")
	if conf.Audience() != "conf-api" {
		t.Errorf("audience of conf = %q, want conf-api", conf.Audience())
	}
	if !registry.audienceAllowed([]string{"conf-api"}) || !registry.audienceAllowed([]string{"app"}) {
		t.Error("registered audiences must be accepted")
	}
	if registry.audienceAllowed([]string{"other-api"}) {
		t.Error("a foreign audience must not be accepted")
	}
	if got := registry.clientForAudience("conf-api"); got != conf {
		t.Errorf("clientForAudience(conf-api) = %v", got)
	}
	if got := registry.clientForAudience("nope"); got != nil {
		t.Errorf("clientForAudience(nope) = %v, want nil", got)
	}

	// CORS origins: every redirect host plus the explicit origins.
	origins := registry.allowedOrigins()
	for _, want := range []string{"https://app.example.com", "https://conf.example.com", "https://conf-spa.example.com"} {
		if !origins[want] {
			t.Errorf("origin %q missing from the CORS allowlist %v", want, origins)
		}
	}
	if origins["https://evil.example.com"] {
		t.Error("an unrelated origin must not be on the allowlist")
	}

	// Redirect policies are per client.
	if conf.redirectURIAllowed("https://app.example.com/callback") {
		t.Error("the confidential client must not honour the public client's redirect")
	}
}

func TestNewClientRegistryRejectsDuplicates(t *testing.T) {
	if _, err := newClientRegistry([]Client{validClient(t), validClient(t)}); err == nil {
		t.Error("expected an error for duplicate client ids")
	}
}

func TestHashPasswordRejectsInvalidCost(t *testing.T) {
	if _, err := HashPassword("x", 2); err == nil {
		t.Error("cost below MinCost must be rejected")
	}
	if _, err := HashPassword("x", 64); err == nil {
		t.Error("cost above MaxCost must be rejected")
	}
}

// The dummy hash used to equalise failed lookups must be a real, verifiable
// bcrypt hash so the timing equalisation actually burns the same work — at
// the cost of the stored user hashes, not an assumed default.
func TestDummyHashIsUsableBcryptHash(t *testing.T) {
	h := newDummyHash(bcrypt.DefaultCost)
	if !isBcryptHash(h) {
		t.Fatalf("dummy hash has unexpected format: %q", h)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("minidp-timing-equalizer-dummy")); err != nil {
		t.Fatalf("dummy hash does not verify: %v", err)
	}
}

func TestBcryptCostOf(t *testing.T) {
	for _, tc := range []struct {
		hash string
		want int
	}{
		{"", bcrypt.DefaultCost},
		{"garbage", bcrypt.DefaultCost},
		{"$2a$10$0123456789012345678901234567890123456789012345678901234", 10},
		{"$2y$14$0123456789012345678901234567890123456789012345678901234", 14},
		{"$2a$ab$0123456789012345678901234567890123456789012345678901234", bcrypt.DefaultCost},
		{"$2a$99$0123456789012345678901234567890123456789012345678901234", bcrypt.DefaultCost},
	} {
		if got := bcryptCostOf(tc.hash); got != tc.want {
			t.Errorf("bcryptCostOf(%q...) = %d, want %d", tc.hash[:min(12, len(tc.hash))], got, tc.want)
		}
	}
}

// TestClientsFileJSONShape pins the on-disk format so operators and the
// clientctl tool agree on it.
func TestClientsFileJSONShape(t *testing.T) {
	c := validClient(t)
	c.Type = TypeConfidential
	c.ClientSecret = "a-confidential-secret"
	c.Audience = "app-api"
	c.PostLogoutRedirectURIs = []string{"https://app.example.com/"}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{`"client_id"`, `"type"`, `"client_secret"`, `"audience"`, `"redirect_uris"`, `"post_logout_redirect_uris"`, `"users"`} {
		if !strings.Contains(string(data), field) {
			t.Errorf("clients JSON is missing the %s field: %s", field, data)
		}
	}
}
