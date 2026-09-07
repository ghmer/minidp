package main

// Regression tests for the clientctl tool: client and user management inside
// the clients file, stdin secret handling ("-" reads one line, an empty flag
// on a non-interactive stdin fails), and the invariant that other clients'
// entries survive every mutation.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/ghmer/minidp/internal/idp"
)

// bcryptCompare reports whether the hash verifies the password.
func bcryptCompare(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// withStdin swaps os.Stdin for a pipe carrying stdinText for the duration of
// the call (stdinText "" leaves stdin untouched).
func withStdin(t *testing.T, stdinText string) {
	t.Helper()
	if stdinText == "" {
		return
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(stdinText); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = w.Close()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old; _ = r.Close() })
}

// readClientsFile reads the clients file for assertions.
func readClientsFile(t *testing.T, file string) []idp.Client {
	t.Helper()
	clients, err := idp.ReadClients(file)
	if err != nil {
		t.Fatalf("read clients: %v", err)
	}
	return clients
}

func clientOf(t *testing.T, file, id string) idp.Client {
	t.Helper()
	for _, c := range readClientsFile(t, file) {
		if c.ClientID == id {
			return c
		}
	}
	t.Fatalf("client %q not found in %s", id, file)
	return idp.Client{}
}

func TestClientAddAndUpdate(t *testing.T) {
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := clientAdd([]string{"-file", file, "-client", "spa", "-type", "public",
		"-redirect", "https://spa.example.com/cb, https://spa.example.com/cb2 ,"}); err != nil {
		t.Fatalf("client add: %v", err)
	}
	c := clientOf(t, file, "spa")
	if c.Type != idp.TypePublic || len(c.RedirectURIs) != 2 || c.RedirectURIs[1] != "https://spa.example.com/cb2" {
		t.Fatalf("unexpected client entry: %+v", c)
	}

	// A confidential client takes its secret from the flag.
	if err := clientAdd([]string{"-file", file, "-client", "api", "-type", "confidential",
		"-secret", "a-confidential-secret", "-redirect", "https://api.example.com/cb",
		"-post-logout", "https://api.example.com/", "-origin", "https://api-spa.example.com"}); err != nil {
		t.Fatalf("client add confidential: %v", err)
	}
	c = clientOf(t, file, "api")
	if !c.Confidential() || c.ClientSecret != "a-confidential-secret" {
		t.Fatalf("unexpected confidential entry: %+v", c)
	}

	// Duplicate ids are rejected.
	err := clientAdd([]string{"-file", file, "-client", "spa", "-type", "public", "-redirect", "https://x.example/cb"})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate add: err = %v, want 'already exists'", err)
	}

	// Required flags.
	if err := clientAdd([]string{"-file", file, "-client", "x"}); err == nil {
		t.Error("add without -type must fail")
	}
	if err := clientAdd([]string{"-file", file, "-client", "x", "-type", "public"}); err == nil {
		t.Error("add without -redirect must fail")
	}
	if err := clientAdd([]string{"-file", file, "-client", "x", "-type", "hybrid", "-redirect", "https://x.example/cb"}); err == nil {
		t.Error("add with an unknown type must fail")
	}

	// Updates apply only the provided flags and keep the other client.
	if err := clientUpdate([]string{"-file", file, "-client", "spa", "-audience", "spa-aud"}); err != nil {
		t.Fatalf("client update: %v", err)
	}
	c = clientOf(t, file, "spa")
	if c.Audience != "spa-aud" || len(c.RedirectURIs) != 2 {
		t.Fatalf("update changed more than the audience: %+v", c)
	}
	if api := clientOf(t, file, "api"); api.ClientSecret != "a-confidential-secret" {
		t.Errorf("the other client's secret changed: %+v", api)
	}
	if err := clientUpdate([]string{"-file", file, "-client", "spa"}); err == nil {
		t.Error("update without any change flag must fail")
	}
}

// TestClientUpdateSecretFromStdin pins the reviewed "-secret -" semantics:
// one line of stdin, never the literal "-".
func TestClientUpdateSecretFromStdin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := clientAdd([]string{"-file", file, "-client", "api", "-type", "confidential",
		"-secret", "old-secret", "-redirect", "https://api.example.com/cb"}); err != nil {
		t.Fatalf("client add: %v", err)
	}
	withStdin(t, "new-secret\n")
	if err := clientUpdate([]string{"-file", file, "-client", "api", "-secret", "-"}); err != nil {
		t.Fatalf("client update: %v", err)
	}
	if got := clientOf(t, file, "api").ClientSecret; got != "new-secret" {
		t.Errorf("secret = %q, want the stdin value", got)
	}
}

// TestClientTypeSwitch pins the profile transitions: switching to public
// drops the (now rejected) secret; switching to confidential requires one.
func TestClientTypeSwitch(t *testing.T) {
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := clientAdd([]string{"-file", file, "-client", "api", "-type", "confidential",
		"-secret", "a-confidential-secret", "-redirect", "https://api.example.com/cb"}); err != nil {
		t.Fatalf("client add: %v", err)
	}
	if err := clientUpdate([]string{"-file", file, "-client", "api", "-type", "public"}); err != nil {
		t.Fatalf("switch to public: %v", err)
	}
	if c := clientOf(t, file, "api"); c.Confidential() || c.ClientSecret != "" {
		t.Errorf("public client must not keep a secret: %+v", c)
	}
	err := clientUpdate([]string{"-file", file, "-client", "api", "-type", "confidential"})
	if err == nil || !strings.Contains(err.Error(), "-secret") {
		t.Errorf("switch to confidential without a secret: err = %v, want a -secret hint", err)
	}
	if err := clientUpdate([]string{"-file", file, "-client", "api", "-type", "confidential", "-secret", "a-confidential-secret"}); err != nil {
		t.Fatalf("switch to confidential with a secret: %v", err)
	}
}

// TestClientRemoveLastClient pins the removal semantics: removing one of two
// clients preserves the other; removing the last one leaves an empty file
// (a warned-about transient state the IdP refuses to start with), and a
// client can be added back into it.
func TestClientRemoveLastClient(t *testing.T) {
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := clientAdd([]string{"-file", file, "-client", "a", "-type", "public", "-redirect", "https://a.example/cb"}); err != nil {
		t.Fatalf("client add a: %v", err)
	}
	if err := clientAdd([]string{"-file", file, "-client", "b", "-type", "public", "-redirect", "https://b.example/cb"}); err != nil {
		t.Fatalf("client add b: %v", err)
	}
	if err := clientRemove([]string{"-file", file, "-client", "a"}); err != nil {
		t.Fatalf("client remove a: %v", err)
	}
	ids := []string{}
	for _, c := range readClientsFile(t, file) {
		ids = append(ids, c.ClientID)
	}
	if len(ids) != 1 || ids[0] != "b" {
		t.Errorf("remaining clients = %v, want [b]", ids)
	}
	if err := clientRemove([]string{"-file", file, "-client", "b"}); err != nil {
		t.Fatalf("client remove b (the last one): %v", err)
	}
	if got := readClientsFile(t, file); len(got) != 0 {
		t.Errorf("clients after last removal = %v, want empty", got)
	}
	if err := clientAdd([]string{"-file", file, "-client", "c", "-type", "public", "-redirect", "https://c.example/cb"}); err != nil {
		t.Fatalf("client add into the emptied file: %v", err)
	}
}

func TestUserAddUpdateRemove(t *testing.T) {
	file := filepath.Join(t.TempDir(), "clients.json")
	if err := clientAdd([]string{"-file", file, "-client", "spa", "-type", "public", "-redirect", "https://spa.example.com/cb"}); err != nil {
		t.Fatalf("client add: %v", err)
	}
	if err := userAdd([]string{"-file", file, "-client", "spa", "-username", "alice",
		"-password", "wonderland", "-email", "alice@example.com", "-roles", " admin , auditor,"}); err != nil {
		t.Fatalf("user add: %v", err)
	}
	u := clientOf(t, file, "spa").Users[0]
	if u.Email != "alice@example.com" || len(u.Roles) != 2 || u.Roles[0] != "admin" || u.Roles[1] != "auditor" {
		t.Fatalf("unexpected user entry: %+v", u)
	}
	if !bcryptCompare(u.PasswordHash, "wonderland") {
		t.Error("stored hash must verify against the password")
	}

	// Duplicate usernames are rejected; unknown clients are rejected.
	if err := userAdd([]string{"-file", file, "-client", "spa", "-username", "alice", "-password", "x"}); err == nil {
		t.Error("duplicate user add must fail")
	}
	if err := userAdd([]string{"-file", file, "-client", "ghost", "-username", "x", "-password", "x"}); err == nil {
		t.Error("user add for an unknown client must fail")
	}

	// A metadata-only update keeps the hash.
	if err := userUpdate([]string{"-file", file, "-client", "spa", "-username", "alice", "-name", "Alice"}); err != nil {
		t.Fatalf("user update: %v", err)
	}
	if !bcryptCompare(clientOf(t, file, "spa").Users[0].PasswordHash, "wonderland") {
		t.Error("metadata-only update must keep the existing hash")
	}

	// "-password -" reads one line from stdin.
	withStdin(t, "new-secret\n")
	if err := userUpdate([]string{"-file", file, "-client", "spa", "-username", "alice", "-password", "-"}); err != nil {
		t.Fatalf("user update via stdin: %v", err)
	}
	if !bcryptCompare(clientOf(t, file, "spa").Users[0].PasswordHash, "new-secret") {
		t.Error("stored hash must verify against the stdin password")
	}

	// An explicit empty -password means "prompt"; on a non-interactive stdin
	// that must fail loudly instead of changing anything.
	withStdin(t, "sneaky\n")
	err := userUpdate([]string{"-file", file, "-client", "spa", "-username", "alice", "-password", ""})
	if err == nil || !strings.Contains(err.Error(), "no password") {
		t.Errorf("expected a 'no password' error for '-password '' on non-interactive stdin, got %v", err)
	}
	if !bcryptCompare(clientOf(t, file, "spa").Users[0].PasswordHash, "new-secret") {
		t.Error("a failed password resolution must keep the existing hash")
	}

	// "-roles ''" clears the roles; an absent -roles keeps them.
	if err := userUpdate([]string{"-file", file, "-client", "spa", "-username", "alice", "-roles", "auditor"}); err != nil {
		t.Fatalf("roles replace: %v", err)
	}
	if got := clientOf(t, file, "spa").Users[0].Roles; len(got) != 1 || got[0] != "auditor" {
		t.Errorf("roles after replace = %v, want [auditor]", got)
	}
	if err := userUpdate([]string{"-file", file, "-client", "spa", "-username", "alice", "-roles", ""}); err != nil {
		t.Fatalf("roles clear: %v", err)
	}
	if got := clientOf(t, file, "spa").Users[0].Roles; len(got) != 0 {
		t.Errorf("roles after clear = %v, want none", got)
	}

	// Removing a user leaves the other client untouched.
	if err := clientAdd([]string{"-file", file, "-client", "api", "-type", "confidential", "-secret", "a-confidential-secret", "-redirect", "https://api.example.com/cb"}); err != nil {
		t.Fatalf("client add api: %v", err)
	}
	if err := userAdd([]string{"-file", file, "-client", "api", "-username", "bob", "-password", "builder"}); err != nil {
		t.Fatalf("user add bob: %v", err)
	}
	if err := userRemove([]string{"-file", file, "-client", "spa", "-username", "alice"}); err != nil {
		t.Fatalf("user remove: %v", err)
	}
	if got := clientOf(t, file, "api").Users; len(got) != 1 || got[0].Username != "bob" {
		t.Errorf("api client users after spa mutation = %v", got)
	}
	if err := userRemove([]string{"-file", file, "-client", "api", "-username", "bob"}); err != nil {
		t.Fatalf("user remove bob: %v", err)
	}
	if got := clientOf(t, file, "api").Users; len(got) != 0 {
		t.Errorf("api users after last removal = %v, want none (transient state)", got)
	}
}

func TestParseList(t *testing.T) {
	cases := map[string][]string{
		"":                  nil,
		" ":                 nil,
		",":                 nil,
		"admin":             {"admin"},
		"admin,auditor":     {"admin", "auditor"},
		" admin , auditor ": {"admin", "auditor"},
		"admin,,auditor,":   {"admin", "auditor"},
	}
	for in, want := range cases {
		got := parseList(in)
		if len(got) != len(want) {
			t.Errorf("parseList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("parseList(%q) = %v, want %v", in, got, want)
			}
		}
	}
}

// TestLoadClientsMissingFile pins the tool's read helpers: a missing file is
// empty state for add, an error for mutations of existing entries.
func TestLoadClientsMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.json")
	clients, ok, err := loadClients(missing)
	if err != nil || ok || clients != nil {
		t.Errorf("loadClients on missing file = %v, %v, %v", clients, ok, err)
	}
	if _, err := loadExistingClients(missing); !errors.Is(err, os.ErrNotExist) && err == nil {
		t.Errorf("loadExistingClients on missing file: err = %v", err)
	}
}
