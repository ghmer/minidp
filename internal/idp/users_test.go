package idp

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestLoadUsersAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	users := []User{
		{Username: "alice", PasswordHash: testHash(t, "wonderland"), Email: "alice@example.com", Name: "Alice", Roles: []string{"admin", "auditor"}},
		{Username: "bob", PasswordHash: testHash(t, "builder")},
	}
	if err := SaveUsers(path, users); err != nil {
		t.Fatalf("SaveUsers: %v", err)
	}

	store, err := LoadUsers(path)
	if err != nil {
		t.Fatalf("LoadUsers: %v", err)
	}
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

func TestLoadUsersErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"malformed json":      `[{`,
		"not an array":        `{"username": "alice"}`,
		"empty array":         `[]`,
		"empty username":      `[{"username": "  ", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234"}]`,
		"whitespace username": `[{"username": " alice ", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234"}]`,
		"plaintext password":  `[{"username": "alice", "password_hash": "demo-password"}]`,
		"truncated hash":      `[{"username": "alice", "password_hash": "$2a$10$short"}]`,
		"duplicate users": `[{"username": "alice", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234"},` +
			`{"username": "alice", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234"}]`,
		"empty role":        `[{"username": "alice", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234", "roles": ["admin", "  "]}]`,
		"whitespace role":   `[{"username": "alice", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234", "roles": [" admin"]}]`,
		"duplicate role":    `[{"username": "alice", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234", "roles": ["admin", "admin"]}]`,
		"role not a string": `[{"username": "alice", "password_hash": "$2a$10$0123456789012345678901234567890123456789012345678901234", "roles": [7]}]`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, name+"-users.json")
		writeFile(t, path, content)
		if _, err := LoadUsers(path); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}

	if _, err := LoadUsers(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected an error for a missing users file")
	}
}

func TestSaveUsersRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	users := []User{
		{Username: "alice", PasswordHash: testHash(t, "pw1")},
		{Username: "bob", PasswordHash: testHash(t, "pw2")},
	}
	if err := SaveUsers(path, users); err != nil {
		t.Fatalf("SaveUsers: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("users file mode = %o, want 600", perm)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp file was not cleaned up")
	}

	// The saved file is valid JSON with the expected entries.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var decoded []User
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("saved file is not valid JSON: %v", err)
	}
	if len(decoded) != 2 || decoded[0].Username != "alice" {
		t.Fatalf("unexpected contents: %s", raw)
	}
}

func TestSaveUsersRejectsInvalidEntries(t *testing.T) {
	dir := t.TempDir()
	if err := SaveUsers(filepath.Join(dir, "u.json"), []User{{Username: "", PasswordHash: testHash(t, "x")}}); err == nil {
		t.Error("expected an error for an empty username")
	}
	if err := SaveUsers(filepath.Join(dir, "u.json"), []User{{Username: "a", PasswordHash: "secret"}}); err == nil {
		t.Error("expected an error for a plaintext password")
	}
	dup := []User{
		{Username: "a", PasswordHash: testHash(t, "x")},
		{Username: "a", PasswordHash: testHash(t, "y")},
	}
	if err := SaveUsers(filepath.Join(dir, "u.json"), dup); err == nil {
		t.Error("expected an error for duplicate usernames")
	}
	if err := SaveUsers(filepath.Join(dir, "u.json"), []User{{Username: "a", PasswordHash: testHash(t, "x"), Roles: []string{"admin", " "}}}); err == nil {
		t.Error("expected an error for an empty role entry")
	}
	// Nothing may have been written by the failed attempts.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("failed saves must not leave files behind, found %d", len(entries))
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
