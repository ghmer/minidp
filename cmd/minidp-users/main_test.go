package main

// Regression tests for the FINDINGS review: `update -password -` must read
// the password from stdin (like add/hash), not hash the literal string "-",
// and a missing -password flag must keep the existing hash.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

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

func hashMatches(t *testing.T, file, username, password string) bool {
	t.Helper()
	users, _, err := readUsersForUpdate(file)
	if err != nil {
		t.Fatalf("read users: %v", err)
	}
	idx := findUserIndex(users, username)
	if idx < 0 {
		t.Fatalf("user %q not found", username)
	}
	return bcrypt.CompareHashAndPassword([]byte(users[idx].PasswordHash), []byte(password)) == nil
}

func TestUpdatePasswordFromStdin(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	if err := add([]string{"-file", file, "-username", "alice", "-password", "old-secret"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// "-password -" must read one line from stdin.
	withStdin(t, "new-secret\n")
	if err := update([]string{"-file", file, "-username", "alice", "-password", "-"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !hashMatches(t, file, "alice", "new-secret") {
		t.Error("stored hash must verify against the stdin password")
	}
	if hashMatches(t, file, "alice", "-") {
		t.Error("stored hash must NOT be the literal '-' (the reviewed bug)")
	}
	if hashMatches(t, file, "alice", "old-secret") {
		t.Error("old password must no longer verify")
	}
}

func TestUpdateWithoutPasswordKeepsHash(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	if err := add([]string{"-file", file, "-username", "alice", "-password", "keep-me", "-email", "old@example.com"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := update([]string{"-file", file, "-username", "alice", "-email", "new@example.com"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !hashMatches(t, file, "alice", "keep-me") {
		t.Error("metadata-only update must keep the existing hash")
	}
	users, _, err := readUsersForUpdate(file)
	if err != nil {
		t.Fatalf("read users: %v", err)
	}
	if users[0].Email != "new@example.com" {
		t.Errorf("email = %q, want new@example.com", users[0].Email)
	}
}

func TestUpdateEmptyPasswordFlagNonInteractiveFails(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	if err := add([]string{"-file", file, "-username", "alice", "-password", "keep-me"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// An explicit empty -password means "prompt"; on a non-interactive stdin
	// (piped) that must fail loudly instead of setting anything.
	withStdin(t, "sneaky\n")
	err := update([]string{"-file", file, "-username", "alice", "-password", ""})
	if err == nil || !strings.Contains(err.Error(), "no password") {
		t.Errorf("expected a 'no password' error for '-password '' on non-interactive stdin, got %v", err)
	}
	if !hashMatches(t, file, "alice", "keep-me") {
		t.Error("a failed password resolution must keep the existing hash")
	}
}

func rolesOf(t *testing.T, file, username string) []string {
	t.Helper()
	users, _, err := readUsersForUpdate(file)
	if err != nil {
		t.Fatalf("read users: %v", err)
	}
	idx := findUserIndex(users, username)
	if idx < 0 {
		t.Fatalf("user %q not found", username)
	}
	return users[idx].Roles
}

func TestAddAndUpdateRoles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "users.json")
	if err := add([]string{"-file", file, "-username", "alice", "-password", "secret", "-roles", " admin , auditor,"}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if got := rolesOf(t, file, "alice"); len(got) != 2 || got[0] != "admin" || got[1] != "auditor" {
		t.Errorf("roles after add = %v, want [admin auditor] (trimmed, empties dropped)", got)
	}

	// An update without -roles keeps the existing set.
	if err := update([]string{"-file", file, "-username", "alice", "-email", "a@example.com"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := rolesOf(t, file, "alice"); len(got) != 2 {
		t.Errorf("roles after unrelated update = %v, want [admin auditor]", got)
	}

	// A provided -roles replaces the set; "-roles ''" clears it.
	if err := update([]string{"-file", file, "-username", "alice", "-roles", "admin"}); err != nil {
		t.Fatalf("update roles: %v", err)
	}
	if got := rolesOf(t, file, "alice"); len(got) != 1 || got[0] != "admin" {
		t.Errorf("roles after replace = %v, want [admin]", got)
	}
	if err := update([]string{"-file", file, "-username", "alice", "-roles", ""}); err != nil {
		t.Fatalf("clear roles: %v", err)
	}
	if got := rolesOf(t, file, "alice"); len(got) != 0 {
		t.Errorf("roles after clear = %v, want none", got)
	}
}

func TestParseRoles(t *testing.T) {
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
		got := parseRoles(in)
		if len(got) != len(want) {
			t.Errorf("parseRoles(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("parseRoles(%q) = %v, want %v", in, got, want)
			}
		}
	}
}
