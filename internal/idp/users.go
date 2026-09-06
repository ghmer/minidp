package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is one account in the users file (IDP_USERS_FILE). Passwords are
// stored as bcrypt hashes — the per-user salt is part of the bcrypt format
// ($2a$10$<salt><hash>), so no separate salt field is needed.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Email        string `json:"email,omitempty"`
	Name         string `json:"name,omitempty"`
}

// UserStore is the account backend of the IdP. It is an interface so the
// JSON-file backend shipped here can later be swapped for a database or an
// external identity source without touching the IdP core.
type UserStore interface {
	// Lookup returns the account with the given username.
	Lookup(username string) (User, bool)
	// Count returns the number of accounts (for startup logging).
	Count() int
}

// validate checks one user entry when the file is loaded or saved.
func (u User) validate() error {
	if strings.TrimSpace(u.Username) == "" {
		return fmt.Errorf("username must not be empty")
	}
	if u.Username != strings.TrimSpace(u.Username) {
		return fmt.Errorf("username %q must not have leading or trailing whitespace", u.Username)
	}
	if !isBcryptHash(u.PasswordHash) {
		return fmt.Errorf("user %q: password_hash must be a 60-character bcrypt hash "+
			"like $2a$10$... (generate one with: minidp-users hash)", u.Username)
	}
	return nil
}

// isBcryptHash reports whether s looks like a modular bcrypt hash.
func isBcryptHash(s string) bool {
	return len(s) == 60 &&
		(strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$"))
}

// dummyHash equalises the bcrypt cost of failed lookups so an attacker cannot
// probe for valid usernames via response timing: comparing against a real hash
// takes ~100ms, a missing user would otherwise return instantly.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("minidp-timing-equalizer-dummy"), bcrypt.DefaultCost)

// fileUserStore is the file-backed UserStore: a JSON array of users read once
// at startup; changes take effect on restart.
type fileUserStore struct {
	byName map[string]User
}

// LoadUsers reads and validates a users file and returns it as the account
// backend. The path is scoped with os.Root so a crafted path cannot traverse
// outside its directory (gosec G304/G703).
func LoadUsers(path string) (UserStore, error) {
	users, err := ReadUsers(path)
	if err != nil {
		return nil, err
	}
	store := &fileUserStore{byName: make(map[string]User, len(users))}
	for _, u := range users {
		store.byName[u.Username] = u
	}
	slog.Info("users file loaded", "path", path, "users", len(users))
	return store, nil
}

// ReadUsers parses and fully validates a users file into a User slice.
func ReadUsers(path string) ([]User, error) {
	raw, err := readScopedFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}
	var users []User
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("users file %q is not a valid JSON array of users: %w", path, err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("users file %q contains no users", path)
	}
	seen := make(map[string]bool, len(users))
	for i, u := range users {
		if err := u.validate(); err != nil {
			return nil, fmt.Errorf("users file %q, entry %d: %w", path, i, err)
		}
		if seen[u.Username] {
			return nil, fmt.Errorf("users file %q: duplicate username %q", path, u.Username)
		}
		seen[u.Username] = true
	}
	return users, nil
}

// Lookup returns the user with the given username.
func (s *fileUserStore) Lookup(username string) (User, bool) {
	u, ok := s.byName[username]
	return u, ok
}

// Count returns the number of accounts.
func (s *fileUserStore) Count() int { return len(s.byName) }

// SaveUsers validates and writes the users file atomically (temp file + rename,
// mode 0600). Used by the minidp-users tool.
func SaveUsers(path string, users []User) error {
	seen := make(map[string]bool, len(users))
	for i, u := range users {
		if err := u.validate(); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if seen[u.Username] {
			return fmt.Errorf("duplicate username %q", u.Username)
		}
		seen[u.Username] = true
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	tmp, err := root.OpenFile(name+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = root.Remove(name + ".tmp")
		return fmt.Errorf("write users file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = root.Remove(name + ".tmp")
		return fmt.Errorf("close users file: %w", err)
	}
	if err := os.Rename(filepath.Join(dir, name+".tmp"), path); err != nil {
		_ = root.Remove(name + ".tmp")
		return fmt.Errorf("persist users file to %q: %w", path, err)
	}
	return nil
}

// readScopedFile reads path via an os.Root anchored at the file's directory.
func readScopedFile(path string) ([]byte, error) {
	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// HashPassword derives a salted bcrypt hash for a users-file entry. The salt
// is generated by bcrypt and embedded in the returned hash string. Shared with
// the minidp-users tool.
func HashPassword(password string, cost int) (string, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// verifyHash wraps bcrypt comparison for readability.
func verifyHash(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
