package idp

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// User is one account in the users file (IDP_USERS_FILE). Passwords are
// stored as bcrypt hashes — the per-user salt is part of the bcrypt format
// ($2a$10$<salt><hash>), so no separate salt field is needed. Roles, when
// set, are released as the roles claim on every token of the user.
type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// UserStore is the account backend of the IdP. It is an interface so the
// JSON-file backend shipped here can later be swapped for a database or an
// external identity source without touching the IdP core.
type UserStore interface {
	// Lookup returns the account with the given username.
	Lookup(username string) (User, bool)
	// Count returns the number of accounts (for startup logging).
	Count() int
	// DummyHash is a verifiable bcrypt hash burned on unknown-user lookups
	// so response timing does not reveal which usernames exist. Its cost
	// should match the cost of the stored user hashes.
	DummyHash() string
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
	seenRoles := make(map[string]bool, len(u.Roles))
	for _, role := range u.Roles {
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("user %q: roles must not contain empty entries", u.Username)
		}
		if role != strings.TrimSpace(role) {
			return fmt.Errorf("user %q: role %q must not have leading or trailing whitespace", u.Username, role)
		}
		if seenRoles[role] {
			return fmt.Errorf("user %q: duplicate role %q", u.Username, role)
		}
		seenRoles[role] = true
	}
	return nil
}

// isBcryptHash reports whether s looks like a modular bcrypt hash.
func isBcryptHash(s string) bool {
	return len(s) == 60 &&
		(strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$"))
}

// newDummyHash creates the hash burned on failed lookups so an attacker
// cannot probe for valid usernames via response timing: comparing against a
// real hash takes as long as the configured bcrypt cost, a missing user would
// otherwise return instantly.
func newDummyHash(cost int) string {
	h, err := bcrypt.GenerateFromPassword([]byte("minidp-timing-equalizer-dummy"), cost)
	if err != nil {
		// Cannot happen for a fixed plaintext and valid cost; fail loudly.
		panic(fmt.Sprintf("generate timing-equalisation dummy hash: %v", err))
	}
	return string(h)
}

// bcryptCostOf extracts the cost factor from a modular bcrypt hash
// ("$2a$10$..."). It falls back to bcrypt.DefaultCost for malformed input.
func bcryptCostOf(hash string) int {
	if len(hash) < 7 || hash[0] != '$' {
		return bcrypt.DefaultCost
	}
	cost, err := strconv.Atoi(hash[4:6])
	if err != nil || cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return bcrypt.DefaultCost
	}
	return cost
}

// fileUserStore is the file-backed UserStore: a JSON array of users read once
// at startup; changes take effect on restart.
type fileUserStore struct {
	byName    map[string]User
	dummyHash string
}

// LoadUsers reads and validates a users file and returns it as the account
// backend. The path is scoped with os.Root so a crafted path cannot traverse
// outside its directory (gosec G304/G703).
func LoadUsers(path string) (UserStore, error) {
	users, err := ReadUsers(path)
	if err != nil {
		return nil, err
	}
	// Burn the same bcrypt work for unknown users as for real ones: derive
	// the dummy hash cost from the users' own hash cost instead of assuming
	// bcrypt.DefaultCost.
	cost := bcrypt.DefaultCost
	if len(users) > 0 {
		cost = bcryptCostOf(users[0].PasswordHash)
	}
	store := &fileUserStore{
		byName:    make(map[string]User, len(users)),
		dummyHash: newDummyHash(cost),
	}
	for _, u := range users {
		store.byName[u.Username] = u
	}
	slog.Info("users file loaded", "path", path, "users", len(users), "bcryptCost", cost)
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

// DummyHash returns the timing-equalisation hash (cost derived at load time).
func (s *fileUserStore) DummyHash() string { return s.dummyHash }

// SaveUsers validates and writes the users file atomically (temp file + rename,
// mode 0600). Used by the minidp-users tool.
func SaveUsers(path string, users []User) error {
	if err := validateUsers(users); err != nil {
		return err
	}
	data, err := marshalUsers(users)
	if err != nil {
		return err
	}
	return saveUsersFile(path, data)
}

// validateUsers rejects duplicate usernames and entries that fail the
// users-file validation.
func validateUsers(users []User) error {
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
	return nil
}

// marshalUsers renders the users file: indented JSON with a trailing newline.
func marshalUsers(users []User) ([]byte, error) {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// saveUsersFile atomically writes data to path: a uniquely named temp file in
// the same directory (instead of a fixed <name>.tmp, so concurrent tool
// invocations cannot clobber each other's temp file), created exclusively
// (O_EXCL) with mode 0600, then renamed over the final path — so a crash
// mid-write can never corrupt the existing file.
func saveUsersFile(path string, data []byte) error {
	dir, name := filepath.Split(filepath.Clean(path))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	suffix, err := randomToken()
	if err != nil {
		return fmt.Errorf("generate temp file name: %w", err)
	}
	tmpName := name + ".tmp-" + suffix
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = root.Remove(tmpName)
		return fmt.Errorf("write users file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = root.Remove(tmpName)
		return fmt.Errorf("close users file: %w", err)
	}
	if err := os.Rename(filepath.Join(dir, tmpName), path); err != nil {
		_ = root.Remove(tmpName)
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
