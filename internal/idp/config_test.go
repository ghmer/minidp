package idp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestLoadConfigDefaults(t *testing.T) {
	// Isolate the test from the ambient environment.
	for _, key := range []string{
		"IDP_HOST", "IDP_PORT", "IDP_ISSUER", "IDP_USERNAME", "IDP_PASSWORD",
		"IDP_ACCESS_TOKEN_TTL", "IDP_REFRESH_TOKEN_TTL", "ALLOWED_REDIRECTS",
		"IDP_TITLE", "IDP_SUBTITLE", "IDP_RSA_PEM", "IDP_KEY_DIR",
		"IDP_PASSWORD_BCRYPT", "IDP_PASSWORD_FILE", "TRUSTED_PROXIES",
		"IDP_LOGIN_RATE_LIMIT", "IDP_USERS_FILE",
	} {
		t.Setenv(key, "")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want %q", cfg.Host, "0.0.0.0")
	}
	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Errorf("Issuer = %q, want %q", cfg.Issuer, "http://localhost:8080")
	}
	if cfg.Username != "rego" {
		t.Errorf("Username = %q, want %q", cfg.Username, "rego")
	}
	if cfg.Password != "adventure" {
		t.Errorf("Password = %q, want %q", cfg.Password, "adventure")
	}
	if cfg.AccessTokenTTL != time.Hour {
		t.Errorf("AccessTokenTTL = %v, want 1h", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 2*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 2h", cfg.RefreshTokenTTL)
	}
	if len(cfg.AllowedRedirects) != 0 {
		t.Errorf("AllowedRedirects = %v, want empty (any http(s) allowed)", cfg.AllowedRedirects)
	}
	if cfg.RSAPeM != "" {
		t.Errorf("RSAPeM = %q, want empty", cfg.RSAPeM)
	}
	if cfg.KeyDir != "" {
		t.Errorf("KeyDir = %q, want empty (ephemeral key)", cfg.KeyDir)
	}
	if cfg.PasswordBcrypt != "" {
		t.Errorf("PasswordBcrypt = %q, want empty", cfg.PasswordBcrypt)
	}
	if cfg.LoginRateLimit != 20 {
		t.Errorf("LoginRateLimit = %d, want 20", cfg.LoginRateLimit)
	}
	if cfg.TrustedProxies != nil {
		t.Errorf("TrustedProxies = %v, want nil", cfg.TrustedProxies)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("IDP_HOST", "127.0.0.1")
	t.Setenv("IDP_PORT", "9999")
	t.Setenv("IDP_ISSUER", "https://idp.example.com")
	t.Setenv("IDP_USERNAME", "alice")
	t.Setenv("IDP_PASSWORD", "wonderland")
	t.Setenv("IDP_ACCESS_TOKEN_TTL", "300")
	t.Setenv("IDP_REFRESH_TOKEN_TTL", "86400")
	t.Setenv("ALLOWED_REDIRECTS", "https://a.example.com/cb, https://b.example.com/cb ,")
	t.Setenv("IDP_RSA_PEM", "/keys/idp.pem")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Issuer != "https://idp.example.com" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if cfg.Username != "alice" || cfg.Password != "wonderland" {
		t.Errorf("credentials not picked up: %q/%q", cfg.Username, cfg.Password)
	}
	if cfg.AccessTokenTTL != 300*time.Second {
		t.Errorf("AccessTokenTTL = %v, want 5m", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 24h", cfg.RefreshTokenTTL)
	}
	want := []string{"https://a.example.com/cb", "https://b.example.com/cb"}
	if len(cfg.AllowedRedirects) != len(want) {
		t.Fatalf("AllowedRedirects = %v, want %v", cfg.AllowedRedirects, want)
	}
	for i, r := range want {
		if cfg.AllowedRedirects[i] != r {
			t.Errorf("AllowedRedirects[%d] = %q, want %q", i, cfg.AllowedRedirects[i], r)
		}
	}
	if cfg.RSAPeM != "/keys/idp.pem" {
		t.Errorf("RSAPeM = %q", cfg.RSAPeM)
	}
}

func TestLoadConfigInvalidNumericEnvFailsFast(t *testing.T) {
	for _, tc := range []struct{ key, val string }{
		{"IDP_ACCESS_TOKEN_TTL", "not-a-number"},
		{"IDP_ACCESS_TOKEN_TTL", "0"},
		{"IDP_ACCESS_TOKEN_TTL", "-5"},
		{"IDP_REFRESH_TOKEN_TTL", "abc"},
		{"IDP_LOGIN_RATE_LIMIT", "abc"},
		{"IDP_LOGIN_RATE_LIMIT", "0"},
	} {
		t.Setenv(tc.key, tc.val)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("%s=%q: expected a fail-fast error, got nil", tc.key, tc.val)
		} else {
			t.Logf("%s=%q rejected: %v", tc.key, tc.val, err)
		}
		t.Setenv(tc.key, "")
	}
}

func TestLoadConfigPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(" s3cret \n"), 0o600); err != nil {
		t.Fatalf("write password file: %v", err)
	}
	t.Setenv("IDP_PASSWORD", "")
	t.Setenv("IDP_PASSWORD_BCRYPT", "")
	t.Setenv("IDP_PASSWORD_FILE", path)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Password != "s3cret" {
		t.Errorf("Password = %q, want the trimmed file contents", cfg.Password)
	}
}

func TestLoadConfigPasswordFileErrors(t *testing.T) {
	t.Setenv("IDP_PASSWORD", "")
	t.Setenv("IDP_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error for a missing password file")
	}

	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}
	t.Setenv("IDP_PASSWORD_FILE", path)
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error for an empty password file")
	}
}

func TestLoadConfigPasswordBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("adventure"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	t.Setenv("IDP_PASSWORD", "")
	t.Setenv("IDP_PASSWORD_FILE", "")
	t.Setenv("IDP_PASSWORD_BCRYPT", string(hash))

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.PasswordBcrypt != string(hash) {
		t.Error("PasswordBcrypt not picked up")
	}
	if cfg.Password != "" {
		t.Errorf("Password = %q, want empty when a bcrypt hash is configured", cfg.Password)
	}
}

func TestLoadConfigConflictingPasswordSources(t *testing.T) {
	t.Setenv("IDP_PASSWORD", "plain")
	t.Setenv("IDP_PASSWORD_BCRYPT", "$2a$10$abc")
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error when IDP_PASSWORD and IDP_PASSWORD_BCRYPT are both set")
	}
	t.Setenv("IDP_PASSWORD_BCRYPT", "")
	path := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	t.Setenv("IDP_PASSWORD_FILE", path)
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error when IDP_PASSWORD and IDP_PASSWORD_FILE are both set")
	}
}

func TestLoadConfigInvalidTrustedProxies(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, not-a-cidr")
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error for an invalid TRUSTED_PROXIES CIDR")
	}
}

// TestLoadConfigValidatesAllowedRedirects pins the fail-fast validation of
// ALLOWED_REDIRECTS: allowlist mode compares strings, so a non-http(s) or
// malformed entry must abort startup instead of being honoured silently.
func TestLoadConfigValidatesAllowedRedirects(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)",
		"http://",           // no host
		"https://x/cb#frag", // fragment cannot survive a redirect round-trip
		"/relative/path",    // not absolute
		"not a url at all",  // contains spaces
	} {
		t.Setenv("ALLOWED_REDIRECTS", bad)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("ALLOWED_REDIRECTS=%q: expected a fail-fast error", bad)
		}
	}
	t.Setenv("ALLOWED_REDIRECTS", "https://good.example.com/cb, http://other.example.com:8080/cb")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("valid allowlist rejected: %v", err)
	}
	if len(cfg.AllowedRedirects) != 2 {
		t.Errorf("AllowedRedirects = %v, want 2 entries", cfg.AllowedRedirects)
	}
}

func TestLoadConfigUsersFileMode(t *testing.T) {
	t.Setenv("IDP_USERNAME", "")
	t.Setenv("IDP_PASSWORD", "")
	t.Setenv("IDP_PASSWORD_BCRYPT", "")
	t.Setenv("IDP_PASSWORD_FILE", "")
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.UsersFile != "/etc/minidp/users.json" {
		t.Errorf("UsersFile = %q", cfg.UsersFile)
	}
	if cfg.Username != "" {
		t.Errorf("Username = %q, want empty in multi-user mode", cfg.Username)
	}
}

func TestLoadConfigUsersFileConflicts(t *testing.T) {
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")
	t.Setenv("IDP_PASSWORD_BCRYPT", "")
	t.Setenv("IDP_PASSWORD_FILE", "")
	t.Setenv("IDP_PASSWORD", "")

	for key, val := range map[string]string{
		"IDP_USERNAME":        "rego",
		"IDP_PASSWORD":        "adventure",
		"IDP_PASSWORD_BCRYPT": "$2a$10$0123456789012345678901234567890123456789012345678901234",
		"IDP_PASSWORD_FILE":   "/tmp/pw",
	} {
		t.Setenv(key, val)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("%s together with IDP_USERS_FILE must be rejected", key)
		}
		t.Setenv(key, "")
	}
}
