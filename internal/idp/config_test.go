package idp

import (
	"path/filepath"
	"testing"
	"time"
)

// setBaseEnv isolates a test from the ambient environment and satisfies the
// mandatory settings (users file, redirect policy) with valid values.
func setBaseEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"IDP_HOST", "IDP_PORT", "IDP_ISSUER", "IDP_CLIENT_ID", "IDP_AUDIENCE",
		"IDP_ACCESS_TOKEN_TTL", "IDP_REFRESH_TOKEN_TTL", "ALLOWED_REDIRECTS",
		"IDP_TITLE", "IDP_SUBTITLE", "IDP_RSA_PEM", "IDP_KEY_DIR",
		"TRUSTED_PROXIES", "IDP_LOGIN_RATE_LIMIT", "IDP_USERS_FILE",
		"MINIDP_MODE", "IDP_CLIENT_SECRET",
		// Removed single-user variables must be cleared: LoadConfig rejects
		// them even when the ambient shell has them set.
		"IDP_USERNAME", "IDP_PASSWORD", "IDP_PASSWORD_BCRYPT", "IDP_PASSWORD_FILE",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("ALLOWED_REDIRECTS", "https://app.example.com/callback")
}

func writeUsersFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	if err := SaveUsers(path, []User{
		{Username: "demo", PasswordHash: testHash(t, "demo-password"), Email: "demo@example.com", Name: "Demo User"},
	}); err != nil {
		t.Fatalf("SaveUsers: %v", err)
	}
	return path
}

func TestLoadConfigDefaults(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")

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
	if cfg.ClientID != "demo-app" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "demo-app")
	}
	// The audience defaults to the registered client id.
	if cfg.Audience != "demo-app" {
		t.Errorf("Audience = %q, want the client id", cfg.Audience)
	}
	if cfg.AccessTokenTTL != time.Hour {
		t.Errorf("AccessTokenTTL = %v, want 1h", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 2*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 2h", cfg.RefreshTokenTTL)
	}
	if len(cfg.AllowedRedirects) != 1 || cfg.AllowedRedirects[0] != "https://app.example.com/callback" {
		t.Errorf("AllowedRedirects = %v", cfg.AllowedRedirects)
	}
	// The client profile defaults to public with no client secret.
	if cfg.Mode != ModePublic {
		t.Errorf("Mode = %q, want %q", cfg.Mode, ModePublic)
	}
	if cfg.Confidential() {
		t.Error("Confidential() = true, want false for the default public mode")
	}
	if cfg.UsersFile != "/etc/minidp/users.json" {
		t.Errorf("UsersFile = %q", cfg.UsersFile)
	}
	if cfg.LoginRateLimit != 20 {
		t.Errorf("LoginRateLimit = %d, want 20", cfg.LoginRateLimit)
	}
	if cfg.TrustedProxies != nil {
		t.Errorf("TrustedProxies = %v, want nil", cfg.TrustedProxies)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_HOST", "127.0.0.1")
	t.Setenv("IDP_PORT", "9999")
	t.Setenv("IDP_ISSUER", "https://idp.example.com")
	t.Setenv("IDP_CLIENT_ID", "my-spa")
	t.Setenv("IDP_AUDIENCE", "my-api")
	t.Setenv("IDP_ACCESS_TOKEN_TTL", "300")
	t.Setenv("IDP_REFRESH_TOKEN_TTL", "86400")
	t.Setenv("ALLOWED_REDIRECTS", "https://a.example.com/cb, https://b.example.com/cb ,")
	t.Setenv("IDP_RSA_PEM", "/keys/idp.pem")
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Issuer != "https://idp.example.com" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if cfg.ClientID != "my-spa" {
		t.Errorf("ClientID = %q", cfg.ClientID)
	}
	if cfg.Audience != "my-api" {
		t.Errorf("Audience = %q, want the IDP_AUDIENCE override", cfg.Audience)
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
	setBaseEnv(t)
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
		}
		t.Setenv(tc.key, "")
	}
}

// TestLoadConfigRejectsRemovedSingleUserVars pins the removal of single-user
// mode: the old variables must abort startup loudly instead of being ignored,
// so an operator cannot believe a silently ignored credential still governs
// sign-in.
func TestLoadConfigRejectsRemovedSingleUserVars(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")
	for _, key := range []string{"IDP_USERNAME", "IDP_PASSWORD", "IDP_PASSWORD_BCRYPT", "IDP_PASSWORD_FILE"} {
		t.Setenv(key, "whatever")
		if _, err := LoadConfig(); err == nil {
			t.Errorf("%s set: expected a fail-fast error", key)
		}
		t.Setenv(key, "")
	}
}

// TestLoadConfigRequiresUsersFile pins that there is no built-in account: an
// unset IDP_USERS_FILE must abort startup.
func TestLoadConfigRequiresUsersFile(t *testing.T) {
	setBaseEnv(t)
	if _, err := LoadConfig(); err == nil {
		t.Error("expected a fail-fast error without IDP_USERS_FILE")
	}
}

// TestLoadConfigRequiresRedirectPolicy pins the fail-closed default (review
// finding H2): an empty ALLOWED_REDIRECTS must abort startup instead of
// sending authorization codes to arbitrary hosts.
func TestLoadConfigRequiresRedirectPolicy(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("ALLOWED_REDIRECTS", "")
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")
	if _, err := LoadConfig(); err == nil {
		t.Error("expected a fail-fast error with an empty ALLOWED_REDIRECTS")
	}
}

func TestLoadConfigInvalidTrustedProxies(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, not-a-cidr")
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error for an invalid TRUSTED_PROXIES CIDR")
	}
}

// TestLoadConfigValidatesAllowedRedirects pins the fail-fast validation of
// ALLOWED_REDIRECTS: allowlist mode compares strings, so a non-http(s) or
// malformed entry must abort startup instead of being honoured silently.
func TestLoadConfigValidatesAllowedRedirects(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")
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

// TestLoadConfigModeValidation pins the MINIDP_MODE contract: the mode and the
// client secret are two halves of one client registration, so every
// inconsistent combination must abort startup instead of silently weakening a
// security boundary.
func TestLoadConfigModeValidation(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_USERS_FILE", "/etc/minidp/users.json")

	// Confidential mode without a secret: every caller would pass client
	// authentication, so this must fail fast.
	t.Setenv("MINIDP_MODE", "confidential")
	if _, err := LoadConfig(); err == nil {
		t.Error("MINIDP_MODE=confidential without IDP_CLIENT_SECRET: expected a fail-fast error")
	}

	// Public mode with a secret: the secret would be dead configuration an
	// operator could mistake for a working control.
	t.Setenv("MINIDP_MODE", "public")
	t.Setenv("IDP_CLIENT_SECRET", "a-secret-of-sufficient-length")
	if _, err := LoadConfig(); err == nil {
		t.Error("MINIDP_MODE=public with IDP_CLIENT_SECRET: expected a fail-fast error")
	}

	// Anything other than the two documented values is rejected.
	t.Setenv("IDP_CLIENT_SECRET", "")
	for _, bad := range []string{"Confidential", "hybrid", "public "} {
		t.Setenv("MINIDP_MODE", bad)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("MINIDP_MODE=%q: expected a fail-fast error", bad)
		}
	}

	// A valid confidential configuration passes and flips the profile.
	t.Setenv("MINIDP_MODE", "confidential")
	t.Setenv("IDP_CLIENT_SECRET", "a-secret-of-sufficient-length")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("MINIDP_MODE=confidential with secret rejected: %v", err)
	}
	if cfg.Mode != ModeConfidential || !cfg.Confidential() {
		t.Errorf("Mode = %q, Confidential() = %v, want confidential/true", cfg.Mode, cfg.Confidential())
	}
}
