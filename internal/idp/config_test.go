package idp

import (
	"testing"
	"time"
)

// setBaseEnv isolates a test from the ambient environment.
func setBaseEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"IDP_HOST", "IDP_PORT", "IDP_ISSUER",
		"IDP_ACCESS_TOKEN_TTL", "IDP_REFRESH_TOKEN_TTL",
		"IDP_TITLE", "IDP_SUBTITLE", "IDP_RSA_PEM", "IDP_KEY_DIR",
		"TRUSTED_PROXIES", "IDP_LOGIN_RATE_LIMIT", "IDP_CLIENTS_FILE",
		// Removed variables must be cleared: LoadConfig rejects them even
		// when the ambient shell has them set.
		"IDP_USERNAME", "IDP_PASSWORD", "IDP_PASSWORD_BCRYPT", "IDP_PASSWORD_FILE",
		"IDP_CLIENT_ID", "IDP_AUDIENCE", "IDP_CLIENT_SECRET", "ALLOWED_REDIRECTS",
		"IDP_ALLOWED_ORIGINS", "IDP_USERS_FILE", "MINIDP_MODE",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_CLIENTS_FILE", "/etc/minidp/clients.json")

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
	if cfg.AccessTokenTTL != time.Hour {
		t.Errorf("AccessTokenTTL = %v, want 1h", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 2*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 2h", cfg.RefreshTokenTTL)
	}
	if cfg.ClientsFile != "/etc/minidp/clients.json" {
		t.Errorf("ClientsFile = %q", cfg.ClientsFile)
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
	t.Setenv("IDP_CLIENTS_FILE", "/etc/minidp/clients.json")
	t.Setenv("IDP_ACCESS_TOKEN_TTL", "300")
	t.Setenv("IDP_REFRESH_TOKEN_TTL", "86400")
	t.Setenv("IDP_RSA_PEM", "/keys/idp.pem")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Issuer != "https://idp.example.com" {
		t.Errorf("Issuer = %q", cfg.Issuer)
	}
	if cfg.AccessTokenTTL != 300*time.Second {
		t.Errorf("AccessTokenTTL = %v, want 5m", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 24h", cfg.RefreshTokenTTL)
	}
	if cfg.RSAPeM != "/keys/idp.pem" {
		t.Errorf("RSAPeM = %q", cfg.RSAPeM)
	}
}

func TestLoadConfigInvalidNumericEnvFailsFast(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_CLIENTS_FILE", "/etc/minidp/clients.json")
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

// TestLoadConfigRejectsRemovedVariables pins the removal of the single-user
// and single-client variables: they must abort startup loudly instead of
// being ignored, so an operator cannot believe a silently ignored
// configuration still governs who can sign in or where codes are sent.
func TestLoadConfigRejectsRemovedVariables(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_CLIENTS_FILE", "/etc/minidp/clients.json")
	for _, key := range removedVariables {
		t.Setenv(key, "whatever")
		if _, err := LoadConfig(); err == nil {
			t.Errorf("%s set: expected a fail-fast error", key)
		}
		t.Setenv(key, "")
	}
}

// TestLoadConfigRequiresClientsFile pins that there is no built-in client
// registration: an unset IDP_CLIENTS_FILE must abort startup.
func TestLoadConfigRequiresClientsFile(t *testing.T) {
	setBaseEnv(t)
	if _, err := LoadConfig(); err == nil {
		t.Error("expected a fail-fast error without IDP_CLIENTS_FILE")
	}
}

func TestLoadConfigInvalidTrustedProxies(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("IDP_CLIENTS_FILE", "/etc/minidp/clients.json")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, not-a-cidr")
	if _, err := LoadConfig(); err == nil {
		t.Error("expected an error for an invalid TRUSTED_PROXIES CIDR")
	}
}
