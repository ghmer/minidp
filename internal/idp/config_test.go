package idp

import (
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	// Isolate the test from the ambient environment.
	for _, key := range []string{
		"IDP_HOST", "IDP_PORT", "IDP_ISSUER", "IDP_USERNAME", "IDP_PASSWORD",
		"IDP_ACCESS_TOKEN_TTL", "IDP_REFRESH_TOKEN_TTL", "ALLOWED_REDIRECTS",
		"IDP_TITLE", "IDP_SUBTITLE", "IDP_RSA_PEM",
	} {
		t.Setenv(key, "")
	}

	cfg := LoadConfig()
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

	cfg := LoadConfig()
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

func TestLoadConfigInvalidTTLFallsBackToDefault(t *testing.T) {
	t.Setenv("IDP_ACCESS_TOKEN_TTL", "not-a-number")
	if cfg := LoadConfig(); cfg.AccessTokenTTL != time.Hour {
		t.Errorf("AccessTokenTTL = %v, want the 1h default", cfg.AccessTokenTTL)
	}
}
