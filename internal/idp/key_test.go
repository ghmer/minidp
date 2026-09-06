package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestPKCES256RFC7636Vector checks the S256 challenge computation against the
// official test vector from RFC 7636, Appendix B.
func TestPKCES256RFC7636Vector(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := pkceS256(verifier); got != challenge {
		t.Fatalf("pkceS256 = %q, want %q", got, challenge)
	}
}

func TestNewSigningKeyGeneratesUsableKey(t *testing.T) {
	k, err := NewSigningKey("", "")
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if k.key == nil || k.key.N == nil {
		t.Fatal("expected a generated RSA key")
	}
	if k.kid == "" {
		t.Fatal("expected a non-empty kid")
	}

	// Sign a token and verify it with the corresponding public key.
	signed, err := k.sign(jwt.RegisteredClaims{Subject: "rego"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := jwt.Parse(signed, func(tok *jwt.Token) (any, error) {
		return &k.key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("signed token did not verify: %v", err)
	}
	if got := parsed.Header["kid"]; got != k.kid {
		t.Errorf("token header kid = %v, want %q", got, k.kid)
	}
}

// TestJWKSPublishedKeyVerifiesToken decodes the published JWKS, rebuilds the
// RSA public key from n/e and verifies a token signed by the private key. This
// is exactly what the rego-adventure backend does.
func TestJWKSPublishedKeyVerifiesToken(t *testing.T) {
	k, err := NewSigningKey("", "")
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}

	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(k.JWKS(), &set); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("expected exactly 1 key in JWKS, got %d", len(set.Keys))
	}
	key := set.Keys[0]
	if key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" {
		t.Fatalf("unexpected JWK fields: %+v", key)
	}
	if key.Kid != k.kid {
		t.Fatalf("JWK kid = %q, want %q", key.Kid, k.kid)
	}

	nBytes, err := base64RawURL(key.N)
	if err != nil {
		t.Fatalf("JWK n is not base64url: %v", err)
	}
	eBytes, err := base64RawURL(key.E)
	if err != nil {
		t.Fatalf("JWK e is not base64url: %v", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}

	signed, err := k.sign(jwt.RegisteredClaims{Subject: "rego"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("token did not verify against published JWKS key: %v", err)
	}
}

func TestLoadSigningKeyFromPEM(t *testing.T) {
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(generated)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	loaded, err := NewSigningKey(path, "")
	if err != nil {
		t.Fatalf("NewSigningKey(%q): %v", path, err)
	}
	if loaded.key.N.Cmp(generated.N) != 0 {
		t.Fatal("loaded key modulus differs from the PEM key")
	}

	// A token signed by the loaded key must verify with the original key.
	signed, err := loaded.sign(jwt.RegisteredClaims{Subject: "rego"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := jwt.Parse(signed, func(*jwt.Token) (any, error) { return &generated.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !parsed.Valid {
		t.Fatalf("token from loaded key did not verify: %v", err)
	}
}

func TestLoadSigningKeyErrors(t *testing.T) {
	if _, err := NewSigningKey(filepath.Join(t.TempDir(), "missing.pem"), ""); err == nil {
		t.Fatal("expected an error for a missing key file")
	}

	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem file"), 0o600); err != nil {
		t.Fatalf("write garbage pem: %v", err)
	}
	if _, err := NewSigningKey(garbage, ""); err == nil {
		t.Fatal("expected an error for a file without a PEM block")
	}
}

// base64RawURL decodes a standard base64url string without padding.
func base64RawURL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func TestPersistentSigningKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	first, err := NewSigningKey("", dir)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	path := filepath.Join(dir, keyFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not persisted: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	second, err := NewSigningKey("", dir)
	if err != nil {
		t.Fatalf("NewSigningKey (second run): %v", err)
	}
	if second.key.N.Cmp(first.key.N) != 0 {
		t.Error("second run did not load the persisted key")
	}
	// No temp file may be left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp key file was not cleaned up")
	}
}

func TestPersistentSigningKeyRequiresExistingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := NewSigningKey("", missing); err == nil {
		t.Error("expected an error for a missing key dir (fail fast instead of silently going ephemeral)")
	}
}

func TestPersistentSigningKeyRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("garbage"), 0o600); err != nil {
		t.Fatalf("write garbage key: %v", err)
	}
	if _, err := NewSigningKey("", dir); err == nil {
		t.Error("expected an error for a corrupt persisted key")
	}
}
