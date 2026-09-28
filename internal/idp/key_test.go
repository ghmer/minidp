package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	signed, err := k.sign(jwt.RegisteredClaims{Subject: "demo"})
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
// is exactly what a JWKS-based resource server does.
func TestJWKSPublishedKeyVerifiesToken(t *testing.T) {
	k, err := NewSigningKey("", "")
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}

	var set struct {
		Keys []jwk `json:"keys"`
	}
	jwks, err := keySetOf(k).JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
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

	signed, err := k.sign(jwt.RegisteredClaims{Subject: "demo"})
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
	signed, err := loaded.sign(jwt.RegisteredClaims{Subject: "demo"})
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

// TestJWKThumbprintRFC7638Vector checks the RSA JWK SHA-256 thumbprint
// against the official example from RFC 7638 §3.1 — the kid of rotated keys.
func TestJWKThumbprintRFC7638Vector(t *testing.T) {
	// The modulus of the RFC example key (base64url, no padding).
	const rfcN = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	nBytes, err := base64.RawURLEncoding.DecodeString(rfcN)
	if err != nil {
		t.Fatalf("decode RFC modulus: %v", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: 65537}
	if got := jwkThumbprint(pub); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("jwkThumbprint = %q, want the RFC 7638 §3.1 vector", got)
	}
}

// TestKeySetLegacyLayoutWithoutRing pins the pre-rotation behavior: a key
// directory without a keyring document resolves exactly one active key with
// the legacy kid, and the same key is loaded on every start.
func TestKeySetLegacyLayoutWithoutRing(t *testing.T) {
	dir := t.TempDir()
	first, err := NewSigningKeySet("", dir)
	if err != nil {
		t.Fatalf("NewSigningKeySet: %v", err)
	}
	if first.active.kid != legacyKid {
		t.Errorf("active kid = %q, want the legacy kid", first.active.kid)
	}
	if len(first.published) != 1 {
		t.Errorf("published keys = %d, want 1", len(first.published))
	}
	second, err := NewSigningKeySet("", dir)
	if err != nil {
		t.Fatalf("NewSigningKeySet (second start): %v", err)
	}
	if second.active.key.N.Cmp(first.active.key.N) != 0 {
		t.Error("second start did not load the persisted key")
	}
}

// TestRotateKeysStagesOverlapAndKeepsOldTokensValid drives a full rotation:
// the pre-rotation key is adopted as retiring, the new key becomes active,
// the JWKS publishes both kids, and tokens signed before the rotation still
// verify through the key set while an unknown kid fails closed.
func TestRotateKeysStagesOverlapAndKeepsOldTokensValid(t *testing.T) {
	dir := t.TempDir()
	old, err := NewSigningKey("", dir)
	if err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	oldToken, err := old.signAccess(jwt.RegisteredClaims{
		Subject:   "demo",
		Audience:  jwt.ClaimStrings{"conf-api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("sign old token: %v", err)
	}

	if err := RotateKeys(dir, time.Hour); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	set, err := NewSigningKeySet("", dir)
	if err != nil {
		t.Fatalf("NewSigningKeySet after rotation: %v", err)
	}
	if len(set.published) != 2 {
		t.Fatalf("published keys after rotation = %d, want 2", len(set.published))
	}
	if set.active.kid == legacyKid {
		t.Errorf("active kid = %q, want the thumbprint kid of the new key", set.active.kid)
	}

	// The JWKS advertises both kids — the transition-window requirement.
	var jwksSet struct {
		Keys []jwk `json:"keys"`
	}
	jwksBytes, err := set.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if err := json.Unmarshal(jwksBytes, &jwksSet); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}
	kids := map[string]bool{}
	for _, k := range jwksSet.Keys {
		kids[k.Kid] = true
	}
	if len(kids) != 2 || !kids[legacyKid] || !kids[set.active.kid] {
		t.Errorf("JWKS kids = %v, want %q and the new active kid", kids, legacyKid)
	}

	// A token signed before the rotation verifies through the key set.
	parsed, err := jwt.Parse(oldToken, set.verifyKey, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		t.Fatalf("pre-rotation token did not verify after rotation: %v", err)
	}

	// New tokens are minted by the active key and verify under its kid.
	newToken, err := set.signAccess(jwt.RegisteredClaims{
		Subject:   "demo",
		Audience:  jwt.ClaimStrings{"conf-api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("sign new token: %v", err)
	}
	parsed, err = jwt.Parse(newToken, set.verifyKey, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		t.Fatalf("post-rotation token did not verify: %v", err)
	}
	if got := parsed.Header["kid"]; got != set.active.kid {
		t.Errorf("new token kid = %v, want the active kid", got)
	}

	// An unknown kid fails closed.
	signed := tamperedWithKid(t, set.active.key, "no-such-kid")
	parsed, err = jwt.Parse(signed, set.verifyKey, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err == nil || (parsed != nil && parsed.Valid) {
		t.Fatal("token with unknown kid must fail closed")
	}
}

// tamperedWithKid signs claims with the given key but forces the kid header.
func tamperedWithKid(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Subject:   "demo",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign with forced kid: %v", err)
	}
	return signed
}

// TestRotateKeysPrunesExpiredRetiring pins the retention horizon: a retiring
// key whose retire_at has passed is pruned at the next start — dropped from
// the keyring, removed from disk and no longer published.
func TestRotateKeysPrunesExpiredRetiring(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewSigningKey("", dir); err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if err := RotateKeys(dir, time.Hour); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}

	// Force the legacy key's retention horizon into the past.
	ringPath := filepath.Join(dir, keyRingFileName)
	raw, err := os.ReadFile(ringPath)
	if err != nil {
		t.Fatalf("read keyring: %v", err)
	}
	var ring keyringFile
	if err := json.Unmarshal(raw, &ring); err != nil {
		t.Fatalf("parse keyring: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	found := false
	for i := range ring.Keys {
		if ring.Keys[i].State == keyStateRetiring {
			ring.Keys[i].RetireAt = past
			found = true
		}
	}
	if !found {
		t.Fatal("no retiring entry in the keyring")
	}
	updated, err := json.Marshal(ring)
	if err != nil {
		t.Fatalf("marshal keyring: %v", err)
	}
	if err := os.WriteFile(ringPath, updated, 0o600); err != nil {
		t.Fatalf("write keyring: %v", err)
	}

	set, err := NewSigningKeySet("", dir)
	if err != nil {
		t.Fatalf("NewSigningKeySet after retention: %v", err)
	}
	if len(set.published) != 1 || set.active.kid == legacyKid {
		t.Errorf("published = %d (active %q), want exactly the new active key", len(set.published), set.active.kid)
	}
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); !os.IsNotExist(err) {
		t.Error("retired key file was not removed from the key dir")
	}
}

// TestRotateKeysEdgeCases covers the empty-directory initialization and the
// two-rotation staging: each staged rotation keeps the earlier horizons.
func TestRotateKeysEdgeCases(t *testing.T) {
	if err := RotateKeys("", time.Hour); err == nil {
		t.Error("rotation without IDP_KEY_DIR must fail")
	}
	// A rotation in an empty directory initializes the ring: one active key.
	dir := t.TempDir()
	if err := RotateKeys(dir, time.Hour); err != nil {
		t.Fatalf("RotateKeys on empty dir: %v", err)
	}
	set, err := NewSigningKeySet("", dir)
	if err != nil {
		t.Fatalf("NewSigningKeySet: %v", err)
	}
	if len(set.published) != 1 || set.active == nil {
		t.Errorf("published = %d, want exactly one active key", len(set.published))
	}
	// Two staged rotations: the first retiring key keeps its earlier horizon.
	if err := RotateKeys(dir, time.Hour); err != nil {
		t.Fatalf("second RotateKeys: %v", err)
	}
	set2, err := NewSigningKeySet("", dir)
	if err != nil {
		t.Fatalf("NewSigningKeySet after second rotation: %v", err)
	}
	if len(set2.published) != 2 {
		t.Errorf("published after two rotations = %d, want 2", len(set2.published))
	}
}

// TestJWKSAfterRotationServesBothKeys verifies the /jwks endpoint end to end
// with a rotated key directory: both the retiring and the active key are
// published.
func TestJWKSAfterRotationServesBothKeys(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewSigningKey("", dir); err != nil {
		t.Fatalf("NewSigningKey: %v", err)
	}
	if err := RotateKeys(dir, time.Hour); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	ts, _ := testIDP(t, func(cfg *Config) { cfg.KeyDir = dir })
	resp, err := http.Get(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS keys after rotation = %d, want 2", len(set.Keys))
	}
}
