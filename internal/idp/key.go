package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// keyFileName is the file name used for the persisted signing key inside
// IDP_KEY_DIR (the pre-rotation layout). Rotated keys are stored next to it
// as minidp-rsa-<kid>.pem, and the keyring document lists every published
// key. A directory holding only the legacy key keeps the pre-rotation
// behavior exactly: one active key with the fixed kid below.
const (
	keyFileName     = "minidp-rsa.pem"
	keyRingFileName = "keyring.json"
	legacyKid       = "minidp-1"
)

// Lifecycle states of a keyring entry. An active key mints new tokens;
// a retiring key is still published (so tokens signed before the rotation
// stay verifiable) until its retention horizon has passed and it is pruned
// at the next start.
const (
	keyStateActive   = "active"
	keyStateRetiring = "retiring"
)

// keyringEntry is one entry of the persisted keyring: a PEM file inside the
// key directory, its published kid and its lifecycle state.
type keyringEntry struct {
	CreatedAt time.Time `json:"created_at"`
	RetireAt  time.Time `json:"retire_at"`
	KID       string    `json:"kid"`
	File      string    `json:"file"`
	State     string    `json:"state"`
}

// keyringFile is the on-disk keyring document (keyring.json inside
// IDP_KEY_DIR). It is written only by key rotations; a key directory without
// one keeps the single-key behavior.
type keyringFile struct {
	Keys []keyringEntry `json:"keys"`
}

// signingKey wraps an RSA private key together with the stable key id (kid) that
// is written into the JWT header and published in the JWKS document so that the
// relying party can select the matching public key for RS256 verification.
type signingKey struct {
	key     *rsa.PrivateKey
	kid     string
	version string
}

// NewSigningKey resolves a single signing key in this order:
//
//  1. pemPath is set: load the key from that PEM file.
//  2. keyDir is set: load <keyDir>/minidp-rsa.pem; if it does not exist yet,
//     generate a fresh RSA-2048 key and persist it there (mode 0600, written
//     via a temp file + rename so an interrupted start cannot corrupt it).
//  3. Otherwise: generate an ephemeral key held in memory only (development
//     mode; all tokens become invalid on restart).
//
// NewSigningKeySet is the entry point for a running IdP: it additionally
// resolves the staged keyring (rotation) layout.
func NewSigningKey(pemPath, keyDir string) (*signingKey, error) {
	switch {
	case pemPath != "":
		return loadSigningKey(pemPath)
	case keyDir != "":
		return persistentSigningKey(keyDir)
	default:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate rsa key: %w", err)
		}
		return &signingKey{key: key, kid: legacyKid, version: "1.0"}, nil
	}
}

// NewSigningKeySet resolves the full signing material of an IdP in this
// order:
//
//  1. pemPath is set: a single key loaded from that PEM file.
//  2. keyDir holds a keyring.json: the staged rotation layout — expired
//     retiring keys are pruned, the single active key mints new tokens and
//     every published key verifies tokens minted before a rotation.
//  3. keyDir without a keyring: the pre-rotation layout — load
//     minidp-rsa.pem (generating it on first use), one active key.
//  4. Neither set: an ephemeral in-memory key (development mode).
func NewSigningKeySet(pemPath, keyDir string) (*keySet, error) {
	switch {
	case pemPath != "":
		k, err := NewSigningKey(pemPath, "")
		if err != nil {
			return nil, err
		}
		return keySetOf(k), nil
	case keyDir != "":
		return keySetFromDir(keyDir)
	default:
		k, err := NewSigningKey("", "")
		if err != nil {
			return nil, err
		}
		return keySetOf(k), nil
	}
}

// keySetFromDir loads the key material from keyDir: a staged keyring when
// keyring.json exists, the legacy single-key layout otherwise. Retiring
// entries whose retention horizon has passed are pruned here — the key file
// is removed and the entry dropped — so the JWKS only publishes keys that
// can still be referenced by unexpired tokens.
func keySetFromDir(keyDir string) (*keySet, error) {
	dir := filepath.Clean(keyDir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open key dir %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	ring, err := readKeyRing(root, keyRingFileName)
	if errors.Is(err, os.ErrNotExist) {
		// No keyring document: the legacy (pre-rotation) layout of exactly
		// one persisted key with the fixed kid.
		k, perr := persistentSigningKey(dir)
		if perr != nil {
			return nil, perr
		}
		return keySetOf(k), nil
	}
	if err != nil {
		return nil, err
	}

	now := time.Now()
	kept := make([]keyringEntry, 0, len(ring.Keys))
	byKid := make(map[string]bool, len(ring.Keys))
	for _, entry := range ring.Keys {
		switch {
		case entry.KID == "" || entry.File == "":
			return nil, fmt.Errorf("keyring %q: entry with empty kid or file", filepath.Join(dir, keyRingFileName))
		case entry.State != keyStateActive && entry.State != keyStateRetiring:
			return nil, fmt.Errorf("keyring %q: entry %q has invalid state %q", filepath.Join(dir, keyRingFileName), entry.KID, entry.State)
		case byKid[entry.KID]:
			return nil, fmt.Errorf("keyring %q: duplicate kid %q", filepath.Join(dir, keyRingFileName), entry.KID)
		}
		byKid[entry.KID] = true
		if entry.State == keyStateRetiring && !entry.RetireAt.IsZero() && entry.RetireAt.Before(now) {
			// Retention horizon passed: the key stops being published (its
			// tokens are expired by now) and the file is removed.
			if err := root.Remove(entry.File); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("remove retired signing key %q: %w", filepath.Join(dir, entry.File), err)
			}
			slog.Info("retired signing key pruned", "kid", entry.KID, "path", filepath.Join(dir, entry.File))
			continue
		}
		kept = append(kept, entry)
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("keyring %q contains no keys", filepath.Join(dir, keyRingFileName))
	}

	set := &keySet{published: make([]*signingKey, 0, len(kept))}
	for _, entry := range kept {
		k, err := loadSigningKey(filepath.Join(dir, entry.File))
		if err != nil {
			if entry.State == keyStateRetiring {
				// A lost retiring key cannot be published anymore; its
				// outstanding tokens are unverifiable either way. Keep the
				// IdP running without it instead of refusing to start.
				slog.Warn("retiring signing key unreadable, dropping it from the JWKS", "kid", entry.KID, "error", err)
				continue
			}
			return nil, fmt.Errorf("load active signing key %q: %w", filepath.Join(dir, entry.File), err)
		}
		if entry.KID != legacyKid && jwkThumbprint(&k.key.PublicKey) != entry.KID {
			// The keyring is the source of truth for kids; a PEM swapped
			// under a published kid would silently break verification. The
			// legacy kid is a fixed label (no thumbprint to check against).
			return nil, fmt.Errorf("keyring %q: entry %q does not match the key material's RFC 7638 thumbprint",
				keyRingPath(dir), entry.KID)
		}
		k.kid = entry.KID
		if entry.State == keyStateActive {
			if set.active != nil {
				return nil, fmt.Errorf("keyring %q: more than one active key", keyRingPath(dir))
			}
			set.active = k
		}
		set.published = append(set.published, k)
	}
	if set.active == nil {
		return nil, fmt.Errorf("keyring %q has no active key", keyRingPath(dir))
	}
	return set, nil
}

// keyRingPath returns the path of the keyring document inside dir.
func keyRingPath(dir string) string { return filepath.Join(dir, keyRingFileName) }

// readKeyRing reads and parses the keyring document inside the scoped root.
// A missing file is reported as os.ErrNotExist (the legacy-layout signal).
func readKeyRing(root *os.Root, name string) (*keyringFile, error) {
	f, err := root.Open(name)
	if err != nil {
		// %w keeps os.ErrNotExist intact: it is the legacy-layout signal.
		return nil, fmt.Errorf("open keyring: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	var ring keyringFile
	if err := json.Unmarshal(raw, &ring); err != nil {
		return nil, fmt.Errorf("parse keyring: %w", err)
	}
	return &ring, nil
}

// persistentSigningKey loads the key from keyDir, generating and persisting a
// new one on first use. Generation is safe against concurrent starts on a
// shared key directory: the temp file is created exclusively (O_EXCL), so
// exactly one instance wins and writes the final key while the losers wait
// for it to appear and load it.
func persistentSigningKey(keyDir string) (*signingKey, error) {
	dir := filepath.Clean(keyDir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open key dir %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	path := filepath.Join(dir, keyFileName)
	tmpName := keyFileName + ".tmp"
	for attempt := 0; ; attempt++ {
		if _, err := os.Stat(path); err == nil {
			return loadSigningKey(path)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("stat signing key %q: %w", path, err)
		}
		// Exclusive create: the winner generates the key, everyone else waits.
		tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			// Another instance is generating right now (or a crashed start
			// left the temp file behind): wait for the final key, or take
			// over a stale temp file once. Either way, retry the round.
			if werr := waitForPeerKey(root, dir, tmpName, path, attempt); werr != nil {
				return nil, werr
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("create temp signing key in %q: %w", dir, err)
		}
		key, err := generateAndPersistKey(root, dir, tmpName, path, tmp)
		if err != nil {
			return nil, err
		}
		return &signingKey{key: key, kid: legacyKid, version: "1.0"}, nil
	}
}

// waitForPeerKey handles the case where another instance holds the exclusive
// temp file: it waits for the final key to appear. When the wait times out on
// the first attempt the temp file is stale (the generating instance crashed
// mid-write): it is removed so the caller can retry generation.
func waitForPeerKey(root *os.Root, dir, tmpName, path string, attempt int) error {
	err := awaitFile(path, 10*time.Second)
	if err == nil {
		return nil
	}
	if attempt > 0 {
		return fmt.Errorf("gave up waiting for signing key %q: %w", path, err)
	}
	slog.Warn("stale signing-key temp file detected, taking over", "path", filepath.Join(dir, tmpName))
	removeTempFile(root, tmpName)
	return nil
}

// generateAndPersistKey generates a fresh RSA-2048 key and persists it to
// path via the exclusively created temp file tmp: write, close, rename, so a
// crash mid-write can never leave a truncated key behind. The temp file is
// created with 0600 directly (os.Root.Create would umask it to 0644).
func generateAndPersistKey(root *os.Root, dir, tmpName, path string, tmp *os.File) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		discardTempFile(root, tmp, tmpName)
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if _, err := tmp.Write(pemBytes); err != nil {
		discardTempFile(root, tmp, tmpName)
		return nil, fmt.Errorf("write signing key in %q: %w", dir, err)
	}
	if err := tmp.Close(); err != nil {
		removeTempFile(root, tmpName)
		return nil, fmt.Errorf("close signing key in %q: %w", dir, err)
	}
	if err := os.Rename(filepath.Join(dir, tmpName), path); err != nil {
		removeTempFile(root, tmpName)
		return nil, fmt.Errorf("persist signing key to %q: %w", path, err)
	}
	slog.Info("generated and persisted RSA signing key", "path", path)
	return key, nil
}

// discardTempFile closes and removes a temp file after a failed write.
func discardTempFile(root *os.Root, tmp *os.File, tmpName string) {
	_ = tmp.Close()
	removeTempFile(root, tmpName)
}

// awaitFile polls until path exists or the timeout elapses.
func awaitFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// jwkThumbprint computes the RFC 7638 JWK SHA-256 thumbprint of an RSA
// public key: the SHA-256 digest of the canonical JSON object built from the
// required members ("e", "kty", "n" — lexicographic order, no whitespace,
// base64url values), base64url-encoded. Used as the kid of rotated keys.
func jwkThumbprint(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	canonical := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RotateKeys stages a signing-key rotation inside the given key directory:
// the currently active key becomes retiring — published for verification
// until the retention horizon passes — and a fresh RSA-2048 key with an
// RFC 7638 thumbprint kid becomes active. The keyring document is persisted;
// the next minidp start picks up the new material. When the directory holds
// no keyring yet (the legacy layout), the existing minidp-rsa.pem is adopted
// as the retiring key and the ring document is created.
func RotateKeys(keyDir string, retention time.Duration) error {
	if strings.TrimSpace(keyDir) == "" {
		return fmt.Errorf("key rotation requires IDP_KEY_DIR")
	}
	dir := filepath.Clean(keyDir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open key dir %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	ring, err := readKeyRing(root, keyRingFileName)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		// Legacy layout: adopt the persisted key (or start empty) as the
		// active entry of a fresh ring.
		ring = &keyringFile{}
		if _, statErr := root.Stat(keyFileName); statErr == nil {
			ring.Keys = []keyringEntry{{
				KID:       legacyKid,
				File:      keyFileName,
				CreatedAt: time.Now(),
				State:     keyStateActive,
			}}
		}
	default:
		return fmt.Errorf("read keyring: %w", err)
	}

	now := time.Now()
	for i := range ring.Keys {
		switch ring.Keys[i].State {
		case keyStateActive:
			ring.Keys[i].State = keyStateRetiring
			ring.Keys[i].RetireAt = now.Add(retention)
		case keyStateRetiring:
			// Keep the previous retirement horizon untouched.
		default:
			return fmt.Errorf("keyring %q: entry %q has invalid state %q",
				keyRingPath(dir), ring.Keys[i].KID, ring.Keys[i].State)
		}
	}

	// Generate the new active key and persist it under its thumbprint kid.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}
	kid := jwkThumbprint(&key.PublicKey)
	for _, entry := range ring.Keys {
		if entry.KID == kid {
			return fmt.Errorf("keyring %q: generated kid %q already exists", keyRingPath(dir), kid)
		}
	}
	fileName := "minidp-rsa-" + kid + ".pem"
	if err := persistKeyPEM(root, dir, fileName, key); err != nil {
		return err
	}
	ring.Keys = append(ring.Keys, keyringEntry{
		KID:       kid,
		File:      fileName,
		CreatedAt: now,
		State:     keyStateActive,
	})
	if err := saveKeyRing(root, dir, keyRingFileName, ring); err != nil {
		return err
	}
	retiring := make([]string, 0, len(ring.Keys)-1)
	for _, entry := range ring.Keys {
		if entry.KID != kid {
			retiring = append(retiring, entry.KID)
		}
	}
	slog.Info("signing key rotation staged",
		"new_kid", kid,
		"retiring_kids", strings.Join(retiring, ","),
		"retire_after", retention.String(),
		"key_dir", dir,
	)
	return nil
}

// persistKeyPEM writes the private key to <dir>/<name> (mode 0600) via an
// exclusively created temp file + rename, so a crash mid-write can never
// leave a truncated key behind. O_EXCL also serializes concurrent rotations:
// the loser gets an explicit error instead of racing the winner.
func persistKeyPEM(root *os.Root, dir, name string, key *rsa.PrivateKey) error {
	tmpName := name + ".tmp"
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temp signing key %q in %q: %w", tmpName, dir, err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if _, err := tmp.Write(pemBytes); err != nil {
		discardTempFile(root, tmp, tmpName)
		return fmt.Errorf("write signing key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		removeTempFile(root, tmpName)
		return fmt.Errorf("close signing key: %w", err)
	}
	if err := os.Rename(filepath.Join(dir, tmpName), filepath.Join(dir, name)); err != nil {
		removeTempFile(root, tmpName)
		return fmt.Errorf("persist signing key to %q: %w", name, err)
	}
	return nil
}

// saveKeyRing writes the keyring document (mode 0600) via temp file + rename.
func saveKeyRing(root *os.Root, dir, name string, ring *keyringFile) error {
	data, err := json.MarshalIndent(ring, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keyring: %w", err)
	}
	data = append(data, '\n')
	tmpName := name + ".tmp"
	tmp, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create temp keyring: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		discardTempFile(root, tmp, tmpName)
		return fmt.Errorf("write keyring: %w", err)
	}
	if err := tmp.Close(); err != nil {
		removeTempFile(root, tmpName)
		return fmt.Errorf("close keyring: %w", err)
	}
	if err := os.Rename(filepath.Join(dir, tmpName), filepath.Join(dir, name)); err != nil {
		removeTempFile(root, tmpName)
		return fmt.Errorf("persist keyring to %q: %w", name, err)
	}
	return nil
}

func loadSigningKey(pemPath string) (*signingKey, error) {
	// Scope the read to the directory holding the configured key file so a
	// crafted path cannot traverse outside it (gosec G304).
	dir, name := filepath.Split(filepath.Clean(pemPath))
	if dir == "" {
		dir = "."
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open key directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read rsa key: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read rsa key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("rsa key: no PEM block found in %q", pemPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to PKCS#8.
		pk, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parse rsa key (tried PKCS#1 and PKCS#8): %w", err)
		}
		rk, ok := pk.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("rsa key in %q is not an RSA key", pemPath)
		}
		key = rk
	}
	return &signingKey{key: key, kid: legacyKid, version: "1.0"}, nil
}

// typIDToken / typAccessToken are the JWT "typ" header values. Access tokens
// use the RFC 9068 profile header "at+jwt" so resource endpoints can tell an
// access token from an id token even before looking at the claims; accepting
// an id token as a bearer access token was a review finding (H3).
const (
	typIDToken     = "JWT"
	typAccessToken = "at+jwt"
)

// sign produces an RS256-signed id token for the supplied claims.
func (k *signingKey) sign(claims jwt.Claims) (string, error) {
	return k.signTyped(claims, typIDToken)
}

// signAccess produces an RS256-signed access token with the RFC 9068 "at+jwt"
// typ header.
func (k *signingKey) signAccess(claims jwt.Claims) (string, error) {
	return k.signTyped(claims, typAccessToken)
}

// signTyped signs the claims with the given typ header value.
func (k *signingKey) signTyped(claims jwt.Claims, typ string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = k.kid
	token.Header["typ"] = typ
	signed, err := token.SignedString(k.key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// jwk is a single JSON Web Key as described by RFC 7517.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwkOf builds the public JWK of one signing key.
func (k *signingKey) jwkOf() jwk {
	pub := &k.key.PublicKey
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: k.kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// keySet is the signing material of a running IdP: the active key that mints
// new tokens plus every key still published in the JWKS, so tokens minted
// before a rotation remain verifiable until the retiring key is pruned.
type keySet struct {
	active    *signingKey
	published []*signingKey
}

// keySetOf wraps a single key into a key set.
func keySetOf(k *signingKey) *keySet {
	return &keySet{active: k, published: []*signingKey{k}}
}

// sign produces an RS256-signed id token with the active key.
func (ks *keySet) sign(claims jwt.Claims) (string, error) {
	return ks.active.sign(claims)
}

// signAccess produces an RS256-signed access token with the active key.
func (ks *keySet) signAccess(claims jwt.Claims) (string, error) {
	return ks.active.signAccess(claims)
}

// verifyKey is the jwt.Parser keyfunc: it returns the published key whose
// kid matches the token header. An unknown or missing kid fails closed — a
// token that references no published key cannot be trusted.
func (ks *keySet) verifyKey(tok *jwt.Token) (any, error) {
	kid := claimString(tok.Header, "kid")
	for _, k := range ks.published {
		if k.kid == kid {
			return &k.key.PublicKey, nil
		}
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

// JWKS returns the JSON Web Key Set containing the public halves of every
// published signing key — the active key and, during a rotation transition,
// the retiring keys until their retention horizon has passed. This is what
// resource servers pull via the discovery document's jwks_uri to verify
// token signatures.
func (ks *keySet) JWKS() ([]byte, error) {
	keys := make([]jwk, 0, len(ks.published))
	for _, k := range ks.published {
		keys = append(keys, k.jwkOf())
	}
	out, err := json.MarshalIndent(struct {
		Keys []jwk `json:"keys"`
	}{Keys: keys}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	return out, nil
}

// pkceS256 computes the PKCE S256 challenge for a code_verifier.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
