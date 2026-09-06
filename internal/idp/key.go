package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// keyFileName is the file name used for the persisted signing key inside
// IDP_KEY_DIR.
const keyFileName = "minidp-rsa.pem"

// signingKey wraps an RSA private key together with the stable key id (kid) that
// is written into the JWT header and published in the JWKS document so that the
// relying party can select the matching public key for RS256 verification.
type signingKey struct {
	key     *rsa.PrivateKey
	kid     string
	version string
}

// NewSigningKey resolves the signing key in this order:
//
//  1. pemPath is set: load the key from that PEM file.
//  2. keyDir is set: load <keyDir>/minidp-rsa.pem; if it does not exist yet,
//     generate a fresh RSA-2048 key and persist it there (mode 0600, written
//     via a temp file + rename so an interrupted start cannot corrupt it).
//  3. Otherwise: generate an ephemeral key held in memory only (development
//     mode; all tokens become invalid on restart).
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
		return &signingKey{key: key, kid: "minidp-1", version: "1.0"}, nil
	}
}

// persistentSigningKey loads the key from keyDir, generating and persisting a
// new one on first use. Generation is safe against concurrent starts on a
// shared key directory: the temp file is created exclusively (O_EXCL), so
// exactly one instance wins and writes the final key while the losers wait
// for it to appear and load it.
func persistentSigningKey(keyDir string) (*signingKey, error) {
	dir := filepath.Clean(keyDir)
	path := filepath.Join(dir, keyFileName)
	tmpName := keyFileName + ".tmp"

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open key dir %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

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
			// left the temp file behind). Wait for the final key, then load it.
			if err := awaitFile(path, 10*time.Second); err != nil {
				if attempt > 0 {
					return nil, fmt.Errorf("gave up waiting for signing key %q: %w", path, err)
				}
				// Break the deadlock once: the temp file is stale (the
				// generating instance crashed mid-write). Remove it and let
				// the next round retry generation.
				slog.Warn("stale signing-key temp file detected, taking over", "path", filepath.Join(dir, tmpName))
				_ = root.Remove(tmpName)
				continue
			}
			continue // final key has appeared: load it on the next round
		}
		if err != nil {
			return nil, fmt.Errorf("create temp signing key in %q: %w", dir, err)
		}

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			_ = tmp.Close()
			_ = root.Remove(tmpName)
			return nil, fmt.Errorf("generate rsa key: %w", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		// Write to the exclusively created temp file, then rename, so a crash
		// mid-write can never leave a truncated key behind. The file is
		// created with 0600 directly (os.Root.Create would umask it to 0644).
		if _, err := tmp.Write(pemBytes); err != nil {
			_ = tmp.Close()
			_ = root.Remove(tmpName)
			return nil, fmt.Errorf("write signing key in %q: %w", dir, err)
		}
		if err := tmp.Close(); err != nil {
			_ = root.Remove(tmpName)
			return nil, fmt.Errorf("close signing key in %q: %w", dir, err)
		}
		if err := os.Rename(filepath.Join(dir, tmpName), path); err != nil {
			_ = root.Remove(tmpName)
			return nil, fmt.Errorf("persist signing key to %q: %w", path, err)
		}
		slog.Info("generated and persisted RSA signing key", "path", path)
		return &signingKey{key: key, kid: "minidp-1", version: "1.0"}, nil
	}
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
	return &signingKey{key: key, kid: "minidp-1", version: "1.0"}, nil
}

// sign produces an RS256-signed JWT for the supplied claims.
func (k *signingKey) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = k.kid
	token.Header["typ"] = "JWT"
	return token.SignedString(k.key)
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

// JWKS returns the JSON Web Key Set containing the public half of the signing
// key. This is what the rego-adventure back-end pulls from AUTH_DISCOVERY_URL's
// jwks_uri to verify token signatures.
func (k *signingKey) JWKS() []byte {
	pub := &k.key.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwks := struct {
		Keys []jwk `json:"keys"`
	}{
		Keys: []jwk{{
			Kty: "RSA",
			Use: "sig",
			Kid: k.kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(nBytes),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
		}},
	}
	out, _ := json.MarshalIndent(jwks, "", "  ")
	return out
}

// pkceS256 computes the PKCE S256 challenge for a code_verifier.
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
