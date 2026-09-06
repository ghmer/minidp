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
	"math/big"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
)

// signingKey wraps an RSA private key together with the stable key id (kid) that
// is written into the JWT header and published in the JWKS document so that the
// relying party can select the matching public key for RS256 verification.
type signingKey struct {
	key     *rsa.PrivateKey
	kid     string
	version string
}

// NewSigningKey loads a PKCS#1 RSA key from a PEM file when pemPath is
// non-empty, otherwise it generates a fresh RSA-2048 key in memory.
func NewSigningKey(pemPath string) (*signingKey, error) {
	if pemPath != "" {
		return loadSigningKey(pemPath)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	return &signingKey{key: key, kid: "minidp-1", version: "1.0"}, nil
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
