package idp

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// authCode is a one-shot authorization code together with the request context
// (client, redirect URI, PKCE challenge, nonce, scopes, subject) that it belongs
// to so it can be redeemed at the token endpoint.
type authCode struct {
	Sub                 string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	Scopes              []string
	ExpiresAt           time.Time
}

// refreshEntry is a stored refresh token bound to its subject, client, scopes
// and the nonce captured at authorization time so a refreshed id_token keeps the
// same nonce as the original.
type refreshEntry struct {
	Sub       string
	ClientID  string
	Scopes    []string
	Nonce     string
	ExpiresAt time.Time
}

// store is an in-memory, concurrency-safe registry of authorization codes and
// refresh tokens. It is intentionally minimal: tokens are held in memory and are
// therefore lost on restart, which is acceptable for a development IdP. Swap the
// maps below for a database for production use.
type store struct {
	mu      sync.Mutex
	codes   map[string]*authCode
	refresh map[string]*refreshEntry
}

func newStore() *store {
	return &store{
		codes:   make(map[string]*authCode),
		refresh: make(map[string]*refreshEntry),
	}
}

func (s *store) addCode(c *authCode, ttl time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpired()
	id := randomToken()
	c.ExpiresAt = time.Now().Add(ttl)
	s.codes[id] = c
	return id
}

// takeCode removes and returns a code by id, or nil if it is unknown, expired,
// or has already been redeemed (codes are single-use to defeat replay).
func (s *store) takeCode(id string) *authCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[id]
	if !ok {
		return nil
	}
	delete(s.codes, id)
	if time.Now().After(c.ExpiresAt) {
		return nil
	}
	return c
}

func (s *store) addRefresh(f *refreshEntry, ttl time.Duration) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpired()
	id := randomToken()
	f.ExpiresAt = time.Now().Add(ttl)
	s.refresh[id] = f
	return id
}

func (s *store) takeRefresh(id string) *refreshEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.refresh[id]
	if !ok {
		return nil
	}
	delete(s.refresh, id)
	if time.Now().After(f.ExpiresAt) {
		return nil
	}
	return f
}

func (s *store) revokeToken(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, id)
	delete(s.refresh, id)
}

// dropExpired removes expired entries. The caller must hold the lock.
func (s *store) dropExpired() {
	now := time.Now()
	for id, c := range s.codes {
		if now.After(c.ExpiresAt) {
			delete(s.codes, id)
		}
	}
	for id, f := range s.refresh {
		if now.After(f.ExpiresAt) {
			delete(s.refresh, id)
		}
	}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
