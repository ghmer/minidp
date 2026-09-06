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
// same nonce as the original. Family groups all tokens derived from one
// authorization so that a detected reuse (RFC 9700 §4.14.2) can revoke the
// whole chain at once.
type refreshEntry struct {
	Sub       string
	ClientID  string
	Scopes    []string
	Nonce     string
	Family    string
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
	// usedRefresh remembers consumed refresh tokens until their original
	// expiry so a replayed (stolen) token can be recognised and its entire
	// family revoked instead of merely failing (RFC 9700 §4.14.2).
	usedRefresh map[string]*refreshEntry
}

func newStore() *store {
	return &store{
		codes:       make(map[string]*authCode),
		refresh:     make(map[string]*refreshEntry),
		usedRefresh: make(map[string]*refreshEntry),
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

// takeRefresh consumes a refresh token (single-use). reused is true when the
// token had already been consumed before — a replay of a stolen token — in
// which case the whole family has been revoked and the entry is nil.
func (s *store) takeRefresh(id string) (entry *refreshEntry, reused bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.usedRefresh[id]; ok {
		s.revokeFamilyLocked(f.Family)
		delete(s.usedRefresh, id)
		return nil, true
	}
	f, ok := s.refresh[id]
	if !ok {
		return nil, false
	}
	delete(s.refresh, id)
	if time.Now().After(f.ExpiresAt) {
		return nil, false
	}
	s.usedRefresh[id] = f
	return f, false
}

// revokeFamily drops every live and consumed refresh token derived from the
// same authorization. An empty family is a no-op (untracked entries).
func (s *store) revokeFamily(family string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(family)
}

// revokeFamilyLocked is revokeFamily without locking. The caller must hold
// the lock.
func (s *store) revokeFamilyLocked(family string) {
	if family == "" {
		return
	}
	for id, f := range s.refresh {
		if f.Family == family {
			delete(s.refresh, id)
		}
	}
	for id, f := range s.usedRefresh {
		if f.Family == family {
			delete(s.usedRefresh, id)
		}
	}
}

// revokeToken revokes the given token per RFC 7009; because a refresh token
// stands for a whole authorization, revoking it (or presenting an already-used
// one to the endpoint) drops the entire family derived from that
// authorization.
func (s *store) revokeToken(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, id)
	if f, ok := s.refresh[id]; ok {
		delete(s.refresh, id)
		s.revokeFamilyLocked(f.Family)
		return
	}
	if f, ok := s.usedRefresh[id]; ok {
		s.revokeFamilyLocked(f.Family)
	}
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
	for id, f := range s.usedRefresh {
		if now.After(f.ExpiresAt) {
			delete(s.usedRefresh, id)
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
