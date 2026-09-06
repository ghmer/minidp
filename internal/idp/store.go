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
	// accessJTI registers issued access tokens (jti -> sub/family/exp). The
	// JWTs themselves are stateless; this registry is what lets revocation
	// and logout deny them.
	accessJTI map[string]jtiRecord
	// deniedJTI is the revocation denylist: jti -> denial expiry. Denied
	// tokens fail verification until their natural expiry.
	deniedJTI map[string]time.Time
}

// jtiRecord tracks one issued access token.
type jtiRecord struct {
	sub    string
	family string
	exp    time.Time
}

func newStore() *store {
	return &store{
		codes:       make(map[string]*authCode),
		refresh:     make(map[string]*refreshEntry),
		usedRefresh: make(map[string]*refreshEntry),
		accessJTI:   make(map[string]jtiRecord),
		deniedJTI:   make(map[string]time.Time),
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
// Read-only traffic also sweeps expired entries so they cannot linger.
func (s *store) takeCode(id string) *authCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropExpired()
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
	s.dropExpired()
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

// registerJTI records an issued access token so it can be denied later
// (revocation endpoint, logout).
func (s *store) registerJTI(jti, sub, family string, exp time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessJTI[jti] = jtiRecord{sub: sub, family: family, exp: exp}
}

// denyJTI puts an access token on the denylist until its expiry.
func (s *store) denyJTI(jti string, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deniedJTI[jti] = until
}

// deniedJTIOf reports whether the given jti is on the denylist.
func (s *store) isDeniedJTI(jti string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.deniedJTI[jti])
}

// revokeFamilyTokens drops every refresh token of the family and denies all
// of its live access tokens. Used by /revoke, reuse detection and logout.
func (s *store) revokeFamilyTokens(family string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(family)
}

// revokeFamilyLocked is revokeFamilyTokens without locking. The caller must
// hold the lock.
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
	// RFC 7009 §2.1: revoking a refresh token SHOULD also invalidate the
	// access tokens based on the same authorization. Access tokens are
	// stateless, so they are denied by jti until their expiry.
	now := time.Now()
	for jti, rec := range s.accessJTI {
		if rec.family == family && now.Before(rec.exp) {
			s.deniedJTI[jti] = rec.exp
			delete(s.accessJTI, jti)
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
	for jti, rec := range s.accessJTI {
		if now.After(rec.exp) {
			delete(s.accessJTI, jti)
		}
	}
	for jti, until := range s.deniedJTI {
		if now.After(until) {
			delete(s.deniedJTI, jti)
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
