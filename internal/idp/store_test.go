package idp

import (
	"testing"
	"time"
)

// mustAddCode/mustAddRefresh wrap the store constructors for tests: a
// crypto/rand failure cannot be simulated here and would fail the test run
// loudly (review finding F6: production propagates it as an error).
func mustAddCode(t *testing.T, s *store, c *authCode, ttl time.Duration) string {
	t.Helper()
	id, err := s.addCode(c, ttl)
	if err != nil {
		t.Fatalf("addCode: %v", err)
	}
	return id
}

func mustAddRefresh(t *testing.T, s *store, f *refreshEntry, ttl time.Duration) string {
	t.Helper()
	id, err := s.addRefresh(f, ttl)
	if err != nil {
		t.Fatalf("addRefresh: %v", err)
	}
	return id
}

func TestAddTakeCodeIsSingleUse(t *testing.T) {
	s := newStore()
	id := mustAddCode(t, s, &authCode{Sub: "rego", ClientID: "c1"}, time.Minute)

	got := s.takeCode(id)
	if got == nil {
		t.Fatal("expected code to be redeemable")
	}
	if got.Sub != "rego" || got.ClientID != "c1" {
		t.Fatalf("unexpected code contents: %+v", got)
	}
	if again := s.takeCode(id); again != nil {
		t.Fatal("expected second redemption to fail (codes are single-use)")
	}
}

func TestTakeCodeUnknown(t *testing.T) {
	s := newStore()
	if got := s.takeCode("does-not-exist"); got != nil {
		t.Fatalf("expected nil for unknown code, got %+v", got)
	}
}

func TestTakeCodeExpired(t *testing.T) {
	s := newStore()
	id := mustAddCode(t, s, &authCode{Sub: "rego"}, -time.Minute) // already expired
	if got := s.takeCode(id); got != nil {
		t.Fatalf("expected expired code to be rejected, got %+v", got)
	}
}

func TestDropExpiredSweepsBothMaps(t *testing.T) {
	s := newStore()
	mustAddCode(t, s, &authCode{Sub: "rego"}, -time.Minute)
	mustAddRefresh(t, s, &refreshEntry{Sub: "rego"}, -time.Minute)
	mustAddCode(t, s, &authCode{Sub: "rego"}, time.Minute)        // stays
	mustAddRefresh(t, s, &refreshEntry{Sub: "rego"}, time.Minute) // stays

	s.mu.Lock()
	s.dropExpired()
	codesLen, refreshLen := len(s.codes), len(s.refresh)
	s.mu.Unlock()

	if codesLen != 1 {
		t.Errorf("expected 1 live code after sweep, got %d", codesLen)
	}
	if refreshLen != 1 {
		t.Errorf("expected 1 live refresh token after sweep, got %d", refreshLen)
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	s := newStore()
	first := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-1"}, time.Minute)

	entry, reused := s.takeRefresh(first)
	if entry == nil || reused {
		t.Fatal("expected refresh token to be redeemable and not marked as reused")
	}
	if entry.Sub != "rego" || entry.ClientID != "c1" || entry.Family != "fam-1" {
		t.Fatalf("unexpected refresh entry: %+v", entry)
	}

	// Rotation: the consumed token must not be redeemable again.
	if again, reused := s.takeRefresh(first); again != nil {
		t.Fatal("expected consumed refresh token to be rejected")
	} else if !reused {
		t.Error("re-presenting a consumed token must be flagged as reuse")
	}

	// A newly issued refresh token is independent of the old one.
	second := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-1"}, time.Minute)
	if second == first {
		t.Fatal("expected new refresh token id to differ from the old one")
	}
	if e, _ := s.takeRefresh(second); e == nil {
		t.Fatal("expected new refresh token to be redeemable")
	}
}

func TestTakeRefreshExpired(t *testing.T) {
	s := newStore()
	id := mustAddRefresh(t, s, &refreshEntry{Sub: "rego"}, -time.Minute)
	if got, reused := s.takeRefresh(id); got != nil || reused {
		t.Fatalf("expected expired refresh token to be rejected, got %+v (reused=%v)", got, reused)
	}
}

// TestRefreshFamilyReuseRevokesFamily pins RFC 9700 §4.14.2: replaying a
// consumed refresh token must revoke not only the presented token but the
// entire family derived from the same authorization.
func TestRefreshFamilyReuseRevokesFamily(t *testing.T) {
	s := newStore()
	other := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-other"}, time.Minute)

	stolen := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-1"}, time.Minute)
	rotated := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-1"}, time.Minute)

	// Legitimate rotation consumes the stolen token...
	if entry, reused := s.takeRefresh(stolen); entry == nil || reused {
		t.Fatalf("expected first use to succeed (entry=%v reused=%v)", entry, reused)
	}
	// ...then the attacker replays it: reuse detection must kill the family.
	if entry, reused := s.takeRefresh(stolen); entry != nil || !reused {
		t.Fatalf("expected reuse to be detected (entry=%v reused=%v)", entry, reused)
	}
	// The rotated descendant of the same authorization is gone too.
	if entry, reused := s.takeRefresh(rotated); entry != nil || reused {
		t.Error("family revocation must also drop live descendants of the same authorization")
	}
	// Unrelated families are untouched.
	if entry, _ := s.takeRefresh(other); entry == nil {
		t.Error("family revocation must not touch other authorizations")
	}
}

// TestRevokeTokenRevokesFamily covers /revoke on both a live token and an
// already-consumed one: either way the whole family goes.
func TestRevokeTokenRevokesFamily(t *testing.T) {
	s := newStore()
	sibling := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-1"}, time.Minute)

	live := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-1"}, time.Minute)
	s.revokeToken(live)
	if entry, _ := s.takeRefresh(sibling); entry != nil {
		t.Error("revoking a live token must drop its whole family")
	}

	sibling2 := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-2"}, time.Minute)
	consumed := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", ClientID: "c1", Family: "fam-2"}, time.Minute)
	if _, reused := s.takeRefresh(consumed); reused {
		t.Fatal("expected first use of the token to succeed")
	}
	s.revokeToken(consumed) // /revoke with an already-rotated token
	if entry, _ := s.takeRefresh(sibling2); entry != nil {
		t.Error("revoking a consumed token must drop its whole family")
	}
}

func TestRevokeToken(t *testing.T) {
	s := newStore()
	codeID := mustAddCode(t, s, &authCode{Sub: "rego"}, time.Minute)
	refreshID := mustAddRefresh(t, s, &refreshEntry{Sub: "rego", Family: "fam-1"}, time.Minute)

	s.revokeToken(refreshID)
	if got, _ := s.takeRefresh(refreshID); got != nil {
		t.Fatal("expected revoked refresh token to be rejected")
	}
	if got := s.takeCode(codeID); got == nil {
		t.Fatal("revoking the refresh token must not touch other tokens")
	}
}

func TestRandomTokenUnique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate random token %q", id)
		}
		seen[id] = true
	}
}
