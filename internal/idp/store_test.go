package idp

import (
	"testing"
	"time"
)

func TestAddTakeCodeIsSingleUse(t *testing.T) {
	s := newStore()
	id := s.addCode(&authCode{Sub: "rego", ClientID: "c1"}, time.Minute)

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
	id := s.addCode(&authCode{Sub: "rego"}, -time.Minute) // already expired
	if got := s.takeCode(id); got != nil {
		t.Fatalf("expected expired code to be rejected, got %+v", got)
	}
}

func TestDropExpiredSweepsBothMaps(t *testing.T) {
	s := newStore()
	s.addCode(&authCode{Sub: "rego"}, -time.Minute)
	s.addRefresh(&refreshEntry{Sub: "rego"}, -time.Minute)
	s.addCode(&authCode{Sub: "rego"}, time.Minute)        // stays
	s.addRefresh(&refreshEntry{Sub: "rego"}, time.Minute) // stays

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
	first := s.addRefresh(&refreshEntry{Sub: "rego", ClientID: "c1"}, time.Minute)

	entry := s.takeRefresh(first)
	if entry == nil {
		t.Fatal("expected refresh token to be redeemable")
	}
	if entry.Sub != "rego" || entry.ClientID != "c1" {
		t.Fatalf("unexpected refresh entry: %+v", entry)
	}

	// Rotation: the consumed token must not be redeemable again.
	if again := s.takeRefresh(first); again != nil {
		t.Fatal("expected consumed refresh token to be rejected")
	}

	// A newly issued refresh token is independent of the old one.
	second := s.addRefresh(&refreshEntry{Sub: "rego", ClientID: "c1"}, time.Minute)
	if second == first {
		t.Fatal("expected new refresh token id to differ from the old one")
	}
	if s.takeRefresh(second) == nil {
		t.Fatal("expected new refresh token to be redeemable")
	}
}

func TestTakeRefreshExpired(t *testing.T) {
	s := newStore()
	id := s.addRefresh(&refreshEntry{Sub: "rego"}, -time.Minute)
	if got := s.takeRefresh(id); got != nil {
		t.Fatalf("expected expired refresh token to be rejected, got %+v", got)
	}
}

func TestRevokeToken(t *testing.T) {
	s := newStore()
	codeID := s.addCode(&authCode{Sub: "rego"}, time.Minute)
	refreshID := s.addRefresh(&refreshEntry{Sub: "rego"}, time.Minute)

	s.revokeToken(refreshID)
	if got := s.takeRefresh(refreshID); got != nil {
		t.Fatal("expected revoked refresh token to be rejected")
	}
	if got := s.takeCode(codeID); got == nil {
		t.Fatal("revoking the refresh token must not touch other tokens")
	}
}

func TestRandomTokenUnique(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := randomToken()
		if seen[id] {
			t.Fatalf("duplicate random token %q", id)
		}
		seen[id] = true
	}
}
