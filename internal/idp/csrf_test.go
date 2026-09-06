package idp

import (
	"net/url"
	"testing"
	"time"
)

var testNonce = []byte("0123456789abcdef0123456789abcdef")

func TestCSRFIssueVerifyRoundTrip(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	params := url.Values{"client_id": {"rego-adventure"}, "state": {"xyz"}}

	token := m.issue("/authorize", params, testNonce)
	if !m.verify("/authorize", params, testNonce, token) {
		t.Fatal("a freshly issued token must verify")
	}
}

func TestCSRFRejectsWrongNonce(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	params := url.Values{"client_id": {"c1"}}
	token := m.issue("/authorize", params, testNonce)

	other := []byte("ffffffffffffffffffffffffffffffff")
	if m.verify("/authorize", params, other, token) {
		t.Fatal("a token must not verify against a different browser nonce")
	}
	if m.verify("/authorize", params, nil, token) {
		t.Fatal("a token must not verify without a nonce")
	}
}

func TestCSRFRejectsWrongAction(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	token := m.issue("/authorize", url.Values{"client_id": {"c1"}}, testNonce)
	if m.verify("/login", url.Values{"client_id": {"c1"}}, testNonce, token) {
		t.Fatal("a token issued for /authorize must not verify for /login")
	}
}

func TestCSRFRejectsTamperedParameters(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	token := m.issue("/authorize", url.Values{"redirect_uri": {"https://good.example.com/cb"}}, testNonce)
	if m.verify("/authorize", url.Values{"redirect_uri": {"https://evil.example.com/cb"}}, testNonce, token) {
		t.Fatal("a token must not verify against different parameters")
	}
}

func TestCSRFRejectsTamperedSignatureAndGarbage(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	params := url.Values{}
	token := m.issue("/login", params, testNonce)

	if m.verify("/login", params, testNonce, token+"x") {
		t.Fatal("flipping the signature must fail verification")
	}
	if m.verify("/login", params, testNonce, "garbage") {
		t.Fatal("garbage must fail verification")
	}
	if m.verify("/login", params, testNonce, "") {
		t.Fatal("an empty token must fail verification")
	}
	// A token from a different secret must not verify.
	other := newCSRFManager([]byte("fedcba9876543210fedcba9876543210"), time.Minute)
	if other.verify("/login", params, testNonce, token) {
		t.Fatal("a token signed with a different key must fail verification")
	}
}

func TestCSRFExpiry(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), -time.Minute) // already expired
	token := m.issue("/login", url.Values{}, testNonce)
	if m.verify("/login", url.Values{}, testNonce, token) {
		t.Fatal("an expired token must fail verification")
	}
}

func TestCSRFTokensAreNotPortableAcrossInstances(t *testing.T) {
	// Two managers with the same secret behave identically (e.g. after a
	// restart with a derived secret this would matter); different secrets
	// must not accept each other's tokens.
	a := newCSRFManager([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), time.Minute)
	b := newCSRFManager([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), time.Minute)
	token := a.issue("/login", url.Values{}, testNonce)
	if b.verify("/login", url.Values{}, testNonce, token) {
		t.Fatal("cross-instance token acceptance")
	}
}
