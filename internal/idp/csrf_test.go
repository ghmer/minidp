package idp

import (
	"net/url"
	"testing"
	"time"
)

func TestCSRFIssueVerifyRoundTrip(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	params := url.Values{"client_id": {"rego-adventure"}, "state": {"xyz"}}

	token := m.issue("/authorize", params)
	if !m.verify("/authorize", params, token) {
		t.Fatal("a freshly issued token must verify")
	}
}

func TestCSRFRejectsWrongAction(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	token := m.issue("/authorize", url.Values{"client_id": {"c1"}})
	if m.verify("/login", url.Values{"client_id": {"c1"}}, token) {
		t.Fatal("a token issued for /authorize must not verify for /login")
	}
}

func TestCSRFRejectsTamperedParameters(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	token := m.issue("/authorize", url.Values{"redirect_uri": {"https://good.example.com/cb"}})
	if m.verify("/authorize", url.Values{"redirect_uri": {"https://evil.example.com/cb"}}, token) {
		t.Fatal("a token must not verify against different parameters")
	}
}

func TestCSRFRejectsTamperedSignatureAndGarbage(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	params := url.Values{}
	token := m.issue("/login", params)

	if m.verify("/login", params, token+"x") {
		t.Fatal("flipping the signature must fail verification")
	}
	if m.verify("/login", params, "garbage") {
		t.Fatal("garbage must fail verification")
	}
	if m.verify("/login", params, "") {
		t.Fatal("an empty token must fail verification")
	}
	// A token from a different secret must not verify.
	other := newCSRFManager([]byte("fedcba9876543210fedcba9876543210"), time.Minute)
	if other.verify("/login", params, token) {
		t.Fatal("a token signed with a different key must fail verification")
	}
}

func TestCSRFExpiry(t *testing.T) {
	m := newCSRFManager([]byte("0123456789abcdef0123456789abcdef"), -time.Minute) // already expired
	token := m.issue("/login", url.Values{})
	if m.verify("/login", url.Values{}, token) {
		t.Fatal("an expired token must fail verification")
	}
}

func TestCSRFTokensAreNotReusableAcrossInstances(t *testing.T) {
	// Two managers with the same secret behave identically (e.g. after a
	// restart with a derived secret this would matter); different secrets
	// must not accept each other's tokens.
	a := newCSRFManager([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), time.Minute)
	b := newCSRFManager([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), time.Minute)
	token := a.issue("/login", url.Values{})
	if b.verify("/login", url.Values{}, token) {
		t.Fatal("cross-instance token acceptance")
	}
}
