package idp

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// csrfManager issues and verifies signed login-form tokens. The login form
// round-trips the OAuth2 request parameters through the browser, so without
// protection an attacker could submit a crafted cross-site form and have the
// victim silently obtain an authorization code for an attacker-controlled
// redirect_uri.
//
// A token is an HMAC over the form action, a fingerprint of the request
// parameters and a per-browser nonce — a random value delivered in an
// HttpOnly, SameSite=Lax cookie alongside the form. Binding the token to the
// nonce means a token fetched by one browser is worthless to another: an
// attacker can pre-fetch a token for malicious parameters, but the victim's
// browser will neither send the attacker's cookie (SameSite) nor possess a
// nonce the attacker knows.
type csrfManager struct {
	key []byte
	ttl time.Duration
}

func newCSRFManager(secret []byte, ttl time.Duration) *csrfManager {
	return &csrfManager{key: secret, ttl: ttl}
}

// issue returns a fresh signed token for the given form action, parameters and
// browser nonce.
func (m *csrfManager) issue(action string, params url.Values, nonce []byte) string {
	exp := time.Now().Add(m.ttl)
	payload := strconv.FormatInt(exp.Unix(), 10) + "|" + action + "|" +
		fingerprint(params) + "|" + nonceFingerprint(nonce)
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verify checks a submitted token: signature, expiry, action, parameter
// fingerprint and browser nonce must all match.
func (m *csrfManager) verify(action string, params url.Values, nonce []byte, token string) bool {
	if len(nonce) == 0 {
		return false
	}
	payload, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	if !m.validSignature(payload, sig) {
		return false
	}
	parts := strings.SplitN(payload, "|", 4)
	if len(parts) != 4 {
		return false
	}
	return claimsMatch(parts, action, params, nonce)
}

// validSignature verifies the HMAC part of the token in constant time.
func (m *csrfManager) validSignature(payload, sig string) bool {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	expected, err := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && subtle.ConstantTimeCompare(mac.Sum(nil), expected) == 1
}

// claimsMatch compares the payload fields against the expected expiry,
// action, parameter fingerprint and browser nonce fingerprint, in constant
// time.
func claimsMatch(parts []string, action string, params url.Values, nonce []byte) bool {
	expUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(action)) == 1 &&
		subtle.ConstantTimeCompare([]byte(parts[2]), []byte(fingerprint(params))) == 1 &&
		subtle.ConstantTimeCompare([]byte(parts[3]), []byte(nonceFingerprint(nonce))) == 1
}

// fingerprint is a stable digest of the canonical parameter encoding
// (url.Values.Encode sorts keys).
func fingerprint(params url.Values) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(params.Encode())))
}

// nonceFingerprint hashes the browser nonce so the raw value never appears in
// the form token (it is already in the cookie).
func nonceFingerprint(nonce []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(nonce))
}
