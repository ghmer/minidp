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
// redirect_uri. The token is an HMAC over the form action plus a fingerprint
// of the request parameters, with a short expiry.
type csrfManager struct {
	key []byte
	ttl time.Duration
}

func newCSRFManager(secret []byte, ttl time.Duration) *csrfManager {
	return &csrfManager{key: secret, ttl: ttl}
}

// issue returns a fresh signed token for the given form action and parameters.
func (m *csrfManager) issue(action string, params url.Values) string {
	payload := m.payload(action, params, time.Now().Add(m.ttl))
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verify checks a submitted token: signature, expiry, action and parameter
// fingerprint must all match.
func (m *csrfManager) verify(action string, params url.Values, token string) bool {
	payload, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	expected, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), expected) != 1 {
		return false
	}
	want := m.payload(action, params, time.Time{})
	gotAction, gotFingerprint, ok := splitPayload(payload)
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(gotAction), []byte(action)) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(gotFingerprint), []byte(want)) != 1 {
		return false
	}
	expUnix, err := strconv.ParseInt(splitExp(payload), 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	return true
}

// payload builds "exp|action|paramFingerprint". When exp is the zero time the
// fingerprint part alone is produced (used as the comparison value).
func (m *csrfManager) payload(action string, params url.Values, exp time.Time) string {
	fingerprint := fmt.Sprintf("%x", sha256.Sum256([]byte(params.Encode())))
	if exp.IsZero() {
		return fingerprint
	}
	return strconv.FormatInt(exp.Unix(), 10) + "|" + action + "|" + fingerprint
}

func splitPayload(payload string) (action, fingerprint string, ok bool) {
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func splitExp(payload string) string {
	if exp, _, ok := strings.Cut(payload, "|"); ok {
		return exp
	}
	return ""
}
