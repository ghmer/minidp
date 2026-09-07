package idp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenResponse is the RFC 6749 / OIDC success payload returned by the token
// endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// accessClaims are the claims embedded in the issued access token.
type accessClaims struct {
	jwt.RegisteredClaims
	Scope    string   `json:"scope,omitempty"`
	Username string   `json:"preferred_username,omitempty"`
	Email    string   `json:"email,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// idClaims are the OIDC claims embedded in the issued id_token. sid carries
// the token family (one authorization) so /end_session can revoke exactly
// that authorization's tokens from an id_token_hint.
type idClaims struct {
	jwt.RegisteredClaims
	Nonce             string   `json:"nonce,omitempty"`
	Email             string   `json:"email,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	SessionID         string   `json:"sid,omitempty"`
}

// issueTokens mints a fresh access token, an id_token (when the openid scope is
// present, as it is for rego-adventure) and a brand-new refresh token. Refresh
// tokens are rotated: every issuance retires the previous one, so a refresh
// token can only ever be used a single time.
//
// Every token carries the configured audience (s.cfg.Audience) — never a
// caller-chosen one — and profile claims are released strictly according to
// the granted scopes from the authoritative users-file record.
func (s *Server) issueTokens(ctx *authContext) (*tokenResponse, error) {
	now := time.Now()
	accessExpires := now.Add(s.cfg.AccessTokenTTL)

	// A crypto/rand failure must not panic here (review finding F6): this
	// runs inside request handlers, so the error degrades to a 500.
	accessJTI, err := randomJTI()
	if err != nil {
		return nil, fmt.Errorf("generate access token jti: %w", err)
	}

	// Scope-based claim release (OIDC Core §5.4): profile unlocks
	// preferred_username and name, email unlocks the email claim. The values
	// come from the users-file record; nothing is fabricated (no
	// placeholder@example.com), so an absent claim is simply omitted. Roles
	// are authorization data, not profile claims: they are released on both
	// tokens whenever the record defines them, regardless of the scopes.
	wantProfile := hasScope(ctx.Scopes, "profile")
	wantEmail := hasScope(ctx.Scopes, "email")
	var email, name string
	var roles []string
	if u, ok := s.users.Lookup(ctx.Sub); ok {
		if wantEmail {
			email = u.Email
		}
		if wantProfile {
			name = u.Name
		}
		roles = u.Roles
	}

	access := &accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   ctx.Sub,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(accessExpires),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        accessJTI,
		},
		Scope: joinScopes(ctx.Scopes),
	}
	if wantProfile {
		access.Username = ctx.Sub
	}
	access.Email = email
	access.Roles = roles
	accessTokenString, err := s.key.signAccess(access)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}
	// Track the access token so /revoke and /end_session can deny it (the
	// JWT itself is stateless and cannot be deleted).
	s.store.registerJTI(access.ID, ctx.Sub, ctx.Family, accessExpires)

	resp := &tokenResponse{
		AccessToken: accessTokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.cfg.AccessTokenTTL.Seconds()),
		Scope:       joinScopes(ctx.Scopes),
	}

	if hasScope(ctx.Scopes, "openid") {
		idJTI, err := randomJTI()
		if err != nil {
			return nil, fmt.Errorf("generate id token jti: %w", err)
		}
		id := &idClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    s.cfg.Issuer,
				Subject:   ctx.Sub,
				Audience:  jwt.ClaimStrings{s.cfg.Audience},
				ExpiresAt: jwt.NewNumericDate(accessExpires),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        idJTI,
			},
			Nonce:     ctx.Nonce,
			SessionID: ctx.Family,
		}
		if wantProfile {
			id.PreferredUsername = ctx.Sub
			id.Name = name
		}
		id.Email = email
		id.Roles = roles
		idTokenString, err := s.key.sign(id)
		if err != nil {
			return nil, fmt.Errorf("sign id token: %w", err)
		}
		resp.IDToken = idTokenString
	}

	// Mint a single-use refresh token that itself carries forward the subject,
	// client, scopes and nonce so it can mint the next token set. Every token
	// of a chain shares the Family id of the originating authorization so reuse
	// detection can revoke the whole chain.
	refresh, err := s.store.addRefresh(&refreshEntry{
		Sub:      ctx.Sub,
		ClientID: ctx.ClientID,
		Scopes:   ctx.Scopes,
		Nonce:    ctx.Nonce,
		Family:   ctx.Family,
	}, s.cfg.RefreshTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}
	resp.RefreshToken = refresh

	return resp, nil
}

// randomJTI returns a 128-bit random claim id. crypto/rand failures are
// propagated as an error instead of panicking (review finding F6): callers
// run inside request handlers, where a panic would kill the whole process.
func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func joinScopes(scopes []string) string {
	// Normalise to the standard, de-duplicated order for presentation.
	seen := map[string]bool{}
	ordered := []string{}
	for _, sc := range scopes {
		if sc == "" || seen[sc] {
			continue
		}
		seen[sc] = true
		ordered = append(ordered, sc)
	}
	return strings.Join(ordered, " ")
}

func hasScope(scopes []string, want string) bool {
	for _, sc := range scopes {
		if sc == want {
			return true
		}
	}
	return false
}
