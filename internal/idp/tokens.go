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
	Scope    string `json:"scope,omitempty"`
	Username string `json:"preferred_username,omitempty"`
	Email    string `json:"email,omitempty"`
}

// idClaims are the OIDC claims embedded in the issued id_token.
type idClaims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce,omitempty"`
	Email             string `json:"email,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// issueTokens mints a fresh access token, an id_token (when the openid scope is
// present, as it is for rego-adventure) and a brand-new refresh token. Refresh
// tokens are rotated: every issuance retires the previous one, so a refresh
// token can only ever be used a single time.
func (s *Server) issueTokens(ctx *authContext) (*tokenResponse, error) {
	now := time.Now()
	accessExpires := now.Add(s.cfg.AccessTokenTTL)

	// Profile claims come from the user store when the subject exists there;
	// single-user mode falls back to a placeholder email.
	email := ctx.Sub + "@example.com"
	name := ""
	if s.users != nil {
		if u, ok := s.users.Lookup(ctx.Sub); ok {
			if u.Email != "" {
				email = u.Email
			}
			name = u.Name
		}
	}

	access := &accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.Issuer,
			Subject:   ctx.Sub,
			Audience:  jwt.ClaimStrings{ctx.ClientID},
			ExpiresAt: jwt.NewNumericDate(accessExpires),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        randomJTI(),
		},
		Scope:    joinScopes(ctx.Scopes),
		Username: ctx.Sub,
		Email:    email,
	}
	accessTokenString, err := s.key.sign(access)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	resp := &tokenResponse{
		AccessToken: accessTokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.cfg.AccessTokenTTL.Seconds()),
		Scope:       joinScopes(ctx.Scopes),
	}

	if hasScope(ctx.Scopes, "openid") {
		id := &idClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    s.cfg.Issuer,
				Subject:   ctx.Sub,
				Audience:  jwt.ClaimStrings{ctx.ClientID},
				ExpiresAt: jwt.NewNumericDate(accessExpires),
				IssuedAt:  jwt.NewNumericDate(now),
				ID:        randomJTI(),
			},
			Nonce:             ctx.Nonce,
			Email:             email,
			Name:              name,
			PreferredUsername: ctx.Sub,
		}
		idTokenString, err := s.key.sign(id)
		if err != nil {
			return nil, fmt.Errorf("sign id token: %w", err)
		}
		resp.IDToken = idTokenString
	}

	// Mint a single-use refresh token that itself carries forward the subject,
	// client, scopes and nonce so it can mint the next token set.
	resp.RefreshToken = s.store.addRefresh(&refreshEntry{
		Sub:      ctx.Sub,
		ClientID: ctx.ClientID,
		Scopes:   ctx.Scopes,
		Nonce:    ctx.Nonce,
	}, s.cfg.RefreshTokenTTL)

	return resp, nil
}

func randomJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
