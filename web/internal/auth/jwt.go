package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Token types. Every JWT torii signs with cfg.JWTSecret carries one, and each
// parser accepts only its own: the secret is shared across token kinds, so
// without a type discriminator a token minted for one purpose verifies as
// another. A handoff token, for instance, parsed cleanly as an access token
// with empty permissions and so authenticated bare RequireUser endpoints.
// Any new secret-signed token type MUST declare a typ here and check it.
const (
	TokenTypeAccess  = "access"
	TokenTypeHandoff = "handoff"
)

// Principal types, forwarded to upstreams as X-Torii-Principal-Type and covered
// by the HMAC signature. users.username and api_users.name are separate tables
// with separate uniqueness, so the same string can name a human and a machine;
// X-Torii-User carries a UUID from one of two namespaces and cannot distinguish
// them either. This is what lets an upstream tell "the person alice" from "the
// service credential called alice" without an out-of-band allowlist.
const (
	PrincipalUser    = "user"
	PrincipalService = "service"
)

type Claims struct {
	Username    string   `json:"username"`
	Email       string   `json:"email,omitempty"`
	Permissions []string `json:"permissions"`
	RoleIDs     []string `json:"role_ids"`
	// TokenType is TokenTypeAccess on every JWT torii issues. It is empty on
	// Claims synthesized for PAT/SAT callers, which never round-trip through
	// ParseAccessToken.
	TokenType string `json:"typ,omitempty"`
	// PrincipalType is PrincipalUser or PrincipalService. Empty means
	// PrincipalUser — tokens minted before the claim existed are human sessions.
	PrincipalType string `json:"ptyp,omitempty"`
	jwt.RegisteredClaims
}

// Principal resolves PrincipalType, defaulting to PrincipalUser so a token from
// before the claim existed is not reported as a machine identity.
func (c *Claims) Principal() string {
	if c.PrincipalType == PrincipalService {
		return PrincipalService
	}
	return PrincipalUser
}

func (c *Claims) Has(perm string) bool {
	for _, p := range c.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// CanonicalHost normalizes a Host header so hosts compare equal regardless of
// case, surrounding space, or an explicitly written default port. Must stay in
// step with config.canonicalHost, which Config.IsToriiHost compares with.
func CanonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ":443")
	h = strings.TrimSuffix(h, ":80")
	return h
}

// IssueAccessToken binds the token to audience — the host it was issued for.
// Sessions are established per host (cookies are host-scoped, so signin,
// sso_handoff and token_refresh all run on proxied service hosts too), and
// without the binding a token minted on an upstream's origin is a portable
// control-plane credential: script running there (a hostile upstream, an XSS,
// a compromised dependency) can read it out of a same-origin response body and
// replay it against /admin or against every other upstream. ParseAccessToken
// rejects a token whose audience is not the host currently being addressed.
func IssueAccessToken(userID uuid.UUID, username, email string, perms []string, roleIDs []uuid.UUID, audience string, secret []byte, ttl time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().Add(ttl)
	roleStrs := make([]string, len(roleIDs))
	for i, r := range roleIDs {
		roleStrs[i] = r.String()
	}
	if perms == nil {
		perms = []string{}
	}
	claims := Claims{
		Username:      username,
		Email:         email,
		Permissions:   perms,
		RoleIDs:       roleStrs,
		TokenType:     TokenTypeAccess,
		PrincipalType: PrincipalUser,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{CanonicalHost(audience)},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	return signed, expiresAt, err
}

// ParseAccessToken verifies the signature, the token type, and that the token
// was issued for audience — the host now serving the request. A token with no
// audience claim is rejected outright; the only ones in the wild are those
// minted before the claim existed, and they age out within one access TTL.
func ParseAccessToken(token string, secret []byte, audience string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeAccess {
		return nil, errors.New("token is not an access token")
	}
	if !claims.hasAudience(CanonicalHost(audience)) {
		return nil, errors.New("token was not issued for this host")
	}
	return claims, nil
}

func (c *Claims) hasAudience(want string) bool {
	if want == "" {
		return false
	}
	for _, a := range c.Audience {
		if CanonicalHost(a) == want {
			return true
		}
	}
	return false
}
