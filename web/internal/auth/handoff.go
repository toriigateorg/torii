package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// HandoffClaims is a one-time-use token that conveys an authenticated user
// from torii's host to a service host after SSO. Cookies are scoped per-host
// in browsers, so SSO cookies set on cfg.ToriiURL aren't visible on a
// service domain. To preserve the "user clicks SSO from a service page and
// lands back on it logged in" UX, torii issues a handoff token after SSO and
// the service-host /api/v1/sso_handoff endpoint exchanges it for fresh
// session cookies on that host.
//
// The token is signed with the same JWT secret as access tokens, has a very
// short TTL (30s), and is bound to a specific target host so it can only be
// consumed at the destination it was minted for.
type HandoffClaims struct {
	TargetHost string `json:"target_host"`
	jwt.RegisteredClaims
}

// IssueHandoffToken signs a short-lived JWT that authorizes targetHost's
// /sso_handoff endpoint to mint a session for userID.
func IssueHandoffToken(userID uuid.UUID, targetHost string, secret []byte) (string, error) {
	claims := HandoffClaims{
		TargetHost: targetHost,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

// ParseHandoffToken validates a handoff token and returns its claims. The
// caller must additionally verify that claims.TargetHost matches the host
// the request landed on, otherwise a token minted for service A could be
// replayed at service B.
func ParseHandoffToken(token string, secret []byte) (*HandoffClaims, error) {
	claims := &HandoffClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims.TargetHost == "" {
		return nil, errors.New("handoff token missing target_host")
	}
	return claims, nil
}
