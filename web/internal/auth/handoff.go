package auth

import (
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const handoffTTL = 30 * time.Second

// HandoffClaims is a one-time-use token that conveys an authenticated user
// from torii's host to a service host after SSO. Cookies are scoped per-host
// in browsers, so SSO cookies set on cfg.ToriiURL aren't visible on a
// service domain. To preserve the "user clicks SSO from a service page and
// lands back on it logged in" UX, torii issues a handoff token after SSO and
// the service-host /api/v1/sso_handoff endpoint exchanges it for fresh
// session cookies on that host.
//
// The token is signed with the same JWT secret as access tokens, has a very
// short TTL (30s), is bound to a specific target host so it can only be
// consumed at the destination it was minted for, and carries a random jti that
// ConsumeHandoffJTI burns on first use.
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
			ID:        uuid.NewString(),
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(handoffTTL)),
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
	if claims.ID == "" {
		return nil, errors.New("handoff token missing jti")
	}
	return claims, nil
}

// handoffReplay remembers spent handoff token ids until they expire. It is
// process-local: torii answers both TORII_URL and every service host, so a
// single instance sees the mint and the redemption. Across replicas a token
// could still be redeemed once per replica within its 30s window — the token
// never appears in a URL query, Referer, or server log, so that residual is
// bounded by an attacker who already holds the token.
var handoffReplay = struct {
	sync.Mutex
	spent map[string]time.Time
}{spent: make(map[string]time.Time)}

// ConsumeHandoffJTI burns a handoff token id and reports whether this call was
// its first use. Anything already spent (or replayed after expiry) returns
// false and must be rejected.
func ConsumeHandoffJTI(jti string, expiresAt time.Time) bool {
	now := time.Now()
	if jti == "" || !expiresAt.After(now) {
		return false
	}
	handoffReplay.Lock()
	defer handoffReplay.Unlock()
	for id, exp := range handoffReplay.spent {
		if !exp.After(now) {
			delete(handoffReplay.spent, id)
		}
	}
	if _, ok := handoffReplay.spent[jti]; ok {
		return false
	}
	handoffReplay.spent[jti] = expiresAt
	return true
}
