package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
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
// The token is signed with the same JWT secret as access tokens, so it declares
// typ=handoff and ParseAccessToken rejects it — otherwise it verified as an
// access token (with empty permissions) and authenticated bare RequireUser
// endpoints on the control-plane host. It also has a very short TTL (30s), is
// bound to a specific target host so it can only be consumed at the destination
// it was minted for, and carries a random jti that ConsumeHandoffJTI burns on
// first use.
//
// Confirmation carries the SHA-256 of a correlator secret set as a host-scoped
// cookie on the service host *before* the flow left it, and redemption requires
// the cookie to hash to this value. Without it the token was a pure bearer
// credential: nothing burns the jti at mint time, so an attacker driving the flow
// headlessly received an unspent token in the Location header, never redeemed it,
// and relayed the URL to a victim — whose browser then took a session for the
// attacker's subject on a genuine service origin. The cookie is what makes the
// token redeemable only by the browser that started the flow.
type HandoffClaims struct {
	TargetHost   string `json:"target_host"`
	TokenType    string `json:"typ"`
	Confirmation string `json:"cnf"`
	jwt.RegisteredClaims
}

// HandoffCorrelatorCookie holds the correlator secret. Host-scoped and
// path-scoped to torii's own namespace, so it is never sent to an upstream.
const HandoffCorrelatorCookie = "torii_handoff_cor"

// HandoffCorrelatorTTL bounds how long a started handoff may be completed. It has
// to outlast the interactive leg (a password entry or a full OIDC round trip),
// not just the token's own 30 seconds.
const HandoffCorrelatorTTL = 10 * time.Minute

// NewHandoffCorrelator returns a fresh correlator secret and its digest. The
// secret goes in the cookie on the service host; the digest travels through the
// bounce and is embedded in the token.
func NewHandoffCorrelator() (secret, digest string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, HandoffCorrelatorDigest(secret), nil
}

// HandoffCorrelatorDigest is the value embedded in the token's cnf claim.
func HandoffCorrelatorDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SetHandoffCorrelator writes the correlator cookie on the current host.
func SetHandoffCorrelator(c *echo.Context, secret string, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     HandoffCorrelatorCookie,
		Value:    secret,
		Path:     "/_torii/",
		Expires:  time.Now().Add(HandoffCorrelatorTTL),
		MaxAge:   int(HandoffCorrelatorTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearHandoffCorrelator expires the correlator cookie. Called on redemption so a
// correlator is good for exactly one handoff.
func ClearHandoffCorrelator(c *echo.Context, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     HandoffCorrelatorCookie,
		Value:    "",
		Path:     "/_torii/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// VerifyHandoffCorrelator reports whether the presented cookie value matches the
// digest the token was minted with. Both must be non-empty: an empty digest would
// otherwise make an uncorrelated token verify against an absent cookie.
func VerifyHandoffCorrelator(cookieValue, digest string) bool {
	if cookieValue == "" || digest == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HandoffCorrelatorDigest(cookieValue)), []byte(digest)) == 1
}

// IssueHandoffToken signs a short-lived JWT that authorizes targetHost's
// /sso_handoff endpoint to mint a session for userID. correlatorDigest binds the
// token to the browser that began the flow and is mandatory.
func IssueHandoffToken(userID uuid.UUID, targetHost, correlatorDigest string, secret []byte) (string, error) {
	if correlatorDigest == "" {
		return "", errors.New("handoff token requires a correlator digest")
	}
	claims := HandoffClaims{
		TargetHost:   targetHost,
		TokenType:    TokenTypeHandoff,
		Confirmation: correlatorDigest,
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
	if claims.TokenType != TokenTypeHandoff {
		return nil, errors.New("token is not a handoff token")
	}
	if claims.TargetHost == "" {
		return nil, errors.New("handoff token missing target_host")
	}
	if claims.ID == "" {
		return nil, errors.New("handoff token missing jti")
	}
	if claims.Confirmation == "" {
		return nil, errors.New("handoff token missing correlator binding")
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
