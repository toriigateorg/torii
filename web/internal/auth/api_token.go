package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const APITokenPrefix = "torii_pat_"

// NewAPIToken returns a fresh plaintext PAT (`torii_pat_<rand>`), its sha256
// hash for storage, and a short display prefix safe to surface in lists.
func NewAPIToken() (raw string, hash []byte, displayPrefix string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, "", err
	}
	raw = APITokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], raw[:min(len(raw), len(APITokenPrefix)+6)], nil
}

// ServiceAPITokenPrefix tags tokens belonging to a Service API user. A distinct
// prefix from APITokenPrefix lets the middleware route the two to different
// resolvers and enforce that service tokens only authenticate proxied requests.
const ServiceAPITokenPrefix = "torii_sat_"

// ServiceTokenHeader carries a `torii_sat_` service token when accessing an
// upstream service through the proxy. It is the only torii credential the proxy
// dispatch reads from a header (the client's `Authorization` is reserved for the
// upstream). Only service tokens are accepted here — a torii_pat_ or session JWT
// in this header is rejected. It is stripped before the request is proxied so
// the token never reaches the upstream.
const ServiceTokenHeader = "X-Torii-Service-Token"

// AuthorizationHeader carries a torii credential when authenticating to torii's
// own control-plane API and web UI: a session JWT or a `torii_pat_` personal
// token (a `torii_sat_` service token is rejected — those are proxy-only).
// torii never reads the standard `Authorization` header, so it stays free for
// upstream services behind the proxy. Stripped before proxying so it never
// reaches an upstream.
const AuthorizationHeader = "X-Torii-Authorization"

// NewServiceAPIToken returns a fresh plaintext service token
// (`torii_sat_<rand>`), its sha256 hash for storage, and a short display prefix.
func NewServiceAPIToken() (raw string, hash []byte, displayPrefix string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, "", err
	}
	raw = ServiceAPITokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], raw[:min(len(raw), len(ServiceAPITokenPrefix)+6)], nil
}

func HashAPIToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func IsAPIToken(raw string) bool {
	return strings.HasPrefix(raw, APITokenPrefix)
}

func IsServiceAPIToken(raw string) bool {
	return strings.HasPrefix(raw, ServiceAPITokenPrefix)
}
