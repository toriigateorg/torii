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

// ServiceTokenHeader is an alternative to `Authorization: Bearer` for presenting
// a Service API user token, for scripts that reserve Authorization for the
// upstream service's own auth. It is stripped before the request is proxied so
// the token never reaches the upstream (see proxy.stripIdentityHeaders).
const ServiceTokenHeader = "X-Torii-Service-Token"

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
