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

func HashAPIToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

func IsAPIToken(raw string) bool {
	return strings.HasPrefix(raw, APITokenPrefix)
}
