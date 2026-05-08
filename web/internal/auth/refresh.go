package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewRefreshToken returns a cryptographically random opaque token (raw, to send
// to the client) and its sha256 hash (to persist).
func NewRefreshToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, h[:], nil
}

func HashRefreshToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}
