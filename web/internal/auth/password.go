package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &t, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	actual := argon2.IDKey([]byte(pw), salt, t, memory, threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// dummyHash is a fixed argon2id-encoded hash used by signin to flatten the
// timing side-channel that would otherwise let an attacker enumerate valid
// usernames. When the supplied identifier doesn't match a user, the handler
// runs VerifyPassword against this constant so the response time is
// indistinguishable from a real-user-with-wrong-password path.
//
// The plaintext that hashes to this value is unknown — it was generated from
// 32 random bytes that were immediately discarded.
var dummyHash = "$argon2id$v=19$m=65536,t=2,p=1$YWFhYWFhYWFhYWFhYWFhYQ$EkCloWYf6QC03Cy0bWh0kdZW8j5HuPMvU2RFf0DAHyA"

// VerifyDummyPassword runs argon2id verification against a fixed dummy hash.
// Used by the signin handler when the user lookup fails, so the per-request
// latency is the same as a real verify-against-stored-hash and an attacker
// can't distinguish "no such user" from "wrong password".
func VerifyDummyPassword(pw string) {
	_ = VerifyPassword(dummyHash, pw)
}

var ErrWeakPassword = errors.New("password must be at least 8 characters and include upper, lower, digit, and special characters")

func ValidatePasswordStrength(pw string) error {
	if len(pw) < 8 {
		return ErrWeakPassword
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{};:,.<>/?\\|`~'\"", r):
			hasSpecial = true
		}
	}
	if !(hasUpper && hasLower && hasDigit && hasSpecial) {
		return ErrWeakPassword
	}
	return nil
}
