package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	Username    string   `json:"username"`
	Email       string   `json:"email,omitempty"`
	Permissions []string `json:"permissions"`
	RoleIDs     []string `json:"role_ids"`
	jwt.RegisteredClaims
}

func (c *Claims) Has(perm string) bool {
	for _, p := range c.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

func IssueAccessToken(userID uuid.UUID, username, email string, perms []string, roleIDs []uuid.UUID, secret []byte, ttl time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().Add(ttl)
	roleStrs := make([]string, len(roleIDs))
	for i, r := range roleIDs {
		roleStrs[i] = r.String()
	}
	if perms == nil {
		perms = []string{}
	}
	claims := Claims{
		Username:    username,
		Email:       email,
		Permissions: perms,
		RoleIDs:     roleStrs,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	return signed, expiresAt, err
}

func ParseAccessToken(token string, secret []byte) (*Claims, error) {
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
	return claims, nil
}
