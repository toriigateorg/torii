package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

const ClaimsContextKey = "claims"

func RequireUser(secret []byte) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims, err := authenticate(c, secret)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			c.Set(ClaimsContextKey, claims)
			return next(c)
		}
	}
}

func RequireAdmin(secret []byte) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims, err := authenticate(c, secret)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			if claims.UserType != "admin" {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "admin only"})
			}
			c.Set(ClaimsContextKey, claims)
			return next(c)
		}
	}
}

func authenticate(c *echo.Context, secret []byte) (*Claims, error) {
	tok := bearerToken(c)
	if tok == "" {
		if ck, err := c.Cookie(AccessCookie); err == nil {
			tok = ck.Value
		}
	}
	if tok == "" {
		return nil, errMissingToken
	}
	return ParseAccessToken(tok, secret)
}

var errMissingToken = errors.New("missing token")

func ClaimsFrom(c *echo.Context) *Claims {
	v := c.Get(ClaimsContextKey)
	if v == nil {
		return nil
	}
	if claims, ok := v.(*Claims); ok {
		return claims
	}
	return nil
}

func bearerToken(c *echo.Context) string {
	h := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
