package auth

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

const ClaimsContextKey = "claims"

func RequireUser(secret []byte) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			tok := bearerToken(c)
			if tok == "" {
				if ck, err := c.Cookie(AccessCookie); err == nil {
					tok = ck.Value
				}
			}
			if tok == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			claims, err := ParseAccessToken(tok, secret)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			c.Set(ClaimsContextKey, claims)
			return next(c)
		}
	}
}

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
