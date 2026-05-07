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

func RequirePermission(secret []byte, perm string, onDenied func(c *echo.Context, perm string)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims, err := authenticate(c, secret)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			}
			if !claims.Has(perm) {
				c.Set(ClaimsContextKey, claims)
				if onDenied != nil {
					onDenied(c, perm)
				}
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: missing permission " + perm})
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

func ValidAccessToken(c *echo.Context, secret []byte) bool {
	_, err := authenticate(c, secret)
	return err == nil
}

func ClaimsFromRequest(c *echo.Context, secret []byte) (*Claims, error) {
	return authenticate(c, secret)
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
