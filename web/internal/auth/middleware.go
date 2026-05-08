package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

const ClaimsContextKey = "claims"

// APITokenResolver resolves a `torii_pat_...` plaintext token to a Claims
// value (subject = user UUID string, permissions populated). It is wired in
// at server startup by the api package so this package doesn't need to depend
// on db / sqlc-generated code.
type APITokenResolver func(ctx context.Context, raw string) (*Claims, error)

var apiTokenResolver APITokenResolver

func SetAPITokenResolver(r APITokenResolver) { apiTokenResolver = r }

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
		// CSRF defense: state-changing methods must carry a Bearer token.
		// SameSite=Lax blocks cross-site cookie sends on cross-origin XHR
		// but a top-level form POST still rides along — without this gate,
		// any future endpoint accepting a non-JSON body would be CSRF-able.
		// The SPA always sends Bearer via useAuth().authHeaders(); the
		// cookie is purely a hydration aid for the proxy dispatch on
		// service domains (read-only navigations).
		if isStateChanging(c.Request().Method) && !isCookieAllowedPath(c.Request().URL.Path) {
			return nil, errMissingToken
		}
		if ck, err := c.Cookie(AccessCookie); err == nil {
			tok = ck.Value
		}
	}
	if tok == "" {
		return nil, errMissingToken
	}
	if IsAPIToken(tok) {
		if apiTokenResolver == nil {
			return nil, errors.New("api tokens not enabled")
		}
		return apiTokenResolver(c.Request().Context(), tok)
	}
	return ParseAccessToken(tok, secret)
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// isCookieAllowedPath lists endpoints that legitimately authenticate via the
// access cookie alone, even on state-changing methods. /logout must succeed
// even if the SPA's in-memory token was lost (idempotent cleanup).
func isCookieAllowedPath(path string) bool {
	return path == "/api/v1/logout"
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
