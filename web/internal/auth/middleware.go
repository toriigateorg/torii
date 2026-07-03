package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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

// ServiceTokenResolver resolves a `torii_sat_...` plaintext token belonging to
// a Service API user. Subject = api_user UUID string, Permissions empty (so it
// can never satisfy a permission gate), RoleIDs populated for proxy RBAC.
type ServiceTokenResolver func(ctx context.Context, raw string) (*Claims, error)

var serviceTokenResolver ServiceTokenResolver

func SetServiceTokenResolver(r ServiceTokenResolver) { serviceTokenResolver = r }

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

// credentialPolicy describes where a caller accepts a torii credential and
// which token types are valid there. Each token type has exactly one valid
// header (single-home rule):
//
//   - control-plane (X-Torii-Authorization): session JWTs and torii_pat_
//     personal tokens — the caller acts as a full torii user.
//   - proxy dispatch (X-Torii-Service-Token): torii_sat_ service tokens only.
//
// `Authorization` is never read on either path — on service hosts it belongs to
// the upstream and is forwarded untouched. The access cookie (always a session
// JWT set by torii) is accepted on both paths, subject to the CSRF gate.
type credentialPolicy struct {
	header                  string // header the torii credential is read from
	allowServiceToken       bool   // accept torii_sat_ in header (proxy only)
	allowUserToken          bool   // accept torii_pat_ / JWT in header (control-plane only)
	allowCookieIfSameOrigin bool   // accept the cookie on same-origin state-changing requests
}

var controlPlanePolicy = credentialPolicy{
	header:         AuthorizationHeader,
	allowUserToken: true,
}

var proxyPolicy = credentialPolicy{
	header:                  ServiceTokenHeader,
	allowServiceToken:       true,
	allowCookieIfSameOrigin: true,
}

func authenticate(c *echo.Context, secret []byte) (*Claims, error) {
	return authenticateWith(c, secret, controlPlanePolicy)
}

// authenticateWith authenticates a request against a credentialPolicy: a torii
// credential in the policy's header, or the access cookie. The token type must
// match the header (a torii_sat_ in X-Torii-Authorization, or a torii_pat_ / JWT
// in X-Torii-Service-Token, is rejected) so each credential has a single valid
// channel and a misplaced one is never silently honored.
func authenticateWith(c *echo.Context, secret []byte, pol credentialPolicy) (*Claims, error) {
	if h := strings.TrimSpace(c.Request().Header.Get(pol.header)); h != "" {
		switch {
		case IsServiceAPIToken(h):
			if !pol.allowServiceToken || serviceTokenResolver == nil {
				return nil, errMissingToken
			}
			return serviceTokenResolver(c.Request().Context(), h)
		case IsAPIToken(h):
			if !pol.allowUserToken || apiTokenResolver == nil {
				return nil, errMissingToken
			}
			return apiTokenResolver(c.Request().Context(), h)
		default: // a session JWT
			if !pol.allowUserToken {
				return nil, errMissingToken
			}
			return ParseAccessToken(h, secret)
		}
	}

	// No header credential: fall back to the access cookie, which torii only
	// ever sets to a session JWT.
	//
	// CSRF defense: state-changing methods may not authenticate by cookie.
	// SameSite=Lax blocks cross-site cookie sends on cross-origin XHR but a
	// top-level form POST still rides along — without this gate, any future
	// endpoint accepting a non-JSON body would be CSRF-able. The SPA always
	// carries the credential in X-Torii-Authorization; the cookie is a hydration
	// aid for the proxy dispatch on service domains, allowed here only when the
	// request is provably same-origin.
	if isStateChanging(c.Request().Method) && !isCookieAllowedPath(c.Request().URL.Path) {
		if !(pol.allowCookieIfSameOrigin && isSameOrigin(c.Request())) {
			return nil, errMissingToken
		}
	}
	ck, err := c.Cookie(AccessCookie)
	if err != nil || ck.Value == "" {
		return nil, errMissingToken
	}
	return ParseAccessToken(ck.Value, secret)
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
	return path == "/_torii/api/v1/logout"
}

var errMissingToken = errors.New("missing token")

func ValidAccessToken(c *echo.Context, secret []byte) bool {
	_, err := authenticate(c, secret)
	return err == nil
}

func ClaimsFromRequest(c *echo.Context, secret []byte) (*Claims, error) {
	return authenticate(c, secret)
}

// ClaimsFromProxyRequest is used by the reverse-proxy dispatch for requests
// targeted at configured service domains. It does not read `Authorization`
// (that header is forwarded untouched to the upstream); the torii credential is
// taken from the access cookie or a torii_sat_ service token in the
// X-Torii-Service-Token header. It accepts the access cookie on state-changing
// methods provided the request is same-origin (Origin or Referer host matches
// the request Host), so apps running on those domains can authenticate their
// own XHRs from the host-scoped cookie alone.
func ClaimsFromProxyRequest(c *echo.Context, secret []byte) (*Claims, error) {
	return authenticateWith(c, secret, proxyPolicy)
}

// isSameOrigin reports whether the request's Origin (or Referer, when Origin
// is absent) refers to the same host as the request itself. Used to gate
// cookie-based auth on state-changing requests to proxied service domains.
// A cross-site attacker cannot forge either header from a page they control.
func isSameOrigin(r *http.Request) bool {
	host := r.Host
	if host == "" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return false
		}
		return u.Host == host
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err != nil || u.Host == "" {
			return false
		}
		return u.Host == host
	}
	return false
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
