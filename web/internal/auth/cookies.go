package auth

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

const (
	AccessCookie  = "access_token"
	RefreshCookie = "refresh_token"
	// SessionCookie is a non-secret marker cookie at Path=/ that lives as long
	// as the refresh token. The refresh cookie itself is scoped to
	// /_torii/api/v1/ so it doesn't leak to upstream services on proxied
	// hosts; dispatch uses this marker's presence on service paths to decide
	// whether to bounce a navigation through /_torii/api/v1/refresh_and_redirect
	// or to /_torii/signin.
	SessionCookie = "torii_session"

	// accessCookiePath stays "/" so the cookie rides along on requests to
	// proxied service paths, letting dispatch authenticate the user via the
	// cookie alone. proxy/service.go strips the cookie before forwarding so
	// it never reaches the upstream — the host is the trust boundary.
	accessCookiePath = "/"
	// refreshCookiePath narrows the refresh cookie even further so it only
	// rides along on the auth endpoints that consume it. dispatch's 302 to
	// /_torii/api/v1/refresh_and_redirect is what makes cross-host refresh
	// work despite this tight scope.
	refreshCookiePath = "/_torii/api/v1/"
)

func SetAccessCookie(c *echo.Context, token string, ttl time.Duration, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     AccessCookie,
		Value:    token,
		Path:     accessCookiePath,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func SetRefreshCookie(c *echo.Context, token string, ttl time.Duration, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     RefreshCookie,
		Value:    token,
		Path:     refreshCookiePath,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	// Marker cookie at Path=/ so dispatch can detect "session refresh might
	// succeed" on requests that don't carry the path-scoped refresh cookie.
	// HttpOnly is fine — only the server side needs to read it.
	c.SetCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    "1",
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func ClearAuthCookies(c *echo.Context, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     AccessCookie,
		Value:    "",
		Path:     accessCookiePath,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     RefreshCookie,
		Value:    "",
		Path:     refreshCookiePath,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	c.SetCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
