package auth

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

const (
	AccessCookie  = "access_token"
	RefreshCookie = "refresh_token"
	// SessionCookie is a non-httponly marker cookie at Path=/ that lives as
	// long as the refresh token. It carries no secret — the proxy dispatch
	// uses its presence to decide whether an unauthenticated request on a
	// service domain is worth a refresh-and-redirect attempt or whether the
	// user is genuinely logged out and should fall through to the SPA.
	SessionCookie = "torii_session"

	// refreshCookiePath is "/" so the refresh cookie rides along on every
	// request to the host — including XHRs to proxied service apps. This
	// lets dispatch perform an inline session refresh on any request (not
	// just document GETs we can 302 to /api/v1/refresh_and_redirect).
	// httpOnly + SameSite=Lax + Secure (prod) keep it as safe at "/" as it
	// was at "/api/v1/"; the threat model already trusts the host.
	refreshCookiePath = "/"
)

func SetAccessCookie(c *echo.Context, token string, ttl time.Duration, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     AccessCookie,
		Value:    token,
		Path:     "/",
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
		Path:     "/",
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
