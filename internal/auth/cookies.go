package auth

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

const (
	AccessCookie  = "access_token"
	RefreshCookie = "refresh_token"

	refreshCookiePath = "/api/v1/"
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
}
