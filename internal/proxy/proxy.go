package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/labstack/echo/v5"
)

// Nuxt forwards every request that wasn't matched by the API to the Nuxt
// dev server on http://127.0.0.1:3000. The standard library reverse proxy
// already handles WebSocket upgrades (used by Nuxt HMR) when the Connection
// and Upgrade headers are preserved, which they are by default.
func Nuxt() echo.HandlerFunc {
	target, _ := url.Parse("http://127.0.0.1:3000")
	rp := httputil.NewSingleHostReverseProxy(target)

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
	}

	return func(c *echo.Context) error {
		rp.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}
