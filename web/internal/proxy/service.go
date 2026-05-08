package proxy

import (
	"net/http"
	"net/http/httputil"

	"github.com/labstack/echo/v5"
)

// ProxyTo reverse-proxies the request to the cached service's target,
// preserving the upstream Host and applying the per-service header
// overrides on top of the client's headers.
func ProxyTo(svc *CachedService, c *echo.Context) error {
	rp := httputil.NewSingleHostReverseProxy(svc.Target)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = svc.Target.Host
		// Disable upstream compression so we can splice the sanmon
		// overlay into HTML responses without having to decode gzip/br.
		req.Header.Del("Accept-Encoding")
		for k, v := range svc.Headers {
			req.Header.Set(k, v)
		}
	}
	rp.ModifyResponse = injectOverlay
	rp.ServeHTTP(c.Response(), c.Request())
	return nil
}
