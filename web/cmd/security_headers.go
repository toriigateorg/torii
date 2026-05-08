package cmd

import (
	"github.com/labstack/echo/v5"

	"torii/internal/config"
)

// securityHeaders attaches a baseline set of browser security headers to
// every torii-served response. Proxied responses (those answered by
// proxy.ProxyTo on a service host) are skipped so the upstream's own header
// policy isn't clobbered — the cookie-stripping in the proxy director is the
// load-bearing defense for those.
//
// CSP is intentionally omitted here. The SPA and the upstream-injected
// overlay both require inline-script support today; tightening that will be
// done as a follow-up that also moves the overlay to an external script with
// SRI so a strict default-src 'self' policy can be applied.
func securityHeaders(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg == nil || !cfg.IsToriiHost(c.Request().Host) {
				return next(c)
			}
			h := c.Response().Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			if cfg.IsProd() {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
			return next(c)
		}
	}
}
