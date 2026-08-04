package cmd

import (
	"strings"

	"github.com/labstack/echo/v5"

	"torii/internal/config"
)

// securityHeaders attaches a baseline set of browser security headers to
// every torii-served response. Routes under /_torii/* are torii's own
// surfaces; proxied responses (answered by proxy.ProxyTo on a service host)
// are skipped so the upstream's own header policy isn't clobbered — the
// cookie-stripping in the proxy director is the load-bearing defense there.
//
// The CSP applies to torii's own pages only, for the same reason: a policy on a
// proxied response would govern the upstream's document, not torii's.
//
// 'unsafe-inline' for script-src is unavoidable today — web.Handler splices an
// inline <script> carrying window.__TORII_URL__ into every document, and the
// upstream overlay is inline too. It is still worth emitting: the directives that
// do bite are the ones that matter for the credential form. form-action 'self'
// keeps a sign-in POST from being retargeted, frame-ancestors 'none' backs up
// X-Frame-Options, and base-uri 'none' stops an injected <base> from re-pointing
// every relative fetch the SPA makes. Moving the injection to a nonce is the
// follow-up that lets 'unsafe-inline' go.
// toriiCSP governs torii's own /_torii* responses.
//
// font-src and style-src admit fonts.googleapis.com / fonts.gstatic.com because
// the shipped bundle loads a webfont from there. Self-hosting the font would let
// both collapse to 'self' and is the better answer.
const toriiCSP = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src 'self' data: https://fonts.gstatic.com; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'; " +
	"object-src 'none'"

func securityHeaders(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			path := c.Request().URL.Path
			if path != "/_torii" && !strings.HasPrefix(path, "/_torii/") {
				return next(c)
			}
			h := c.Response().Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Content-Security-Policy", toriiCSP)
			// The handoff page carries a live session-minting token in its
			// fragment. Fragments aren't sent in a Referer, but the page also
			// hard-navigates into proxied upstream paths right after, so pin
			// it to no-referrer and keep it out of caches.
			if path == "/_torii/handoff" {
				h.Set("Referrer-Policy", "no-referrer")
				h.Set("Cache-Control", "no-store")
			} else {
				h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			}
			if cfg != nil && cfg.IsProd() {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			}
			return next(c)
		}
	}
}
