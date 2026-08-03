package cmd

import (
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"torii/internal/proxy"
)

// configureIPExtractor wires Echo's RealIP() to honor X-Forwarded-For only
// when the immediate peer is in the trusted-proxy CIDR list. Without this,
// Echo's default RealIP trusts XFF from any caller, which lets clients
// spoof their IP in audit logs and rate-limit keys.
//
// We don't use echo.ExtractIPFromXFFHeader directly because we want to drive
// the trust set entirely from config CIDRs rather than the broad
// TrustPrivateNet/TrustLoopback toggles — keeps the deployment story
// explicit ("torii's reverse proxy is at 10.0.1.5/32" reads better than
// "trust all of RFC1918").
func configureIPExtractor(e *echo.Echo, nets []*net.IPNet) {
	e.IPExtractor = func(r *http.Request) string {
		direct, _, _ := net.SplitHostPort(r.RemoteAddr)
		directIP := net.ParseIP(direct)
		// Only honor X-Forwarded-For / X-Real-Ip when the direct peer is a
		// trusted reverse proxy. Otherwise return the direct peer.
		if directIP != nil && proxy.IPIsTrustedProxy(directIP, nets) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// XFF can be a chain "client, proxy1, proxy2" — leftmost
				// is the original client. Walk from the right discarding
				// trusted proxies, then take the next one as the client.
				parts := strings.Split(xff, ",")
				for i := len(parts) - 1; i >= 0; i-- {
					ip := net.ParseIP(strings.TrimSpace(parts[i]))
					if ip == nil {
						continue
					}
					if !proxy.IPIsTrustedProxy(ip, nets) {
						return ip.String()
					}
				}
				// Entire chain is trusted: take the leftmost. Parsed, not
				// returned raw — see below.
				if ip := net.ParseIP(strings.TrimSpace(parts[0])); ip != nil {
					return ip.String()
				}
			}
			// Parse before returning. These two paths used to hand back the
			// header string verbatim, so any value at all became the rate-limit
			// key and the recorded client address: a fresh string per request
			// meant a fresh token bucket per request, which removes the only
			// rate limits torii has and re-opens unbounded argon2 work. Parsing
			// also normalises, so "::ffff:1.2.3.4" and "1.2.3.4" cannot hold two
			// separate buckets.
			if real := strings.TrimSpace(r.Header.Get("X-Real-Ip")); real != "" {
				if ip := net.ParseIP(real); ip != nil {
					return ip.String()
				}
			}
		}
		if directIP != nil {
			return directIP.String()
		}
		return r.RemoteAddr
	}
}
