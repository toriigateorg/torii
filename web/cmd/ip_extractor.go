package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
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
func configureIPExtractor(e *echo.Echo, trustedCIDRs []string) {
	nets := make([]*net.IPNet, 0, len(trustedCIDRs))
	for _, cidr := range trustedCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[config] ignoring invalid TRUSTED_PROXY_CIDRS entry:", cidr, err)
			continue
		}
		nets = append(nets, n)
	}
	e.IPExtractor = func(r *http.Request) string {
		direct, _, _ := net.SplitHostPort(r.RemoteAddr)
		directIP := net.ParseIP(direct)
		// Only honor X-Forwarded-For / X-Real-Ip when the direct peer is a
		// trusted reverse proxy. Otherwise return the direct peer.
		if directIP != nil && peerIsTrusted(directIP, nets) {
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
					if !peerIsTrusted(ip, nets) {
						return ip.String()
					}
				}
				// Entire chain is trusted: take the leftmost.
				if first := strings.TrimSpace(parts[0]); first != "" {
					return first
				}
			}
			if real := strings.TrimSpace(r.Header.Get("X-Real-Ip")); real != "" {
				return real
			}
		}
		if directIP != nil {
			return directIP.String()
		}
		return r.RemoteAddr
	}
}

func peerIsTrusted(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
