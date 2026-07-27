package proxy

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

// Trusted-proxy state. torii may itself sit behind an operator's reverse proxy,
// in which case client-facing facts (source IP, request scheme) only survive as
// X-Forwarded-* headers. Those headers are forgeable by anyone who can reach
// torii directly, so they are honored only when the immediate peer is inside
// TRUSTED_PROXY_CIDRS. Both the IP extractor (cmd/ip_extractor.go) and the
// proxy's scheme detection read this one set.
//
// Written once during startup, before the server accepts connections, then
// read-only.
var trustedProxyNets []*net.IPNet

// ParseTrustedCIDRs parses CIDR strings, reporting and skipping invalid entries.
func ParseTrustedCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "[config] ignoring invalid TRUSTED_PROXY_CIDRS entry:", cidr, err)
			continue
		}
		nets = append(nets, n)
	}
	return nets
}

// SetTrustedProxies records the trusted-proxy set. Call once at startup.
func SetTrustedProxies(nets []*net.IPNet) {
	trustedProxyNets = nets
}

// IPIsTrustedProxy reports whether ip falls inside any of nets.
func IPIsTrustedProxy(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// PeerIsTrustedProxy reports whether the request's immediate peer is a
// configured trusted proxy. With no CIDRs configured nothing is trusted, so
// X-Forwarded-* from any client is ignored.
func PeerIsTrustedProxy(r *http.Request) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return IPIsTrustedProxy(ip, trustedProxyNets)
}
