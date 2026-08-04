package proxy

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
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

// warnUntrustedForwardedOnce fires the first time a request arrives carrying
// X-Forwarded-For from a peer torii does not trust. That combination means
// something in front of torii believes it is a reverse proxy while torii does
// not, which silently collapses every per-IP rate limiter and every audit
// source-IP into the one address of that hop. A startup warning cannot detect
// it (an unset CIDR list is legitimate for a directly-exposed torii); only a
// live request can.
var warnUntrustedForwardedOnce sync.Once

// WarnOnMisconfiguredTrust reports the peer/XFF mismatch described above, once
// per process, naming the peer so the operator can paste it into
// TRUSTED_PROXY_CIDRS.
func WarnOnMisconfiguredTrust(r *http.Request) {
	if r.Header.Get("X-Forwarded-For") == "" || PeerIsTrustedProxy(r) {
		return
	}
	warnUntrustedForwardedOnce.Do(func() {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		fmt.Fprintf(os.Stderr, "[trust] WARNING: request from %s carried X-Forwarded-For but that peer is not in TRUSTED_PROXY_CIDRS. "+
			"Every client is being attributed to %s, so per-IP rate limits and audit source IPs are meaningless. "+
			"Set TRUSTED_PROXY_CIDRS to the CIDR containing %s if it is your reverse proxy.\n", host, host, host)
	})
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
