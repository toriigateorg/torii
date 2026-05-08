// Package netutil contains small networking helpers shared across torii.
package netutil

import (
	"errors"
	"fmt"
	"net"
)

// ErrUnsafeAddress is returned when a host resolves to an address class
// that is never a legitimate upstream destination for torii.
var ErrUnsafeAddress = errors.New("address resolves to an unsafe network range")

// IsSafeUpstreamHost resolves host (which may be hostname[:port] or just
// hostname) and returns nil iff every resolved IP is acceptable as a torii
// upstream destination. It is the SSRF guard applied to admin-supplied URLs:
// services.service_url and sso_providers.issuer_url.
//
// Torii's job is to front internal services, so RFC1918 / ULA / loopback are
// legitimate destinations and are NOT blocked by default. What we always
// reject is:
//
//   - Link-local (169.254.0.0/16, fe80::/10) — covers cloud metadata
//     services like 169.254.169.254 (AWS/GCP IMDS) which would otherwise
//     let an authenticated user exfiltrate cloud credentials by routing
//     through torii.
//   - Multicast (224.0.0.0/4, ff00::/8) — not a valid unicast destination.
//   - Unspecified (0.0.0.0, ::) — same.
//
// blockLoopback adds 127.0.0.0/8 and ::1 to the deny set. Off by default
// because co-hosted sidecars on loopback are a normal deployment pattern;
// turn it on if torii binds anything sensitive to localhost.
func IsSafeUpstreamHost(host string, blockLoopback bool) error {
	if host == "" {
		return errors.New("empty host")
	}
	// Strip optional port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("dns lookup: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("no addresses resolved")
	}
	for _, ip := range ips {
		if reason := unsafeReason(ip, blockLoopback); reason != "" {
			return fmt.Errorf("%w: %s (%s)", ErrUnsafeAddress, ip, reason)
		}
	}
	return nil
}

func unsafeReason(ip net.IP, blockLoopback bool) string {
	switch {
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast():
		return "link-local (cloud metadata range)"
	case ip.IsMulticast():
		return "multicast"
	case blockLoopback && ip.IsLoopback():
		return "loopback"
	}
	return ""
}
