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
//   - Named credential-bearing metadata endpoints that match no IP predicate;
//     see metadataAddrs.
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

// IsSafeUpstreamAddr checks an already-resolved socket address ("ip:port", the
// form net.Dialer's Control hook receives) against the same deny set as
// IsSafeUpstreamHost. IsSafeUpstreamHost validates admin input at write time,
// which a DNS rebind can outlive: the proxy re-resolves the hostname on every
// dial, so a record that answered with a public IP during validation can later
// answer 169.254.169.254. This runs at the socket, after resolution, so there
// is no window between the check and the connect.
func IsSafeUpstreamAddr(address string, blockLoopback bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unparseable address %q", ErrUnsafeAddress, address)
	}
	if reason := unsafeReason(ip, blockLoopback); reason != "" {
		return fmt.Errorf("%w: %s (%s)", ErrUnsafeAddress, ip, reason)
	}
	return nil
}

// imdsIPv6Net is fd00:ec2::/32, which holds fd00:ec2::254 — the IPv6 endpoint
// of the AWS instance metadata service. It sits inside ULA (fc00::/7), which
// torii allows on purpose because that's where legitimate internal upstreams
// live, so it has to be denied explicitly.
//
// nat64WellKnownNet is 64:ff9b::/96 (RFC 6052). On a NAT64 network the last
// four bytes are an embedded IPv4 address the packet is translated to, so
// 64:ff9b::a9fe:a9fe reaches 169.254.169.254. To4 does not decode this form,
// so without unwrapping it the v4 deny set never sees the real destination.
var (
	imdsIPv6Net       = mustCIDR("fd00:ec2::/32")
	nat64WellKnownNet = mustCIDR("64:ff9b::/96")
)

// metadataAddrs are credential-bearing instance-metadata endpoints that fall
// outside every net.IP predicate, so neither the link-local nor the private
// checks reach them. Each has to be named.
//
// 100.100.100.200 is Alibaba Cloud's metadata service. It sits in CGNAT
// (100.64.0.0/10, RFC 6598), which is neither link-local nor private as far as
// Go is concerned, so it passed both the write-time and the dial-time guard and
// served instance RAM role credentials to anyone who could point a service at
// it.
//
// Deliberately excluded: Azure's WireServer (168.63.129.16) serves goal state
// rather than credentials, and Oracle Classic's 192.0.0.192 is retired. Neither
// is worth the false-positive risk of denying a real upstream.
var metadataAddrs = map[string]string{
	"100.100.100.200": "alibaba cloud metadata service",
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("netutil: bad CIDR " + s)
	}
	return n
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
	case imdsIPv6Net.Contains(ip):
		return "cloud metadata over IPv6"
	}
	// Keyed on the canonical string form so a v4-mapped v6 spelling
	// (::ffff:100.100.100.200) resolves to the same entry.
	if v4 := ip.To4(); v4 != nil {
		if reason, denied := metadataAddrs[v4.String()]; denied {
			return reason
		}
	}
	// NAT64-embedded IPv4: re-run the deny set against the address the packet
	// is actually translated to. Only for real v6 forms — To4 already handles
	// ::ffff:0:0/96 IPv4-mapped addresses.
	if ip.To4() == nil && nat64WellKnownNet.Contains(ip) {
		if v6 := ip.To16(); v6 != nil {
			embedded := net.IPv4(v6[12], v6[13], v6[14], v6[15])
			if reason := unsafeReason(embedded, blockLoopback); reason != "" {
				return reason + ", NAT64-embedded " + embedded.String()
			}
		}
	}
	return ""
}
