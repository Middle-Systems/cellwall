// Package proxy implements the policy-enforcing egress proxy that runs in the gateway container.
package proxy

import (
	"net/netip"
)

// Class says how an address is treated by the SSRF guard.
type Class int

const (
	// ClassPublic addresses are routable global unicast and may be dialed.
	ClassPublic Class = iota
	// ClassPrivate addresses (RFC 1918, CGNAT, ULA, non-metadata link-local) are blocked unless
	// the matching rule sets unsafe_allow_private.
	ClassPrivate
	// ClassHard addresses are never dialed, whatever the rule says: loopback (the gateway's own
	// admin surface), unspecified (connects to localhost on Linux), multicast, reserved ranges,
	// and cloud metadata endpoints.
	ClassHard
)

// Verdict is the guard's decision for one address.
type Verdict struct {
	Class  Class
	Reason string // short stable code, e.g. "loopback", "private", "cloud-metadata"
}

// Blocked reports whether the address may not be dialed given allowPrivate.
func (v Verdict) Blocked(allowPrivate bool) bool {
	switch v.Class {
	case ClassPublic:
		return false
	case ClassPrivate:
		return !allowPrivate
	default:
		return true
	}
}

type rangeEntry struct {
	prefix netip.Prefix
	class  Class
	reason string
}

func entry(cidr string, class Class, reason string) rangeEntry {
	return rangeEntry{netip.MustParsePrefix(cidr), class, reason}
}

// Order matters: the first match wins, so specific entries (metadata) precede the ranges that
// contain them.
var guardTable = []rangeEntry{
	// Cloud metadata endpoints. Some sit in ranges that are otherwise merely "private", and one
	// (Azure's wireserver) is a public address, so they are listed explicitly and hard-blocked.
	entry("169.254.169.254/32", ClassHard, "cloud-metadata"), // AWS, GCP, Azure IMDS, OpenStack, DO
	entry("169.254.170.2/32", ClassHard, "cloud-metadata"),   // AWS ECS task metadata
	entry("100.100.100.200/32", ClassHard, "cloud-metadata"), // Alibaba Cloud
	entry("192.0.0.192/32", ClassHard, "cloud-metadata"),     // Oracle Cloud
	entry("168.63.129.16/32", ClassHard, "cloud-metadata"),   // Azure wireserver
	entry("fd00:ec2::254/128", ClassHard, "cloud-metadata"),  // AWS IMDS over IPv6
	entry("fd20:ce::254/128", ClassHard, "cloud-metadata"),   // GCP IMDS over IPv6

	// IPv4
	entry("0.0.0.0/8", ClassHard, "unspecified"),
	entry("127.0.0.0/8", ClassHard, "loopback"),
	entry("224.0.0.0/4", ClassHard, "multicast"),
	entry("240.0.0.0/4", ClassHard, "reserved"), // includes 255.255.255.255
	entry("10.0.0.0/8", ClassPrivate, "private"),
	entry("172.16.0.0/12", ClassPrivate, "private"),
	entry("192.168.0.0/16", ClassPrivate, "private"),
	entry("100.64.0.0/10", ClassPrivate, "cgnat"),
	entry("169.254.0.0/16", ClassPrivate, "link-local"),
	entry("192.0.0.0/24", ClassHard, "reserved"), // IETF protocol assignments
	entry("192.0.2.0/24", ClassHard, "documentation"),
	entry("198.51.100.0/24", ClassHard, "documentation"),
	entry("203.0.113.0/24", ClassHard, "documentation"),
	entry("198.18.0.0/15", ClassHard, "benchmarking"),
	entry("192.88.99.0/24", ClassHard, "reserved"), // deprecated 6to4 relay anycast

	// IPv6
	entry("::/128", ClassHard, "unspecified"),
	entry("::1/128", ClassHard, "loopback"),
	entry("ff00::/8", ClassHard, "multicast"),
	entry("::/96", ClassHard, "reserved"), // IPv4-compatible, deprecated
	entry("100::/64", ClassHard, "reserved"),
	entry("2001::/32", ClassHard, "reserved"), // Teredo
	entry("2001:2::/48", ClassHard, "benchmarking"),
	entry("2001:db8::/32", ClassHard, "documentation"),
	entry("3fff::/20", ClassHard, "documentation"),
	entry("2001:10::/28", ClassHard, "reserved"),
	entry("5f00::/16", ClassHard, "reserved"),
	entry("64:ff9b:1::/48", ClassHard, "reserved"), // local-use NAT64
	entry("fc00::/7", ClassPrivate, "private"),     // ULA
	entry("fe80::/10", ClassPrivate, "link-local"),
	entry("fec0::/10", ClassPrivate, "private"), // deprecated site-local
}

// Classify returns the guard's verdict for an address. Anything that is not clearly public global
// unicast is not public: the guard is allowlist-shaped at the end, so a range this table forgot is
// still refused unless Go itself considers it global unicast.
func Classify(a netip.Addr) Verdict {
	if !a.IsValid() {
		return Verdict{ClassHard, "invalid"}
	}
	a = a.WithZone("").Unmap() // IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged as the IPv4 address

	// Addresses that embed an IPv4 address take the stricter of the outer and embedded verdicts:
	// 64:ff9b::a00:1 would otherwise smuggle 10.0.0.1 past a v6 check.
	if inner, ok := embeddedIPv4(a); ok {
		if v := Classify(inner); v.Class != ClassPublic {
			return Verdict{v.Class, "embedded-" + v.Reason}
		}
	}
	for _, e := range guardTable {
		if e.prefix.Contains(a) {
			return Verdict{e.class, e.reason}
		}
	}
	if !a.IsGlobalUnicast() {
		return Verdict{ClassHard, "non-global"}
	}
	return Verdict{ClassPublic, ""}
}

// embeddedIPv4 extracts an IPv4 address carried inside an IPv6 one by a translation or tunnelling
// scheme: NAT64 (64:ff9b::/96), 6to4 (2002::/16) and ISATAP (…:0:5efe:a.b.c.d).
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && allZero(b[4:12]): // 64:ff9b::/96
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case b[0] == 0x20 && b[1] == 0x02: // 2002::/16, IPv4 in bytes 2-5
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	case (b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5e && b[11] == 0xfe: // ISATAP
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
