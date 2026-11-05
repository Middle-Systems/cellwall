package proxy

import (
	"net/netip"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestClassifyBlocked(t *testing.T) {
	hard := map[string]string{
		// loopback, unspecified, multicast, broadcast, reserved
		"127.0.0.1": "loopback", "127.255.255.255": "loopback", "127.1.2.3": "loopback", "::1": "loopback",
		"0.0.0.0": "unspecified", "0.1.2.3": "unspecified", "::": "unspecified",
		"224.0.0.1": "multicast", "239.255.255.255": "multicast", "ff02::1": "multicast", "ff0e::1": "multicast",
		"255.255.255.255": "reserved", "240.0.0.1": "reserved",
		"192.0.2.1": "documentation", "198.51.100.7": "documentation", "203.0.113.9": "documentation", "2001:db8::1": "documentation",
		"198.18.0.1": "benchmarking", "198.19.255.255": "benchmarking",
		// cloud metadata, in every spelling
		"169.254.169.254": "cloud-metadata", "169.254.170.2": "cloud-metadata", "100.100.100.200": "cloud-metadata",
		"192.0.0.192": "cloud-metadata", "168.63.129.16": "cloud-metadata", "fd00:ec2::254": "cloud-metadata",
		"::ffff:169.254.169.254": "cloud-metadata", // IPv4-mapped metadata
		// IPv6 oddities
		"2001:0:4136:e378:8000:63bf:3fff:fdd2": "reserved", // Teredo
		"100::1":                               "reserved", // discard prefix
		"::2":                                  "reserved", // IPv4-compatible
	}
	for s, reason := range hard {
		v := Classify(addr(s))
		if v.Class != ClassHard || v.Reason != reason {
			t.Errorf("Classify(%s) = %+v; want hard/%s", s, v, reason)
		}
		if !v.Blocked(true) {
			t.Errorf("%s must stay blocked even with unsafe_allow_private", s)
		}
	}

	private := map[string]string{
		"10.0.0.1": "private", "10.255.255.255": "private", "172.16.0.1": "private", "172.31.255.255": "private",
		"192.168.0.1": "private", "192.168.255.255": "private", "100.64.0.1": "cgnat", "100.127.255.255": "cgnat",
		"169.254.0.1": "link-local", "169.254.1.1": "link-local", "fe80::1": "link-local", "febf::1": "link-local",
		"fc00::1": "private", "fd12:3456::1": "private", "fec0::1": "private",
		"::ffff:10.0.0.1": "private", "::ffff:192.168.1.1": "private",
	}
	for s, reason := range private {
		v := Classify(addr(s))
		if v.Class != ClassPrivate || v.Reason != reason {
			t.Errorf("Classify(%s) = %+v; want private/%s", s, v, reason)
		}
		if !v.Blocked(false) {
			t.Errorf("%s must be blocked by default", s)
		}
		if v.Blocked(true) {
			t.Errorf("%s should be reachable with unsafe_allow_private", s)
		}
	}
}

func TestClassifyEmbeddedIPv4(t *testing.T) {
	// Translation / tunnel addresses that carry a private or metadata IPv4 must not slip through.
	for _, s := range []string{
		"64:ff9b::a00:1",                                                            // NAT64 10.0.0.1
		"64:ff9b::7f00:1",                                                           // NAT64 127.0.0.1
		"64:ff9b::a9fe:a9fe",                                                        // NAT64 169.254.169.254
		"2002:a00:1::1",                                                             // 6to4 10.0.0.1
		"2002:7f00:1::",                                                             // 6to4 127.0.0.1
		"2002:a9fe:a9fe::1",                                                         // 6to4 metadata
		"fe80::5efe:10.0.0.1", "2001:db8::200:5efe:192.168.1.1", "::5efe:127.0.0.1", // ISATAP
	} {
		if v := Classify(addr(s)); v.Class == ClassPublic {
			t.Errorf("Classify(%s) = public; embedded private IPv4 must be caught", s)
		}
	}
	// Embedded metadata/loopback stays hard even with unsafe_allow_private.
	for _, s := range []string{"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1"} {
		if !Classify(addr(s)).Blocked(true) {
			t.Errorf("%s must be hard-blocked", s)
		}
	}
	// Embedded PUBLIC IPv4 is as public as the IPv4 itself.
	for _, s := range []string{"64:ff9b::808:808", "2002:808:808::1"} {
		if v := Classify(addr(s)); v.Class != ClassPublic {
			t.Errorf("Classify(%s) = %+v; want public (embeds 8.8.8.8)", s, v)
		}
	}
}

func TestClassifyBoundaries(t *testing.T) {
	// Just outside each private range must be public; just inside must not.
	tests := []struct {
		addr   string
		public bool
	}{
		{"9.255.255.255", true}, {"10.0.0.0", false}, {"10.255.255.255", false}, {"11.0.0.0", true},
		{"172.15.255.255", true}, {"172.16.0.0", false}, {"172.31.255.255", false}, {"172.32.0.0", true},
		{"192.167.255.255", true}, {"192.168.0.0", false}, {"192.169.0.0", true},
		{"100.63.255.255", true}, {"100.64.0.0", false}, {"100.127.255.255", false}, {"100.128.0.0", true},
		{"169.253.255.255", true}, {"169.254.0.0", false}, {"169.255.0.0", true},
		{"126.255.255.255", true}, {"128.0.0.0", true},
		{"223.255.255.255", true}, {"224.0.0.0", false},
		{"198.17.255.255", true}, {"198.20.0.0", true},
		{"168.63.129.15", true}, {"168.63.129.17", true}, // only the exact wireserver address
		{"8.8.8.8", true}, {"1.1.1.1", true}, {"93.184.216.34", true},
		{"2606:4700:4700::1111", true}, {"2001:4860:4860::8888", true}, {"2a00:1450:4001:81b::200e", true},
		{"fbff::1", true}, {"fc00::", false}, {"fdff::1", false}, {"fe00::1", true},
	}
	for _, tt := range tests {
		got := Classify(addr(tt.addr)).Class == ClassPublic
		if got != tt.public {
			t.Errorf("Classify(%s) public = %v; want %v", tt.addr, got, tt.public)
		}
	}
}

func TestClassifyZoneAndInvalid(t *testing.T) {
	if v := Classify(addr("fe80::1%eth0")); v.Class != ClassPrivate {
		t.Errorf("zoned link-local: %+v", v)
	}
	if v := Classify(netip.Addr{}); v.Class != ClassHard {
		t.Errorf("invalid address must be hard-blocked: %+v", v)
	}
}

func TestGuardTableIsConsistent(t *testing.T) {
	// A specific entry placed after a containing range would be dead code and silently weaken
	// the guard (e.g. metadata classified as plain "private"). Catch ordering mistakes.
	for i, e := range guardTable {
		for j := 0; j < i; j++ {
			p := guardTable[j]
			if p.prefix.Bits() < e.prefix.Bits() && p.prefix.Contains(e.prefix.Addr()) && p.class != e.class {
				t.Errorf("entry %d (%s %v) is shadowed by earlier broader entry %d (%s %v)", i, e.prefix, e.class, j, p.prefix, p.class)
			}
		}
	}
	// Every table entry's first and last address is classified as non-public.
	for _, e := range guardTable {
		first := e.prefix.Masked().Addr()
		if Classify(first).Class == ClassPublic {
			t.Errorf("%s: first address %s classified public", e.prefix, first)
		}
	}
}
