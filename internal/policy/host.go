package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Hostname limits per RFC 1035. Request-side limits are configurable (Limits.MaxLabelLen /
// MaxHostLen) but can never exceed these: a longer name is not a valid DNS name at all.
const (
	MaxLabelLen = 63
	MaxHostLen  = 253
)

// HostError describes why a hostname was rejected. Code is stable and used in audit records.
type HostError struct {
	Code string
	Msg  string
}

func (e *HostError) Error() string { return e.Msg }

// Host error codes.
const (
	HostEmpty        = "host-empty"
	HostTooLong      = "host-too-long"
	HostLabelTooLong = "label-too-long"
	HostEmptyLabel   = "empty-label"
	HostBadChar      = "bad-char"
	HostNonASCII     = "non-ascii"
	HostBadHyphen    = "bad-hyphen"
	HostIPLiteral    = "ip-literal"
)

// NormalizeHost lowercases a hostname, strips exactly one trailing dot, and validates it as a
// strict LDH (letters, digits, hyphen) DNS name. maxHost and maxLabel of 0 mean the RFC limits.
//
// It deliberately does NOT perform IDNA conversion: a non-ASCII name is rejected rather than
// silently rewritten, because a silent rewrite is exactly the kind of normalization difference
// attackers use to slip past an allowlist. Callers must supply the punycode (xn--) form.
// Underscores are rejected too: they are not valid in hostnames and only show up in
// non-host DNS records.
func NormalizeHost(s string, maxHost, maxLabel int) (string, error) {
	if maxHost <= 0 || maxHost > MaxHostLen {
		maxHost = MaxHostLen
	}
	if maxLabel <= 0 || maxLabel > MaxLabelLen {
		maxLabel = MaxLabelLen
	}
	if s == "" {
		return "", &HostError{HostEmpty, "hostname is empty"}
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", &HostError{HostNonASCII, "hostname contains non-ASCII characters; use the punycode (xn--) form"}
		}
	}
	// Strip a single trailing dot (the DNS root); "a.." stays invalid via the empty-label check.
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", &HostError{HostEmpty, "hostname is empty"}
	}
	s = strings.ToLower(s)
	if len(s) > maxHost {
		return "", &HostError{HostTooLong, fmt.Sprintf("hostname is %d bytes; the limit is %d", len(s), maxHost)}
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			continue
		}
		label := s[start:i]
		if label == "" {
			return "", &HostError{HostEmptyLabel, "hostname has an empty label"}
		}
		if len(label) > maxLabel {
			return "", &HostError{HostLabelTooLong, fmt.Sprintf("hostname label is %d bytes; the limit is %d", len(label), maxLabel)}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", &HostError{HostBadHyphen, "hostname label starts or ends with a hyphen"}
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			if !isLDH(c) {
				return "", &HostError{HostBadChar, fmt.Sprintf("hostname contains invalid character %q", c)}
			}
		}
		start = i + 1
	}
	return s, nil
}

// isLDH reports whether c is a lowercase letter, digit or hyphen.
func isLDH(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

// LooksLikeIP reports whether a (normalized or raw) host could be an IP address in ANY of the
// notations resolvers and URL parsers accept: canonical IPv4/IPv6, bracketed IPv6, and the legacy
// shorthand forms (2130706433, 0x7f.1, 127.1, 0177.0.0.1). Matching anything that could be
// interpreted as an address is the point: the proxy refuses IP-literal targets outright.
func LooksLikeIP(host string) bool {
	h := strings.TrimSuffix(host, ".")
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "[") || strings.Contains(h, ":") {
		return true // IPv6 literal (possibly bracketed or zoned); hostnames never contain ':'
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	// A final label that is all digits, or starts with 0x, can never be a real TLD
	// (RFC 3696 section 2) and is how the legacy inet_aton forms are spelled.
	last := h
	if i := strings.LastIndexByte(h, '.'); i >= 0 {
		last = h[i+1:]
	}
	if last == "" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(last), "0x") {
		return true
	}
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	return allDigits
}

// PatternKind is how a rule's host field matches.
type PatternKind int

const (
	// Exact matches the hostname exactly.
	Exact PatternKind = iota
	// SingleLabel is "*.base": exactly one label below base (never base itself).
	SingleLabel
	// MultiLabel is "**.base": one or more labels below base (never base itself).
	MultiLabel
)

func (k PatternKind) String() string {
	switch k {
	case SingleLabel:
		return "single-label wildcard"
	case MultiLabel:
		return "multi-label wildcard"
	default:
		return "exact"
	}
}

// Pattern is a parsed rule host.
type Pattern struct {
	Kind PatternKind
	Base string // normalized hostname; for wildcards, the part after "*." / "**."
}

// String returns the pattern in rule syntax.
func (p Pattern) String() string {
	switch p.Kind {
	case SingleLabel:
		return "*." + p.Base
	case MultiLabel:
		return "**." + p.Base
	default:
		return p.Base
	}
}

// ErrWildcardPosition is returned for wildcards anywhere but as the whole leading label.
var ErrWildcardPosition = errors.New("wildcards are only allowed as the entire leading label (\"*.example.com\" or \"**.example.com\")")

// ParsePattern parses a rule host: "example.com", "*.example.com" or "**.example.com".
func ParsePattern(s string) (Pattern, error) {
	kind := Exact
	rest := s
	switch {
	case strings.HasPrefix(s, "**."):
		kind, rest = MultiLabel, s[3:]
	case strings.HasPrefix(s, "*."):
		kind, rest = SingleLabel, s[2:]
	}
	if strings.Contains(rest, "*") {
		return Pattern{}, ErrWildcardPosition
	}
	if LooksLikeIP(rest) {
		return Pattern{}, &HostError{HostIPLiteral, "IP addresses are not allowed in rules; allow a hostname instead"}
	}
	base, err := NormalizeHost(rest, 0, 0)
	if err != nil {
		return Pattern{}, err
	}
	return Pattern{Kind: kind, Base: base}, nil
}

// Matches reports whether a normalized host matches the pattern.
func (p Pattern) Matches(host string) bool {
	switch p.Kind {
	case Exact:
		return host == p.Base
	case SingleLabel:
		i := strings.IndexByte(host, '.')
		return i > 0 && host[i+1:] == p.Base
	default: // MultiLabel
		return len(host) > len(p.Base)+1 && strings.HasSuffix(host, "."+p.Base)
	}
}
