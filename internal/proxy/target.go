package proxy

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

const maxTargetLen = 300

// TargetError describes a malformed CONNECT target.
type TargetError struct{ Msg string }

func (e *TargetError) Error() string { return e.Msg }

// ParseConnectTarget parses the authority-form request target of a CONNECT ("host:port" or
// "[v6]:port") strictly: no scheme, path, userinfo, whitespace or control characters, and the
// port must be a plain decimal in 1-65535. The host is returned as written; the caller normalizes
// and checks it.
func ParseConnectTarget(s string) (host string, port int, err error) {
	if s == "" || len(s) > maxTargetLen {
		return "", 0, &TargetError{"CONNECT target is empty or too long"}
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f {
			return "", 0, &TargetError{"CONNECT target contains whitespace, control or non-ASCII characters"}
		}
	}
	if strings.ContainsAny(s, "/@?#\\") {
		return "", 0, &TargetError{"CONNECT target must be host:port (no scheme, path or userinfo)"}
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil || h == "" {
		return "", 0, &TargetError{"CONNECT target must be host:port"}
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return "", 0, &TargetError{"CONNECT port must be a decimal number"}
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, &TargetError{"CONNECT port must be between 1 and 65535"}
	}
	return h, n, nil
}

// Suspicious flags a hostname that looks like data rather than a name: a long run of characters
// with high entropy and a data-like shape (hex, base32 or base64 payloads). It is a heuristic for
// the audit log (suspicious=true) and for the optional deny_suspicious limit; it is not a
// security boundary, and it is tuned for precision: a flag that fires on ordinary names such as
// "browser-intake-us5-datadoghq" would teach people to ignore it.
//
// Hyphen-separated words are judged separately (real names are made of short words; encoded data
// is one long run), and entropy alone is not enough because plain English already scores
// 3.5-4 bits per character. A segment must also contain many digits, or almost no vowels.
func Suspicious(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if len(label) < minSuspiciousRun {
			continue
		}
		for _, seg := range strings.Split(label, "-") {
			if looksLikeData(seg) {
				return true
			}
		}
	}
	return false
}

const minSuspiciousRun = 16

func looksLikeData(seg string) bool {
	if len(seg) < minSuspiciousRun {
		return false
	}
	if allHex(seg) && len(seg) >= 32 {
		return true
	}
	if entropy(seg) < 3.5 {
		return false
	}
	digits, vowels, letters := 0, 0, 0
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			letters++
			if strings.IndexByte("aeiou", c) >= 0 {
				vowels++
			}
		}
	}
	if float64(digits)/float64(len(seg)) >= 0.15 {
		return true
	}
	return letters >= 16 && float64(vowels)/float64(letters) <= 0.2
}

func allHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// printable returns s with anything outside a conservative hostname alphabet replaced by '?', and
// truncated, so client-supplied text can be echoed in responses and logs without injecting
// control characters or terminal escapes.
func printable(s string) string {
	const max = 100
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':', c == '[', c == ']':
			b.WriteByte(c)
		default:
			b.WriteByte('?')
		}
	}
	if len(s) > max {
		b.WriteString("...")
	}
	return b.String()
}

func hostPort(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}
