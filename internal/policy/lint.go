package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Level is a lint finding's severity.
type Level string

// Levels. Errors block loading unless explicitly waived on the rule.
const (
	LevelError Level = "error"
	LevelWarn  Level = "warn"
	LevelInfo  Level = "info"
)

// Finding is one lint result.
type Finding struct {
	Level   Level  `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Rule    int    `json:"rule"` // index into the (expanded) rules, or -1
	Host    string `json:"host,omitempty"`
	Source  string `json:"source,omitempty"`
	// Relaxation marks findings that describe something weakened on purpose. These are the lines
	// printed in the gateway's startup banner and by `status` / `verify` (ADR 0003).
	Relaxation bool `json:"relaxation,omitempty"`
}

func (f Finding) String() string {
	loc := ""
	if f.Rule >= 0 {
		loc = fmt.Sprintf("rules[%d] ", f.Rule)
		if f.Host != "" {
			loc += fmt.Sprintf("(%s) ", f.Host)
		}
	}
	return fmt.Sprintf("%s: %s%s [%s]", f.Level, loc, f.Message, f.Code)
}

// Lint inspects an expanded policy. It is pure: Compile uses it to refuse dangerous policies, and
// `policy lint` prints it. Findings are ordered by rule, then code, so output is deterministic.
func Lint(p *Policy) []Finding {
	var out []Finding
	add := func(level Level, code string, idx int, r *Rule, relax bool, format string, args ...any) {
		f := Finding{Level: level, Code: code, Message: fmt.Sprintf(format, args...), Rule: idx, Relaxation: relax}
		if r != nil {
			f.Host, f.Source = r.Host, describeSource(r.Source)
		}
		out = append(out, f)
	}

	type key struct {
		host, action string
		ports        string
	}
	dup := map[key]int{}
	var denies []int

	for i := range p.Rules {
		r := &p.Rules[i]
		pat, err := ParsePattern(r.Host)
		if err != nil {
			continue // Validate reports it
		}
		k := key{pat.String(), r.Action, fmt.Sprint(r.effectivePorts())}
		if first, ok := dup[k]; ok {
			add(LevelInfo, "duplicate-rule", i, r, false, "duplicates rules[%d]", first)
		} else {
			dup[k] = i
		}
		if r.IsDeny() {
			denies = append(denies, i)
			continue
		}

		if pat.Kind != Exact {
			lintWildcard(add, i, r, pat)
		}
		if r.UnsafeAllowPrivate {
			add(LevelWarn, "unsafe-private", i, r, true,
				"UNSAFE: %s may resolve to loopback/private/link-local/metadata addresses; the agent can then reach internal services through this host", r.Host)
		}
		if r.UnsafeAllowHTTP {
			add(LevelWarn, "unsafe-http", i, r, true, "plain HTTP is allowed: requests and responses to %s are unencrypted and visible to anything on the path", r.Host)
		}
		if r.UnsafeAllowECH {
			add(LevelWarn, "unsafe-ech", i, r, true, "Encrypted Client Hello is allowed: the gateway cannot check the SNI for %s, so a tunnel can carry a hidden destination name", r.Host)
		}
		if r.UnsafeSkipTLSCheck {
			add(LevelWarn, "unsafe-skip-tls", i, r, true, "TLS ClientHello inspection is skipped for %s: any protocol can be tunnelled to it", r.Host)
		}
		for _, port := range r.Ports {
			if port != 80 && port != 443 {
				add(LevelInfo, "nonstandard-port", i, r, false, "port %d is not 80 or 443", port)
			}
		}
		if len(r.Ports) > 0 && !r.UnsafeAllowHTTP && !containsPort(r.Ports, 443) && !r.UnsafeSkipTLSCheck {
			add(LevelInfo, "tls-on-nonstandard-port", i, r, false, "ports %v are TLS-inspected like 443; set unsafe_skip_tls_check for non-TLS protocols", r.Ports)
		}
	}

	// Allow rules that a deny rule fully covers can never take effect: usually a mistake.
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.IsDeny() {
			continue
		}
		for _, di := range denies {
			d := &p.Rules[di]
			if covers(d, r) {
				add(LevelInfo, "shadowed-by-deny", i, r, false, "denied by rules[%d] (%s), so this rule never applies", di, d.Host)
				break
			}
		}
	}

	lintLimits(&out, p.Limits)
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Rule != out[b].Rule {
			return out[a].Rule < out[b].Rule
		}
		return out[a].Code < out[b].Code
	})
	return out
}

func lintWildcard(add func(Level, string, int, *Rule, bool, string, ...any), i int, r *Rule, pat Pattern) {
	base := pat.Base
	labels := strings.Count(base, ".") + 1
	waived := r.UnsafeDangerousWildcard

	// dangerous wildcard problems are errors, unless the rule says (loudly) that it means it.
	problem := func(code, format string, args ...any) {
		if waived {
			add(LevelWarn, code+"-waived", i, r, true, "WAIVED: "+format, args...)
			return
		}
		add(LevelError, code, i, r, false, format+" (waive with unsafe_allow_dangerous_wildcard: true if you really mean it)", args...)
	}
	switch {
	case labels < 2:
		problem("wildcard-tld", "%s matches every name under the top-level domain %q", pat, base)
	case multiLabelPublicSuffixes[base]:
		problem("wildcard-public-suffix", "%s matches every registrant under the public suffix %q", pat, base)
	}
	if s, ok := userContentSuffix(base); ok {
		problem("wildcard-user-content", "%s covers %q, where anyone can create hostnames and host content; an agent could exfiltrate data to a name it controls (the gateway resolves names itself, so even the DNS lookup leaks)", pat, s)
	}
	if pat.Kind == MultiLabel {
		add(LevelWarn, "wildcard-multi-label", i, r, false, "%s matches names of any depth; prefer %s or exact hosts", pat, "*."+base)
	}
	add(LevelInfo, "wildcard", i, r, false, "wildcards let the gateway resolve any matching name; exact hostnames are safer")
}

func lintLimits(out *[]Finding, l Limits) {
	flag := func(name string, unlimited bool) {
		if unlimited {
			*out = append(*out, Finding{Level: LevelWarn, Code: "unlimited-" + name, Rule: -1, Relaxation: true,
				Message: fmt.Sprintf("limits.%s is unlimited", name)})
		}
	}
	flag("max_conns", l.MaxConns < 0)
	flag("idle_timeout", l.IdleTimeout < 0)
	flag("total_timeout", l.TotalTimeout < 0)
	flag("dial_timeout", l.DialTimeout < 0)
	flag("handshake_timeout", l.HandshakeTimeout < 0)
	flag("max_bytes_per_conn", l.MaxBytesPerConn < 0)
	flag("max_new_conns_per_host_per_min", l.MaxNewConnsPerHostPerMin < 0)
}

func containsPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// covers reports whether deny rule d denies everything allow rule a could allow.
func covers(d, a *Rule) bool {
	dp, err1 := ParsePattern(d.Host)
	ap, err2 := ParsePattern(a.Host)
	if err1 != nil || err2 != nil {
		return false
	}
	hostCovered := false
	switch {
	case dp.Kind == Exact && ap.Kind == Exact:
		hostCovered = dp.Base == ap.Base
	case dp.Kind == Exact:
		hostCovered = false
	case ap.Kind == Exact:
		hostCovered = dp.Matches(ap.Base)
	default:
		// Both wildcards: d covers a if a's base is d's base or beneath it (for multi), or equal (single).
		hostCovered = dp.Base == ap.Base && (dp.Kind == MultiLabel || ap.Kind == SingleLabel) ||
			dp.Kind == MultiLabel && strings.HasSuffix(ap.Base, "."+dp.Base)
	}
	if !hostCovered {
		return false
	}
	dports := d.effectivePorts()
	if dports == nil {
		return true
	}
	for _, p := range a.effectivePorts() {
		if !containsPort(dports, p) {
			return false
		}
	}
	return true
}

// HasErrors reports whether any finding is an unwaived error.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Level == LevelError {
			return true
		}
	}
	return false
}

// Relaxations returns the human-readable lines for every deliberately weakened control.
func Relaxations(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Relaxation {
			out = append(out, f.String())
		}
	}
	return out
}
