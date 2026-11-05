package policy

import (
	"fmt"
	"strings"
)

// MaxRules bounds policy size so a runaway generator cannot exhaust gateway memory.
const MaxRules = 10000

const maxNoteLen = 200

func (r *Rule) errf(index int, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if r.line > 0 {
		return &SyntaxError{File: r.file, Line: r.line, Col: r.col, Msg: fmt.Sprintf("rules[%d] (host %q): %s", index, r.Host, msg)}
	}
	return fmt.Errorf("rules[%d] (host %q): %s", index, r.Host, msg)
}

// IsDeny reports whether the rule denies.
func (r *Rule) IsDeny() bool { return r.Action == ActionDeny }

// Validate checks semantics that the structural parser cannot. allowSource permits rules to carry
// a Source (true for the effective policy the host CLI writes; false for anything a user authored).
func (p *Policy) Validate(allowSource bool) error {
	if p.Version != Version {
		return fmt.Errorf("policy: version must be %d (got %d)", Version, p.Version)
	}
	// Only deny-by-default exists. A policy cannot opt into allow-by-default: that would turn
	// the allowlist into a blocklist and defeat the product.
	if p.Default != "" && p.Default != "deny" {
		return fmt.Errorf("policy: default must be \"deny\" (got %q); allow-by-default is not supported", p.Default)
	}
	if len(p.Rules) > MaxRules {
		return fmt.Errorf("policy: %d rules exceeds the limit of %d", len(p.Rules), MaxRules)
	}
	for i := range p.Rules {
		if err := p.Rules[i].validate(i, allowSource); err != nil {
			return err
		}
	}
	return p.Limits.validate()
}

func (r *Rule) validate(i int, allowSource bool) error {
	if r.Host == "" {
		return r.errf(i, "host is required")
	}
	if _, err := ParsePattern(r.Host); err != nil {
		return r.errf(i, "%v", err)
	}
	switch r.Action {
	case "", ActionAllow, ActionDeny:
	default:
		return r.errf(i, "action must be \"allow\" or \"deny\" (got %q)", r.Action)
	}
	seen := map[int]bool{}
	for _, port := range r.Ports {
		if port < 1 || port > 65535 {
			return r.errf(i, "port %d is out of range 1-65535", port)
		}
		if seen[port] {
			return r.errf(i, "port %d is listed twice", port)
		}
		seen[port] = true
	}
	if len(r.Note) > maxNoteLen {
		return r.errf(i, "note is longer than %d characters", maxNoteLen)
	}
	for _, c := range r.Note {
		if c < 0x20 || c == 0x7f {
			return r.errf(i, "note must not contain control characters")
		}
	}
	if r.Source != "" && !allowSource {
		return r.errf(i, "\"source\" is set by kennel and cannot be written in a policy file")
	}
	if r.IsDeny() && (r.UnsafeAllowHTTP || r.UnsafeAllowPrivate || r.UnsafeAllowECH || r.UnsafeSkipTLSCheck || r.UnsafeDangerousWildcard) {
		return r.errf(i, "unsafe_* options only make sense on allow rules")
	}
	if r.UnsafeAllowPrivate && r.Pattern().Kind != Exact {
		return r.errf(i, "unsafe_allow_private is only allowed on an exact host, not a wildcard")
	}
	return nil
}

// Pattern returns the parsed host pattern. It must only be called on validated rules.
func (r *Rule) Pattern() Pattern {
	p, _ := ParsePattern(r.Host)
	return p
}

func (l Limits) validate() error {
	for name, v := range map[string]int{
		"max_conns": l.MaxConns, "max_new_conns_per_host_per_min": l.MaxNewConnsPerHostPerMin,
		"max_label_len": l.MaxLabelLen, "max_host_len": l.MaxHostLen,
	} {
		if v < Unlimited {
			return fmt.Errorf("limits.%s must be positive, or -1 for unlimited (got %d)", name, v)
		}
	}
	if l.MaxBytesPerConn < Unlimited {
		return fmt.Errorf("limits.max_bytes_per_conn must be positive, or -1 for unlimited (got %d)", l.MaxBytesPerConn)
	}
	// Hostname length limits are structural, not resource limits: "unlimited" would let through
	// names that are not valid DNS names at all.
	if l.MaxLabelLen < 0 || l.MaxHostLen < 0 {
		return fmt.Errorf("limits.max_label_len and limits.max_host_len cannot be unlimited")
	}
	if l.MaxLabelLen > MaxLabelLen || l.MaxHostLen > MaxHostLen {
		return fmt.Errorf("limits.max_label_len / max_host_len cannot exceed the DNS limits (%d / %d)", MaxLabelLen, MaxHostLen)
	}
	return nil
}

// effectivePorts returns the ports an allow rule applies to.
func (r *Rule) effectivePorts() []int {
	if len(r.Ports) > 0 {
		return r.Ports
	}
	if r.IsDeny() {
		return nil // nil = every port
	}
	if r.UnsafeAllowHTTP {
		return []int{80, 443}
	}
	return []int{443}
}

func describeSource(s string) string {
	if s == "" {
		return "policy"
	}
	return strings.TrimSpace(s)
}
