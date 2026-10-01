package policy

import (
	"fmt"
	"sort"
	"strings"
)

// Proto is how a request reaches the gateway.
type Proto int

const (
	// ProtoTunnel is an HTTP CONNECT tunnel (HTTPS and other TCP).
	ProtoTunnel Proto = iota
	// ProtoHTTP is a plain-HTTP request forwarded by the gateway.
	ProtoHTTP
)

// Decision reasons.
const (
	ReasonRule         = "rule"
	ReasonDefaultDeny  = "default-deny"
	ReasonExplicitDeny = "explicit-deny"
	ReasonPortNotAllow = "port-not-allowed"
	ReasonHTTPNotAllow = "http-not-allowed"
)

// CompiledRule is a rule ready for matching.
type CompiledRule struct {
	Index   int
	Rule    Rule
	Pattern Pattern
	Deny    bool
	ports   []int // nil = every port
}

func (c *CompiledRule) hasPort(p int) bool {
	if c.ports == nil {
		return true
	}
	return containsPort(c.ports, p)
}

// Compiled is an immutable, ready-to-use policy. It is safe for concurrent use; reload by building
// a new Compiled and swapping the pointer.
type Compiled struct {
	Policy   *Policy // expanded
	Hash     string
	Limits   EffectiveLimits
	Findings []Finding

	exact  map[string][]*CompiledRule
	single map[string][]*CompiledRule // keyed by the base (parent) domain
	multi  map[string][]*CompiledRule
}

// Compile expands presets, validates, lints (refusing unwaived lint errors) and indexes a policy.
// allowSource must be true only for the effective policy written by the host CLI.
func Compile(p *Policy, allowSource bool) (*Compiled, error) {
	if err := p.Validate(allowSource); err != nil {
		return nil, err
	}
	exp, err := Expand(p)
	if err != nil {
		return nil, err
	}
	findings := Lint(exp)
	if HasErrors(findings) {
		var msgs []string
		for _, f := range findings {
			if f.Level == LevelError {
				msgs = append(msgs, f.String())
			}
		}
		return nil, fmt.Errorf("policy has dangerous rules:\n  %s", strings.Join(msgs, "\n  "))
	}
	c := &Compiled{
		Policy:   exp,
		Hash:     Hash(exp),
		Limits:   exp.Limits.Effective(),
		Findings: findings,
		exact:    map[string][]*CompiledRule{},
		single:   map[string][]*CompiledRule{},
		multi:    map[string][]*CompiledRule{},
	}
	for i := range exp.Rules {
		r := exp.Rules[i]
		pat := r.Pattern()
		cr := &CompiledRule{Index: i, Rule: r, Pattern: pat, Deny: r.IsDeny(), ports: r.effectivePorts()}
		switch pat.Kind {
		case Exact:
			c.exact[pat.Base] = append(c.exact[pat.Base], cr)
		case SingleLabel:
			c.single[pat.Base] = append(c.single[pat.Base], cr)
		case MultiLabel:
			c.multi[pat.Base] = append(c.multi[pat.Base], cr)
		}
	}
	return c, nil
}

// candidates returns every rule whose host pattern matches, in policy order.
func (c *Compiled) candidates(host string) []*CompiledRule {
	var out []*CompiledRule
	out = append(out, c.exact[host]...)
	if i := strings.IndexByte(host, '.'); i > 0 {
		out = append(out, c.single[host[i+1:]]...)
	}
	// Every proper suffix after a dot is a possible multi-label base.
	for i := 0; i < len(host); i++ {
		if host[i] == '.' && i+1 < len(host) {
			out = append(out, c.multi[host[i+1:]]...)
		}
	}
	if len(out) > 1 {
		sort.SliceStable(out, func(a, b int) bool { return out[a].Index < out[b].Index })
	}
	return out
}

// Decision is the policy's answer for one destination.
type Decision struct {
	Allowed bool
	Reason  string
	// Rule is the rule that decided (the allowing rule, or the deny rule); nil for default-deny
	// and for denials where only non-matching-port rules exist.
	Rule *CompiledRule
}

// Match decides whether host:port is allowed for proto. host must already be normalized
// (NormalizeHost). Deny rules always win; among allow rules the first in policy order wins.
func (c *Compiled) Match(host string, port int, proto Proto) Decision {
	cands := c.candidates(host)
	if len(cands) == 0 {
		return Decision{Reason: ReasonDefaultDeny}
	}
	for _, r := range cands {
		if r.Deny && r.hasPort(port) {
			return Decision{Reason: ReasonExplicitDeny, Rule: r}
		}
	}
	sawPortMatch := false
	for _, r := range cands {
		if r.Deny || !r.hasPort(port) {
			continue
		}
		sawPortMatch = true
		if proto == ProtoHTTP && !r.Rule.UnsafeAllowHTTP {
			continue
		}
		return Decision{Allowed: true, Reason: ReasonRule, Rule: r}
	}
	if sawPortMatch {
		return Decision{Reason: ReasonHTTPNotAllow}
	}
	return Decision{Reason: ReasonPortNotAllow}
}
