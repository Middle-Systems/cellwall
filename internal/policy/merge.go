package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/middle-systems/cellwall/presets"
)

var presetName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// PresetNames lists the embedded presets, sorted.
func PresetNames() []string {
	entries, err := fs.ReadDir(presets.FS, ".")
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if n, ok := strings.CutSuffix(e.Name(), ".yaml"); ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// LoadPreset parses and validates an embedded preset. Presets are held to a stricter standard
// than user policy: plain allow rules for specific hosts, no relaxations, no limits.
func LoadPreset(name string) (*Policy, error) {
	if !presetName.MatchString(name) {
		return nil, fmt.Errorf("invalid preset name %q", name)
	}
	data, err := fs.ReadFile(presets.FS, name+".yaml")
	if err != nil {
		return nil, fmt.Errorf("unknown preset %q (available: %s)", name, strings.Join(PresetNames(), ", "))
	}
	p, err := Parse("preset:"+name, data)
	if err != nil {
		return nil, err
	}
	if err := p.Validate(false); err != nil {
		return nil, fmt.Errorf("preset %q: %w", name, err)
	}
	if err := checkPresetShape(name, p); err != nil {
		return nil, err
	}
	return p, nil
}

// checkPresetShape enforces that presets are plain allow rules and nothing else.
func checkPresetShape(name string, p *Policy) error {
	if len(p.Presets) > 0 || p.Limits != (Limits{}) {
		return fmt.Errorf("preset %q: presets may only contain rules", name)
	}
	for i, r := range p.Rules {
		if r.IsDeny() || r.UnsafeAllowHTTP || r.UnsafeAllowPrivate || r.UnsafeAllowECH || r.UnsafeSkipTLSCheck || r.UnsafeDangerousWildcard {
			return fmt.Errorf("preset %q: rules[%d] (%s): presets may only contain plain allow rules", name, i, r.Host)
		}
	}
	return nil
}

// Merge combines policy layers, lowest precedence first (embedded defaults, user-global, project,
// session). Rules accumulate — a higher layer can add rules but never silently remove a lower
// layer's rule, and because deny beats allow a lower layer's deny cannot be overridden by an allow.
// Scalar limits are overridden by the highest layer that sets them. Presets are the ordered union.
func Merge(layers ...*Policy) *Policy {
	out := &Policy{Version: Version, Default: "deny"}
	seen := map[string]bool{}
	for _, l := range layers {
		if l == nil {
			continue
		}
		for _, name := range l.Presets {
			if !seen[name] {
				seen[name] = true
				out.Presets = append(out.Presets, name)
			}
		}
		out.Rules = append(out.Rules, l.Rules...)
		out.Limits = overlay(out.Limits, l.Limits)
	}
	return out
}

func overlay(base, over Limits) Limits {
	if over.MaxConns != 0 {
		base.MaxConns = over.MaxConns
	}
	if over.IdleTimeout != 0 {
		base.IdleTimeout = over.IdleTimeout
	}
	if over.TotalTimeout != 0 {
		base.TotalTimeout = over.TotalTimeout
	}
	if over.DialTimeout != 0 {
		base.DialTimeout = over.DialTimeout
	}
	if over.HandshakeTimeout != 0 {
		base.HandshakeTimeout = over.HandshakeTimeout
	}
	if over.MaxBytesPerConn != 0 {
		base.MaxBytesPerConn = over.MaxBytesPerConn
	}
	if over.MaxNewConnsPerHostPerMin != 0 {
		base.MaxNewConnsPerHostPerMin = over.MaxNewConnsPerHostPerMin
	}
	if over.MaxLabelLen != 0 {
		base.MaxLabelLen = over.MaxLabelLen
	}
	if over.MaxHostLen != 0 {
		base.MaxHostLen = over.MaxHostLen
	}
	if over.DenySuspicious {
		base.DenySuspicious = true // tightening only: a higher layer cannot turn it back off
	}
	return base
}

// Expand returns a copy with presets replaced by their rules (preset rules first, then the
// policy's own, each tagged with a Source). The result has no Presets, so Expand is idempotent.
func Expand(p *Policy) (*Policy, error) {
	out := *p
	out.Presets = nil
	out.Rules = nil
	out.Default = "deny"
	seen := map[string]bool{}
	for _, name := range p.Presets {
		if seen[name] {
			continue
		}
		seen[name] = true
		pr, err := LoadPreset(name)
		if err != nil {
			return nil, err
		}
		for _, r := range pr.Rules {
			r.Source = "preset:" + name
			out.Rules = append(out.Rules, r)
		}
	}
	for _, r := range p.Rules {
		if r.Source == "" {
			r.Source = "policy"
		}
		out.Rules = append(out.Rules, r)
	}
	return &out, nil
}

// Canonical returns the deterministic JSON encoding of a policy. Struct field order is fixed and
// slices keep rule order (which is meaningful), so equal policies produce identical bytes.
func Canonical(p *Policy) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Hash is the SHA-256 of the canonical encoding, hex. Audit records and `status` carry it so a
// decision can be tied to the exact policy that made it.
func Hash(p *Policy) string {
	b, err := Canonical(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
