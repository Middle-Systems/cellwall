// Package policy defines, loads, lints and compiles egress policy.
//
// Security posture (docs/decisions/0003): the default is deny and cannot be changed; anything
// that widens what the agent can reach is spelled with an "unsafe_" prefix, is reported by
// Relaxations, and is never produced by presets.
package policy

import (
	"encoding/json"
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// Version is the only supported schema version.
const Version = 1

// Rule actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Policy is the on-disk policy document. The same schema is used for user policy files and for
// the effective policy the host CLI writes for the gateway (where presets are expanded and each
// rule carries its Source).
type Policy struct {
	Version     int      `yaml:"version" json:"version"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Default     string   `yaml:"default,omitempty" json:"default,omitempty"`
	Presets     []string `yaml:"presets,omitempty" json:"presets,omitempty"`
	Rules       []Rule   `yaml:"rules,omitempty" json:"rules,omitempty"`
	Limits      Limits   `yaml:"limits,omitempty" json:"limits,omitempty"`
}

// Rule allows or denies one host pattern.
type Rule struct {
	// Host is "example.com", "*.example.com" (exactly one label) or "**.example.com" (one or more).
	Host string `yaml:"host" json:"host"`
	// Action is "allow" (default) or "deny". Deny always beats allow, whatever the order.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	// Ports the rule applies to. Allow rules default to 443 (plus 80 with unsafe_allow_http);
	// deny rules default to every port.
	Ports []int  `yaml:"ports,omitempty" json:"ports,omitempty"`
	Note  string `yaml:"note,omitempty" json:"note,omitempty"`

	// Relaxations. Each one widens what the agent can do and is reported at startup, by
	// `policy lint` and by `verify`.
	UnsafeAllowHTTP         bool `yaml:"unsafe_allow_http,omitempty" json:"unsafe_allow_http,omitempty"`
	UnsafeAllowPrivate      bool `yaml:"unsafe_allow_private,omitempty" json:"unsafe_allow_private,omitempty"`
	UnsafeAllowECH          bool `yaml:"unsafe_allow_ech,omitempty" json:"unsafe_allow_ech,omitempty"`
	UnsafeSkipTLSCheck      bool `yaml:"unsafe_skip_tls_check,omitempty" json:"unsafe_skip_tls_check,omitempty"`
	UnsafeDangerousWildcard bool `yaml:"unsafe_allow_dangerous_wildcard,omitempty" json:"unsafe_allow_dangerous_wildcard,omitempty"`

	// Source is set by Expand ("policy" or "preset:<name>"). Users may not set it.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`

	// Where the rule was written, so validation errors can point at it. Not serialized.
	file      string
	line, col int
}

// Limits bound what a single connection or the whole gateway may consume. Zero means "use the
// default"; -1 means unlimited and is reported as a relaxation.
type Limits struct {
	MaxConns                 int      `yaml:"max_conns,omitempty" json:"max_conns,omitempty"`
	IdleTimeout              Duration `yaml:"idle_timeout,omitempty" json:"idle_timeout,omitempty"`
	TotalTimeout             Duration `yaml:"total_timeout,omitempty" json:"total_timeout,omitempty"`
	DialTimeout              Duration `yaml:"dial_timeout,omitempty" json:"dial_timeout,omitempty"`
	HandshakeTimeout         Duration `yaml:"handshake_timeout,omitempty" json:"handshake_timeout,omitempty"`
	MaxBytesPerConn          int64    `yaml:"max_bytes_per_conn,omitempty" json:"max_bytes_per_conn,omitempty"`
	MaxNewConnsPerHostPerMin int      `yaml:"max_new_conns_per_host_per_min,omitempty" json:"max_new_conns_per_host_per_min,omitempty"`
	MaxLabelLen              int      `yaml:"max_label_len,omitempty" json:"max_label_len,omitempty"`
	MaxHostLen               int      `yaml:"max_host_len,omitempty" json:"max_host_len,omitempty"`
	// DenySuspicious refuses (instead of only logging) hostnames with a high-entropy label.
	DenySuspicious bool `yaml:"deny_suspicious,omitempty" json:"deny_suspicious,omitempty"`
}

// Unlimited marks a limit as intentionally disabled.
const Unlimited = -1

// Default limits, applied for zero values.
const (
	DefaultMaxConns                 = 256
	DefaultIdleTimeout              = 60 * time.Second
	DefaultTotalTimeout             = time.Hour
	DefaultDialTimeout              = 10 * time.Second
	DefaultHandshakeTimeout         = 10 * time.Second
	DefaultMaxBytesPerConn          = int64(8) << 30
	DefaultMaxNewConnsPerHostPerMin = 300
)

// EffectiveLimits are Limits with every default resolved. A zero Duration/int in the result means
// "unlimited" (the -1 sentinel is translated), so consumers never see sentinel values.
type EffectiveLimits struct {
	MaxConns                 int
	IdleTimeout              time.Duration
	TotalTimeout             time.Duration
	DialTimeout              time.Duration
	HandshakeTimeout         time.Duration
	MaxBytesPerConn          int64
	MaxNewConnsPerHostPerMin int
	MaxLabelLen              int
	MaxHostLen               int
	DenySuspicious           bool
}

// Effective resolves defaults and sentinels.
func (l Limits) Effective() EffectiveLimits {
	e := EffectiveLimits{
		MaxConns:                 intOr(l.MaxConns, DefaultMaxConns),
		IdleTimeout:              durOr(l.IdleTimeout, DefaultIdleTimeout),
		TotalTimeout:             durOr(l.TotalTimeout, DefaultTotalTimeout),
		DialTimeout:              durOr(l.DialTimeout, DefaultDialTimeout),
		HandshakeTimeout:         durOr(l.HandshakeTimeout, DefaultHandshakeTimeout),
		MaxBytesPerConn:          l.MaxBytesPerConn,
		MaxNewConnsPerHostPerMin: intOr(l.MaxNewConnsPerHostPerMin, DefaultMaxNewConnsPerHostPerMin),
		MaxLabelLen:              intOr(l.MaxLabelLen, MaxLabelLen),
		MaxHostLen:               intOr(l.MaxHostLen, MaxHostLen),
		DenySuspicious:           l.DenySuspicious,
	}
	switch {
	case l.MaxBytesPerConn == 0:
		e.MaxBytesPerConn = DefaultMaxBytesPerConn
	case l.MaxBytesPerConn < 0:
		e.MaxBytesPerConn = 0
	}
	if e.MaxLabelLen > MaxLabelLen {
		e.MaxLabelLen = MaxLabelLen
	}
	if e.MaxHostLen > MaxHostLen {
		e.MaxHostLen = MaxHostLen
	}
	return e
}

func intOr(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

func durOr(v Duration, def time.Duration) time.Duration {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return time.Duration(v)
}

// Duration is a time.Duration written as a string ("60s", "1h"), or "unlimited" for -1.
type Duration time.Duration

func parseDuration(s string) (Duration, error) {
	if s == "unlimited" {
		return Duration(Unlimited), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (examples: \"30s\", \"5m\", \"1h\", or \"unlimited\")", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive (use \"unlimited\" to disable)", s)
	}
	return Duration(d), nil
}

func (d Duration) String() string {
	if d < 0 {
		return "unlimited"
	}
	return time.Duration(d).String()
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }
