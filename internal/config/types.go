// Package config defines cellwall's project configuration (.cellwall/config.yaml): its schema,
// layering, validation and canonical form.
//
// Posture (docs/decisions/0003 and 0006): everything that merely tunes the sandbox is a plain
// option; everything that weakens it lives under `unsafe:`, is honoured only in the committed
// project file (so it appears in code review, never hidden in a user-global file or an
// environment variable), and is listed by Relaxations. Some things are not configurable at all:
// the Docker socket, privileged mode, NET_ADMIN/NET_RAW, and giving the agent the policy files.
package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Version is the only supported schema version.
const Version = 1

// Gateway ports. The proxy port is what the agent's HTTP(S)_PROXY points at; the admin port is
// loopback-only inside the gateway container and is never reachable by the agent.
const (
	GatewayProxyPort = 3128
	GatewayAdminPort = 3129
)

// Config is the effective configuration after layering.
type Config struct {
	Version   int       `yaml:"version" json:"version"`
	Project   string    `yaml:"project,omitempty" json:"project"`
	Stacks    AutoList  `yaml:"stacks,omitempty" json:"stacks"`
	Agent     Agent     `yaml:"agent,omitempty" json:"agent"`
	Workspace Workspace `yaml:"workspace,omitempty" json:"workspace"`
	Ports     []int     `yaml:"ports,omitempty" json:"ports"`
	Hardening Hardening `yaml:"hardening,omitempty" json:"hardening"`
	Gateway   Gateway   `yaml:"gateway,omitempty" json:"gateway"`
	// ProtectedPaths are ADDITIONAL read-only paths. The built-in defaults (DefaultProtected) are
	// always protected; they can only be removed through unsafe.unprotect, never by editing this
	// list, so copying a config and trimming a line cannot silently weaken the sandbox.
	ProtectedPaths []string `yaml:"protected_paths,omitempty" json:"protected_paths"`
	Secrets        []Secret `yaml:"secrets,omitempty" json:"secrets"`
	Git            Git      `yaml:"git,omitempty" json:"git"`
	Unsafe         Unsafe   `yaml:"unsafe,omitempty" json:"unsafe"`
}

// Agent configures the coding agent.
type Agent struct {
	// Preset selects built-in install and defaults: "claude", or "none" for a bring-your-own agent.
	Preset string `yaml:"preset,omitempty" json:"preset"`
	// Command is the argv started by `cellwall run`. No shell is involved.
	Command []string `yaml:"command,omitempty" json:"command"`
	// Version of the agent to install. cellwall ships integrity pins for pins.ClaudeCodeVersion only.
	Version string `yaml:"version,omitempty" json:"version"`
	// Telemetry allows the agent's optional telemetry and error reporting. Off by default; turning
	// it on also adds the matching gateway allowlist preset so the setting and the policy agree.
	Telemetry bool `yaml:"telemetry,omitempty" json:"telemetry"`
	// MCPConnectors allows claude.ai connectors via Anthropic's proxy (off by default).
	MCPConnectors bool `yaml:"mcp_connectors,omitempty" json:"mcp_connectors"`
	// Env is extra, non-secret environment for the agent. Secrets belong in `secrets`.
	Env map[string]string `yaml:"env,omitempty" json:"env"`
	// AptPackages are extra Debian packages installed into the agent image at build time.
	AptPackages []string `yaml:"apt_packages,omitempty" json:"apt_packages"`
	// BaseImage replaces the pinned Debian base. It must be Debian/Ubuntu based (apt) and pinned
	// by digest unless unsafe.unpinned_base_image is set.
	BaseImage string `yaml:"base_image,omitempty" json:"base_image"`
}

// Workspace configures how the repository reaches the agent container.
type Workspace struct {
	// Mode is "bind" (host directory mounted) or "volume" (repo in a named volume; needs `fetch`).
	Mode string `yaml:"mode,omitempty" json:"mode"`
	// CacheVolumes are workspace-relative directories kept on named volumes, off the slow mount:
	// "auto" (from detected stacks), "none", or an explicit list.
	CacheVolumes AutoList `yaml:"cache_volumes,omitempty" json:"cache_volumes"`
}

// Hardening configures the agent container's limits.
type Hardening struct {
	ReadonlyRootfs bool    `yaml:"readonly_rootfs,omitempty" json:"readonly_rootfs"`
	Runtime        string  `yaml:"runtime,omitempty" json:"runtime"` // e.g. "runsc" for gVisor
	PidsLimit      int     `yaml:"pids_limit,omitempty" json:"pids_limit"`
	Memory         string  `yaml:"memory,omitempty" json:"memory"`
	CPUs           float64 `yaml:"cpus,omitempty" json:"cpus"`
}

// Gateway configures the gateway container.
type Gateway struct {
	Memory         string `yaml:"memory,omitempty" json:"memory"`
	PidsLimit      int    `yaml:"pids_limit,omitempty" json:"pids_limit"`
	AuditMaxSizeMB int    `yaml:"audit_max_size_mb,omitempty" json:"audit_max_size_mb"`
	AuditMaxFiles  int    `yaml:"audit_max_files,omitempty" json:"audit_max_files"`
}

// Secret is an explicit, opt-in credential. Only its location is configured, never its value.
// The file is mounted read-only at /run/secrets/<name>; if Env is set, the agent's entrypoint
// exports that variable from the file when the container starts, so the value never appears in
// `docker inspect`, in generated files, or in logs.
type Secret struct {
	Name       string `yaml:"name" json:"name"`
	SourceFile string `yaml:"source_file" json:"source_file"`
	Env        string `yaml:"env,omitempty" json:"env"`
}

// Git sets the identity the agent commits with.
type Git struct {
	UserName  string `yaml:"user_name,omitempty" json:"user_name"`
	UserEmail string `yaml:"user_email,omitempty" json:"user_email"`
}

// Unsafe collects every option that weakens the sandbox. Honoured only from the project file.
type Unsafe struct {
	// Unprotect removes built-in protected paths (the agent can then write them).
	Unprotect []string `yaml:"unprotect,omitempty" json:"unprotect"`
	// PublishAllInterfaces publishes preview ports on 0.0.0.0 instead of 127.0.0.1.
	PublishAllInterfaces bool `yaml:"publish_all_interfaces,omitempty" json:"publish_all_interfaces"`
	// CapAdd adds Linux capabilities to the agent. Only SYS_PTRACE is permitted (debuggers).
	CapAdd []string `yaml:"cap_add,omitempty" json:"cap_add"`
	// AuditFailOpen lets the gateway keep allowing connections when its audit log cannot be written.
	AuditFailOpen bool `yaml:"audit_fail_open,omitempty" json:"audit_fail_open"`
	// UnpinnedBaseImage permits agent.base_image without a digest.
	UnpinnedBaseImage bool `yaml:"unpinned_base_image,omitempty" json:"unpinned_base_image"`
	// AllowOldEngine skips the Docker Engine >= 28 requirement for host-isolated networking
	// (ADR 0001). The agent may then reach host services bound to 0.0.0.0.
	AllowOldEngine bool `yaml:"allow_old_engine,omitempty" json:"allow_old_engine"`
}

// AutoList is "auto", "none", or an explicit list. The zero value means "auto"-by-default is NOT
// assumed: callers set defaults explicitly.
type AutoList struct {
	Auto  bool
	Items []string
}

// IsNone reports an explicit empty selection.
func (a AutoList) IsNone() bool { return !a.Auto && len(a.Items) == 0 }

// UnmarshalYAML implements yaml.Unmarshaler.
func (a *AutoList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		switch strings.ToLower(n.Value) {
		case "auto":
			*a = AutoList{Auto: true}
		case "none":
			*a = AutoList{}
		default:
			return fmt.Errorf("expected \"auto\", \"none\" or a list, got %q", n.Value)
		}
		return nil
	case yaml.SequenceNode:
		var items []string
		if err := n.Decode(&items); err != nil {
			return err
		}
		*a = AutoList{Items: items}
		return nil
	}
	return fmt.Errorf("expected \"auto\", \"none\" or a list")
}

// MarshalYAML implements yaml.Marshaler.
func (a AutoList) MarshalYAML() (any, error) {
	switch {
	case a.Auto:
		return "auto", nil
	case len(a.Items) == 0:
		return "none", nil
	}
	return a.Items, nil
}

// MarshalJSON implements json.Marshaler.
func (a AutoList) MarshalJSON() ([]byte, error) {
	v, _ := a.MarshalYAML()
	return json.Marshal(v)
}
