package config

import (
	"fmt"
	"sort"
)

// ProtectedSet returns the effective read-only paths: the built-in defaults plus protected_paths,
// minus unsafe.unprotect, normalized, de-duplicated and sorted.
func (c *Config) ProtectedSet() []string {
	removed := map[string]bool{}
	for _, u := range c.Unsafe.Unprotect {
		if n, err := NormalizeRelPath(u); err == nil {
			removed[n] = true
		}
	}
	set := map[string]bool{}
	for _, list := range [][]string{DefaultProtected, c.ProtectedPaths} {
		for _, p := range list {
			n, err := NormalizeRelPath(p)
			if err != nil || removed[n] {
				continue
			}
			set[n] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Relaxations lists, in stable order, everything in this configuration that weakens the sandbox.
// `prepare`, `status` and `verify` print these (ADR 0003).
func (c *Config) Relaxations() []string {
	var out []string
	for _, u := range c.Unsafe.Unprotect {
		out = append(out, fmt.Sprintf("unsafe.unprotect: %s is writable by the agent (the host may later execute what it writes there)", u))
	}
	if c.Unsafe.PublishAllInterfaces {
		out = append(out, "unsafe.publish_all_interfaces: preview ports are published on every host interface, not just 127.0.0.1")
	}
	for _, cp := range c.Unsafe.CapAdd {
		out = append(out, fmt.Sprintf("unsafe.cap_add: the agent holds %s", cp))
	}
	if c.Unsafe.AuditFailOpen {
		out = append(out, "unsafe.audit_fail_open: the gateway keeps allowing connections when it cannot write its audit log")
	}
	if c.Unsafe.UnpinnedBaseImage && c.Agent.BaseImage != "" {
		out = append(out, "unsafe.unpinned_base_image: the agent base image is not pinned by digest")
	}
	if c.Unsafe.AllowOldEngine {
		out = append(out, "unsafe.allow_old_engine: on Docker < 28 the agent can reach host services bound to 0.0.0.0 (ADR 0001)")
	}
	if c.Agent.Telemetry {
		out = append(out, "agent.telemetry: the agent's optional telemetry and error reporting are allowed through the gateway")
	}
	if c.Agent.MCPConnectors {
		out = append(out, "agent.mcp_connectors: claude.ai MCP connector traffic is allowed through the gateway")
	}
	return out
}
