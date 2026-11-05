package config

import (
	"github.com/middle-systems/kennel/internal/pins"
)

// DefaultProtected are the paths that are read-only inside the agent container by default
// (spec section 4.8, plus .husky and .githooks, which hold git hooks the host would run).
// .git/config is deliberately NOT here: the agent legitimately edits it (remotes, identity), so
// `prepare` warns about it instead (see docs/decisions/0002).
var DefaultProtected = []string{
	".devcontainer",
	".kennel",
	".git/hooks",
	".githooks",
	".husky",
	".vscode/tasks.json",
	".vscode/settings.json",
	".idea",
	".claude",
	".mcp.json",
}

// Defaults for the sandbox. Strict by default; every number can be tuned in config.
const (
	DefaultPidsLimit      = 1024
	DefaultMemory         = "8g"
	DefaultCPUs           = 4
	DefaultGatewayMemory  = "256m"
	DefaultGatewayPids    = 256
	DefaultAuditMaxSizeMB = 50
	DefaultAuditMaxFiles  = 5
)

// Default returns the built-in configuration (the lowest layer).
func Default() *Config {
	return &Config{
		Version: Version,
		Stacks:  AutoList{Auto: true},
		Agent: Agent{
			Preset:  "claude",
			Command: []string{"claude"},
			Version: pins.ClaudeCodeVersion,
		},
		Workspace: Workspace{
			// bind here; scaffold picks volume on macOS and Windows when the project is a git
			// repository (spec section 4.5), because bind mounts are slow and awkward there.
			Mode:         "bind",
			CacheVolumes: AutoList{Auto: true},
		},
		Devcontainer: Devcontainer{Dir: DevcontainerDir},
		Hardening:    Hardening{PidsLimit: DefaultPidsLimit, Memory: DefaultMemory, CPUs: DefaultCPUs},
		Gateway: Gateway{
			Memory: DefaultGatewayMemory, PidsLimit: DefaultGatewayPids,
			AuditMaxSizeMB: DefaultAuditMaxSizeMB, AuditMaxFiles: DefaultAuditMaxFiles,
		},
	}
}
