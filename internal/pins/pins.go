// Package pins holds every externally sourced artifact the generated images depend on, pinned by
// content: base and toolchain images by digest, and the agent by a lockfile whose integrity
// hashes make `npm ci` fail if the registry serves different bytes.
//
// Nothing here is fetched at run time. Refresh with scripts/update-pins.sh (images) and
// `make update-claude-lock` (agent); both are reviewed like any other dependency change, and
// TestPinsAreWellFormed rejects tag-only references.
package pins

import (
	"embed"
	"fmt"
	"regexp"
)

// ClaudeCodeVersion is the agent version cellwall ships a verified lockfile for. Choosing another
// agent.version is allowed but is installed without a cellwall-held integrity pin (init warns).
const ClaudeCodeVersion = "2.1.286"

//go:embed claude/package.json claude/package-lock.json
var claudeFS embed.FS

// ClaudeLock returns the package.json and package-lock.json that pin Claude Code at version, or
// ok=false when cellwall does not hold a lockfile for that version.
func ClaudeLock(version string) (pkgJSON, lockJSON []byte, ok bool) {
	if version != ClaudeCodeVersion {
		return nil, nil, false
	}
	p, err1 := claudeFS.ReadFile("claude/package.json")
	l, err2 := claudeFS.ReadFile("claude/package-lock.json")
	if err1 != nil || err2 != nil {
		return nil, nil, false
	}
	return p, l, true
}

// Image names. Each value is "repository:tag@sha256:digest": the tag documents intent, the digest
// is what is actually pulled (the tag can move; the digest cannot).
const (
	// Debian is the base of the agent image.
	Debian = "debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"
	// Node supplies Node.js (24.x LTS at pin time) both for node projects and to install the agent.
	Node = "node:lts-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6"
	// Golang supplies the Go toolchain (1.27.1 at pin time).
	Golang = "golang:bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195"
	// Rust supplies the Rust toolchain (1.98.1 at pin time).
	Rust = "rust:slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730"
	// Dotnet supplies the .NET SDK (9.0.318 at pin time).
	Dotnet = "mcr.microsoft.com/dotnet/sdk:9.0-bookworm-slim@sha256:01fabc4758d1d74e39eda700c8463dae6241a61481f973683692ddcb59a5eeb7"
)

// All lists every pinned image, for validation and for the update script.
func All() map[string]string {
	return map[string]string{"debian": Debian, "node": Node, "golang": Golang, "rust": Rust, "dotnet": Dotnet}
}

var digestRef = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)

// Validate reports the first pinned image that is not a tag-plus-digest reference.
func Validate() error {
	for name, ref := range All() {
		if !digestRef.MatchString(ref) {
			return fmt.Errorf("pin %q is not repository:tag@sha256:<64 hex>: %q", name, ref)
		}
	}
	return nil
}
