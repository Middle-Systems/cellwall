// Package presets embeds the reviewed, versioned allowlist presets. Each preset is a policy
// document containing only plain allow rules for specific hostnames.
package presets

import "embed"

// FS holds one <name>.yaml file per preset.
//
//go:embed *.yaml
var FS embed.FS
