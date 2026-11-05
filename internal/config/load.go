package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/middle-systems/kennel/internal/strictyaml"
)

// Layer says where a config file sits in the precedence order (lowest first).
type Layer int

const (
	// LayerUserGlobal is ~/.config/kennel/config.yaml: personal defaults across projects.
	LayerUserGlobal Layer = iota
	// LayerProject is the committed .kennel/config.yaml.
	LayerProject
)

func (l Layer) String() string {
	if l == LayerUserGlobal {
		return "user-global"
	}
	return "project"
}

// SyntaxError is a config problem with a position.
type SyntaxError = strictyaml.Error

var (
	agentSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"preset": {}, "command": {Kind: strictyaml.ScalarList}, "version": {}, "telemetry": {}, "mcp_connectors": {},
		"env": {Kind: strictyaml.ScalarMap}, "apt_packages": {Kind: strictyaml.ScalarList}, "base_image": {},
	}}
	workspaceSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"mode": {}, "cache_volumes": {Kind: strictyaml.ScalarOrList},
	}}
	devcontainerSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{"dir": {}}}
	hardeningSchema    = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"readonly_rootfs": {}, "runtime": {}, "pids_limit": {}, "memory": {}, "cpus": {},
	}}
	gatewaySchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"memory": {}, "pids_limit": {}, "audit_max_size_mb": {}, "audit_max_files": {},
	}}
	secretSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"name": {}, "source_file": {}, "env": {},
	}}
	gitSchema    = &strictyaml.Schema{Keys: map[string]strictyaml.Field{"user_name": {}, "user_email": {}}}
	unsafeSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"unprotect": {Kind: strictyaml.ScalarList}, "publish_all_interfaces": {}, "cap_add": {Kind: strictyaml.ScalarList},
		"audit_fail_open": {}, "unpinned_base_image": {}, "allow_old_engine": {},
	}}
	rootSchema = &strictyaml.Schema{Keys: map[string]strictyaml.Field{
		"version": {}, "project": {}, "stacks": {Kind: strictyaml.ScalarOrList},
		"agent":           {Kind: strictyaml.Object, Sub: agentSchema},
		"workspace":       {Kind: strictyaml.Object, Sub: workspaceSchema},
		"devcontainer":    {Kind: strictyaml.Object, Sub: devcontainerSchema},
		"ports":           {Kind: strictyaml.ScalarList},
		"hardening":       {Kind: strictyaml.Object, Sub: hardeningSchema},
		"gateway":         {Kind: strictyaml.Object, Sub: gatewaySchema},
		"protected_paths": {Kind: strictyaml.ScalarList},
		"secrets":         {Kind: strictyaml.ObjectList, Sub: secretSchema},
		"git":             {Kind: strictyaml.Object, Sub: gitSchema},
		"unsafe":          {Kind: strictyaml.Object, Sub: unsafeSchema},
	}}

	// Keys a user-global file may not set. Relaxations and credentials must be visible in the
	// committed project file, where a reviewer sees them; project identity and ports are
	// per-repository by nature.
	projectOnlyKeys = []string{"unsafe", "secrets", "project", "ports", "stacks", "devcontainer"}
)

// Parse reads one config file and applies it OVER base, returning a new Config (base is not
// modified). Keys absent from the file keep base's values; lists and the agent.env map follow the
// documented replace/merge rules of decoding onto an existing value. Structure is checked
// strictly (unknown/duplicate keys, anchors, tags) with line:col; call Validate on the result.
func Parse(file string, data []byte, layer Layer, base *Config) (*Config, error) {
	top, err := strictyaml.Parse(file, data, rootSchema)
	if err != nil {
		return nil, err
	}
	if layer == LayerUserGlobal {
		for i := 0; i+1 < len(top.Content); i += 2 {
			k := top.Content[i]
			for _, banned := range projectOnlyKeys {
				if k.Value == banned {
					return nil, &SyntaxError{File: file, Line: k.Line, Col: k.Column,
						Msg: fmt.Sprintf("%q cannot be set in the user-global config: relaxations, secrets and per-project settings must live in the committed project config where they can be reviewed", k.Value)}
				}
			}
		}
	}
	cfg, err := clone(base)
	if err != nil {
		return nil, err
	}
	if err := strictyaml.Decode(file, top, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// clone deep-copies the slices and map so layers cannot alias each other.
func clone(c *Config) (*Config, error) {
	cp := *c
	cp.Ports = append([]int(nil), c.Ports...)
	cp.ProtectedPaths = append([]string(nil), c.ProtectedPaths...)
	cp.Secrets = append([]Secret(nil), c.Secrets...)
	cp.Stacks.Items = append([]string(nil), c.Stacks.Items...)
	cp.Workspace.CacheVolumes.Items = append([]string(nil), c.Workspace.CacheVolumes.Items...)
	cp.Agent.Command = append([]string(nil), c.Agent.Command...)
	cp.Agent.AptPackages = append([]string(nil), c.Agent.AptPackages...)
	cp.Unsafe.Unprotect = append([]string(nil), c.Unsafe.Unprotect...)
	cp.Unsafe.CapAdd = append([]string(nil), c.Unsafe.CapAdd...)
	if c.Agent.Env != nil {
		cp.Agent.Env = make(map[string]string, len(c.Agent.Env))
		for k, v := range c.Agent.Env {
			cp.Agent.Env[k] = v
		}
	}
	return &cp, nil
}

// LoadOptions says where to read config from.
type LoadOptions struct {
	ProjectDir string // directory containing .kennel/
	// GlobalDir is the user-global config directory (e.g. ~/.config/kennel). Empty disables it.
	GlobalDir string
}

// ProjectFile is the project config path relative to the project directory.
const ProjectFile = ".kennel/config.yaml"

// Loaded is the result of Load.
type Loaded struct {
	Config      *Config
	ProjectFile string // path actually read
	GlobalFile  string // path actually read, "" if none
}

// ErrNoProjectConfig is returned when the project has no .kennel/config.yaml.
var ErrNoProjectConfig = errors.New("no .kennel/config.yaml in this project (run `kennel init`)")

// Load layers defaults < user-global < project, validates, and returns the effective config.
func Load(opts LoadOptions) (*Loaded, error) {
	out := &Loaded{}
	cfg := Default()

	if opts.GlobalDir != "" {
		path := filepath.Join(opts.GlobalDir, "config.yaml")
		if data, err := os.ReadFile(path); err == nil { //nolint:gosec // operator-controlled config location
			cfg, err = Parse(path, data, LayerUserGlobal, cfg)
			if err != nil {
				return nil, err
			}
			out.GlobalFile = path
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}

	path := filepath.Join(opts.ProjectDir, filepath.FromSlash(ProjectFile))
	data, err := os.ReadFile(path) //nolint:gosec // operator-controlled config location
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoProjectConfig
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	cfg, err = Parse(path, data, LayerProject, cfg)
	if err != nil {
		return nil, err
	}
	out.ProjectFile = path
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out.Config = cfg
	return out, nil
}

// Hash is the SHA-256 of the canonical JSON encoding, hex.
func (c *Config) Hash() string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
