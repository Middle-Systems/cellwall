package gen

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/middle-systems/kennel/internal/config"
	"github.com/middle-systems/kennel/internal/detect"
	"github.com/middle-systems/kennel/internal/pins"
)

// Inputs is everything generation depends on. Rendering is a pure function of it.
type Inputs struct {
	Config *config.Config
	Detect *detect.Result
	Plan   detect.Plan
}

// Layout says where the generated container files live and how they reach the project root.
type Layout struct {
	Dir    string // project-relative directory, e.g. ".devcontainer"
	ToRoot string // path from Dir back to the project root, e.g. ".."
}

// LayoutFor derives the layout from config.
func LayoutFor(c *config.Config) Layout {
	if c.Devcontainer.Dir == config.DevcontainerMergeDir {
		return Layout{Dir: config.DevcontainerMergeDir, ToRoot: "../.."}
	}
	return Layout{Dir: config.DevcontainerDir, ToRoot: ".."}
}

// StateDirRel is where `prepare` writes per-session gateway state, relative to the project root.
const StateDirRel = ".kennel/state"

// CacheVolume is a workspace directory kept on a named volume.
type CacheVolume struct {
	Path   string // workspace-relative, e.g. "web/node_modules"
	Volume string // compose volume name
}

// KV is an ordered key/value pair.
type KV struct{ Key, Value string }

// Data is the template model.
type Data struct {
	Cfg     *config.Config
	Project string
	Layout  Layout
	Stacks  []string

	BaseImage string
	// Toolchains copied from digest-pinned official images.
	Node, Go, Rust, Dotnet bool
	Pins                   map[string]string

	Claude        bool
	ClaudeVersion string
	ClaudePinned  bool // a kennel-held lockfile exists for ClaudeVersion

	AptPackages []string
	Caches      []CacheVolume
	Ports       []int
	Env         []KV // agent environment, sorted by key
	ImageName   string

	Secrets    []config.Secret
	SecretsEnv string // "name:ENVVAR;name2:" for the entrypoint

	Hints []string

	// SeedPresets are the presets written into a freshly created policy.yaml.
	SeedPresets []string
}

// NewData builds the template model. It validates nothing the config validator already covers.
func NewData(in Inputs) (*Data, error) {
	c := in.Config
	if c == nil || in.Detect == nil {
		return nil, fmt.Errorf("gen: config and detection result are required")
	}
	project := c.Project
	if project == "" {
		return nil, fmt.Errorf("gen: config has no project name")
	}
	d := &Data{Cfg: c, Project: project, Layout: LayoutFor(c), Pins: pins.All(), ImageName: "kennel-" + project + "-agent:local"}

	// Stacks.
	if c.Stacks.Auto {
		d.Stacks = in.Detect.Names()
	} else {
		d.Stacks = canonicalStacks(c.Stacks.Items)
	}
	has := map[string]bool{}
	for _, s := range d.Stacks {
		has[s] = true
	}
	d.Node, d.Go, d.Rust, d.Dotnet = has["node"], has["go"], has["rust"], has["dotnet"]

	d.BaseImage = c.Agent.BaseImage
	if d.BaseImage == "" {
		d.BaseImage = pins.Debian
	}

	// Agent.
	if c.Agent.Preset == "claude" {
		d.Claude = true
		d.ClaudeVersion = c.Agent.Version
		_, _, d.ClaudePinned = pins.ClaudeLock(c.Agent.Version)
	}

	// Cache volumes.
	switch {
	case c.Workspace.CacheVolumes.Auto:
		d.Caches = cacheVolumes(in.Plan.Caches)
	default:
		var items []string
		for _, it := range c.Workspace.CacheVolumes.Items {
			n, err := config.NormalizeRelPath(it)
			if err != nil {
				return nil, fmt.Errorf("gen: cache volume %q: %w", it, err)
			}
			items = append(items, n)
		}
		sort.Strings(items)
		d.Caches = cacheVolumes(items)
	}
	d.Ports = append([]int(nil), c.Ports...)
	sort.Ints(d.Ports)

	d.AptPackages = aptPackages(d, in.Detect)
	d.Secrets = append([]config.Secret(nil), c.Secrets...)
	sort.Slice(d.Secrets, func(i, j int) bool { return d.Secrets[i].Name < d.Secrets[j].Name })
	d.SecretsEnv = secretsEnv(d.Secrets)
	d.Env = agentEnv(d)
	d.Hints = in.Plan.BindHints
	return d, nil
}

func canonicalStacks(items []string) []string {
	want := map[string]bool{}
	for _, it := range items {
		want[it] = true
	}
	var out []string
	for _, n := range config.KnownStacks {
		if want[n] {
			out = append(out, n)
		}
	}
	return out
}

// cacheVolumes names a volume per directory, deterministically and without collisions.
func cacheVolumes(dirs []string) []CacheVolume {
	var out []CacheVolume
	used := map[string]bool{}
	for _, dir := range dirs {
		base := "cache-" + sanitizeVolume(dir)
		name := base
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		used[name] = true
		out = append(out, CacheVolume{Path: dir, Volume: name})
	}
	return out
}

func sanitizeVolume(p string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimLeft(path.Clean(p), ".")) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		case r == '/' || r == '.':
			b.WriteByte('-')
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "dir"
	}
	return b.String()
}

// aptPackages is the sorted union of what the base tooling, each stack and the user need.
func aptPackages(d *Data, r *detect.Result) []string {
	set := map[string]bool{}
	add := func(p ...string) {
		for _, x := range p {
			set[x] = true
		}
	}
	add("ca-certificates", "curl", "git", "jq", "less", "make", "procps", "ripgrep", "unzip")
	for _, s := range d.Stacks {
		switch s {
		case "node":
			add("build-essential", "python3", "pkg-config")
		case "python":
			add("build-essential", "python3", "python3-dev", "python3-pip", "python3-venv")
		case "go":
			add("gcc", "libc6-dev")
		case "rust":
			add("build-essential", "pkg-config", "libssl-dev")
		case "java":
			add("default-jdk-headless")
			for _, st := range r.Stacks {
				if st.Name == "java" && st.Tool == "maven" {
					add("maven")
				}
			}
		case "dotnet":
			add("libicu72", "libssl3", "zlib1g", "libgcc-s1", "libstdc++6")
		case "ruby":
			add("build-essential", "ruby-full", "libssl-dev", "libyaml-dev", "zlib1g-dev")
		case "php":
			add("composer", "php-cli", "php-curl", "php-mbstring", "php-xml", "php-zip")
		}
	}
	add(d.Cfg.Agent.AptPackages...)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func secretsEnv(secrets []config.Secret) string {
	var parts []string
	for _, s := range secrets {
		parts = append(parts, s.Name+":"+s.Env)
	}
	return strings.Join(parts, ";")
}

// agentEnv builds the agent container's environment, sorted by key. Proxy variables point at the
// gateway; nothing here contains a secret value.
func agentEnv(d *Data) []KV {
	c := d.Cfg
	env := map[string]string{}
	proxy := fmt.Sprintf("http://gateway:%d", config.GatewayProxyPort)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env[k] = proxy
	}
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		env[k] = "gateway,localhost,127.0.0.1"
	}
	env["LANG"] = "C.UTF-8"

	if d.Claude {
		env["DISABLE_AUTOUPDATER"] = "1" // the version is pinned; updates would need hosts we do not allow
		if !c.Agent.Telemetry {
			env["DISABLE_TELEMETRY"] = "1"
			env["DISABLE_ERROR_REPORTING"] = "1"
			env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
		}
		if !c.Agent.MCPConnectors {
			env["ENABLE_CLAUDEAI_MCP_SERVERS"] = "false"
		}
	}
	has := map[string]bool{}
	for _, s := range d.Stacks {
		has[s] = true
	}
	if has["python"] {
		env["PYTHONPYCACHEPREFIX"] = "/home/dev/.cache/pycache" // keeps __pycache__ off the workspace mount
	}
	if has["go"] {
		env["GOTOOLCHAIN"] = "local" // never silently download a toolchain (the host is not allowlisted)
	}
	if has["node"] {
		env["NPM_CONFIG_UPDATE_NOTIFIER"] = "false"
		env["NPM_CONFIG_FUND"] = "false"
	}
	if has["dotnet"] {
		env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
		env["DOTNET_NOLOGO"] = "1"
	}
	if c.Git.UserName != "" {
		env["GIT_AUTHOR_NAME"], env["GIT_COMMITTER_NAME"] = c.Git.UserName, c.Git.UserName
	}
	if c.Git.UserEmail != "" {
		env["GIT_AUTHOR_EMAIL"], env["GIT_COMMITTER_EMAIL"] = c.Git.UserEmail, c.Git.UserEmail
	}
	if d.SecretsEnv != "" {
		env["KENNEL_SECRETS_ENV"] = d.SecretsEnv
	}
	for k, v := range c.Agent.Env { // validated: cannot override anything set above
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]KV, 0, len(keys))
	for _, k := range keys {
		out = append(out, KV{k, env[k]})
	}
	return out
}
