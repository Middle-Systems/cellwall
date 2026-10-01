// Package prepare turns a project's committed configuration into the live state the sandbox runs
// on: the effective gateway policy, the per-session compose override (protected-path mounts and
// secrets), and the host directories Docker would otherwise create as root.
//
// It is idempotent: running it again with nothing changed rewrites nothing, so the gateway's policy
// watcher is never poked for no reason.
package prepare

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/middle-systems/cellwall/internal/config"
	"github.com/middle-systems/cellwall/internal/gen"
	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/safefs"
	"github.com/middle-systems/cellwall/internal/scaffold"
)

// Options configures Run.
type Options struct {
	Root            string
	GlobalConfigDir string
	// UID/GID of the sandbox user. Zero values use the invoking user (or 1000 on Windows and when
	// running as root: the sandbox user is never root).
	UID, GID int
	// GatewayImage is the gateway image reference written to compose.env. Release builds pass a
	// digest reference; the default is the locally built tag.
	GatewayImage string
	// EngineCPUs is the number of CPUs the container engine reports (0 = unknown). A configured
	// hardening.cpus above it is clamped to it, because Docker rejects such a limit outright.
	EngineCPUs int
}

// DefaultGatewayImage is what compose uses when no digest-pinned image has been supplied.
const DefaultGatewayImage = "cellwall-gateway:local"

// Result describes what prepare did and found.
type Result struct {
	Config     *config.Config
	Policy     *policy.Compiled
	Presets    []string // the effective preset list, including the ones the agent preset implies
	Protected  gen.ProtectedPlan
	Appeared   []string // protected paths that did not exist at the last prepare but do now
	Written    []string
	Unchanged  []string
	CachesMade []string
	// Relaxations and Warnings are always shown to the user (ADR 0003).
	Relaxations []string
	Warnings    []string
}

// manifest is the machine-readable record of the last prepare. It holds no secrets and no times.
type manifest struct {
	Version     int      `json:"version"`
	ConfigHash  string   `json:"config_hash"`
	PolicyHash  string   `json:"policy_hash"`
	Mounted     []string `json:"protected_mounted"`
	Missing     []string `json:"protected_missing"`
	Symlinked   []string `json:"protected_symlinked"`
	Relaxations []string `json:"relaxations"`
}

const manifestPath = gen.StateDirRel + "/manifest.json"

// AgentPresets are the gateway presets the agent configuration implies. They come from config,
// not from policy.yaml, so a typed option (telemetry, MCP connectors) and the allowlist can never
// disagree.
func AgentPresets(c *config.Config) []string {
	if c.Agent.Preset != "claude" {
		return nil
	}
	out := []string{"claude"}
	if c.Agent.Telemetry {
		out = append(out, "claude-telemetry")
	}
	if c.Agent.MCPConnectors {
		out = append(out, "claude-mcp-connectors")
	}
	return out
}

// Run prepares the project.
func Run(opts Options) (*Result, error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}
	loaded, err := config.Load(config.LoadOptions{ProjectDir: root, GlobalDir: opts.GlobalConfigDir})
	if err != nil {
		return nil, err
	}
	cfg := loaded.Config
	res := &Result{Config: cfg}

	// The state directory is reached through the repository; refuse to follow a planted symlink.
	if why := safefs.SymlinkOnPath(root, gen.StateDirRel); why != "" {
		return nil, fmt.Errorf("%s", why)
	}
	if why := safefs.SymlinkOnPath(root, ".cellwall"); why != "" {
		return nil, fmt.Errorf("%s", why)
	}

	// What was missing last time and exists now was created during a session.
	res.Appeared = appearedSince(root)

	// Policy: agent-implied presets < user-global < project.
	pol, warns, err := effectivePolicy(root, opts.GlobalConfigDir, cfg)
	if err != nil {
		return nil, err
	}
	res.Policy, res.Warnings = pol, append(res.Warnings, warns...)
	res.Presets = presetNames(pol)
	res.Relaxations = append(cfg.Relaxations(), policy.Relaxations(pol.Findings)...)

	canon, err := policy.Canonical(pol.Policy)
	if err != nil {
		return nil, err
	}
	stateDir := filepath.Join(root, filepath.FromSlash(gen.StateDirRel))
	for _, d := range []string{"policy", "audit"} {
		if err := os.MkdirAll(filepath.Join(stateDir, d), 0o755); err != nil { //nolint:gosec // the gateway user must be able to read/write these
			return nil, err
		}
	}
	res.record(root, writeIf(filepath.Join(stateDir, "policy", "policy.json"), canon))

	// Protected paths, cache directories, secrets.
	in, _, err := scaffold.InputsFor(root, cfg, nil)
	if err != nil {
		return nil, err
	}
	data, err := gen.NewData(in)
	if err != nil {
		return nil, err
	}
	layout := gen.LayoutFor(cfg)
	if cfg.Workspace.Mode == "bind" {
		res.Protected = gen.PlanProtected(cfg.ProtectedSet(), gen.WorkspaceExpr(layout), gen.StatFS(root))
		res.warnProtected()
		made, w := ensureCacheDirs(root, data.Caches)
		res.CachesMade, res.Warnings = made, append(res.Warnings, w...)
	} else {
		res.Warnings = append(res.Warnings, "workspace.mode: volume — protected paths cannot be enforced with bind mounts; `cellwall fetch` will gate them (M5)")
	}
	secretSources, warns, err := resolveSecrets(cfg)
	if err != nil {
		return nil, err
	}
	res.Warnings = append(res.Warnings, warns...)

	override, err := gen.Override(gen.OverrideInputs{Config: cfg, Mounts: res.Protected.Mounts, SecretSources: secretSources})
	if err != nil {
		return nil, err
	}
	uid, gid, w := sandboxIDs(opts)
	res.Warnings = append(res.Warnings, w...)
	image := opts.GatewayImage
	if image == "" {
		image = DefaultGatewayImage
	}
	clamp := 0.0
	if opts.EngineCPUs > 0 && cfg.Hardening.CPUs > float64(opts.EngineCPUs) {
		clamp = float64(opts.EngineCPUs)
		res.Warnings = append(res.Warnings, fmt.Sprintf("hardening.cpus is %g but the container engine has %d CPUs; using %d (raise the engine's CPU allocation, or lower hardening.cpus in .cellwall/config.yaml)", cfg.Hardening.CPUs, opts.EngineCPUs, opts.EngineCPUs))
	}
	env, err := gen.EnvFile(uid, gid, root, stateDir, image, clamp)
	if err != nil {
		return nil, err
	}
	for _, f := range []gen.File{override, env} {
		res.record(root, writeIf(filepath.Join(root, filepath.FromSlash(f.Path)), f.Content))
	}

	mf, _ := json.MarshalIndent(manifest{
		Version: 1, ConfigHash: cfg.Hash(), PolicyHash: pol.Hash,
		Mounted: nz(res.Protected.Mounted), Missing: nz(res.Protected.Missing), Symlinked: nz(res.Protected.Symlinked),
		Relaxations: nz(res.Relaxations),
	}, "", "  ")
	res.record(root, writeIf(filepath.Join(root, filepath.FromSlash(manifestPath)), append(mf, '\n')))

	if b, err := os.ReadFile(filepath.Join(root, ".git", "config")); err == nil { //nolint:gosec // project-relative
		res.Warnings = append(res.Warnings, gen.GitConfigWarnings(string(b))...)
	}
	res.Warnings = append(res.Warnings, driftWarnings(root, opts)...)
	return res, nil
}

// driftWarnings reports generated container files that no longer match the configuration. Without
// this, editing .cellwall/config.yaml and forgetting `cellwall init` leaves the sandbox running
// with the old settings and nothing says so.
func driftWarnings(root string, opts Options) []string {
	plan, err := scaffold.Build(scaffold.Options{Root: root, GlobalConfigDir: opts.GlobalConfigDir})
	if err != nil {
		return nil
	}
	var stale []string
	for _, a := range plan.Actions {
		if a.Kind == scaffold.Update {
			stale = append(stale, a.File.Path)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)
	return []string{"generated files are out of date with .cellwall/config.yaml (" + strings.Join(stale, ", ") + "): run `cellwall init` to regenerate them"}
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type writeResult struct {
	path    string
	changed bool
	err     error
}

func writeIf(path string, content []byte) writeResult {
	changed, err := safefs.WriteIfChanged(path, content, 0o644)
	return writeResult{path: path, changed: changed, err: err}
}

func (r *Result) record(root string, w writeResult) {
	rel, _ := filepath.Rel(root, w.path)
	rel = filepath.ToSlash(rel)
	switch {
	case w.err != nil:
		r.Warnings = append(r.Warnings, fmt.Sprintf("could not write %s: %v", rel, w.err))
	case w.changed:
		r.Written = append(r.Written, rel)
	default:
		r.Unchanged = append(r.Unchanged, rel)
	}
}

func (r *Result) warnProtected() {
	for _, p := range r.Protected.Symlinked {
		r.Warnings = append(r.Warnings, fmt.Sprintf("protected path %s is a symlink and cannot be mounted read-only: the agent could replace it. Replace it with a real file/directory, or accept the risk", p))
	}
	for _, p := range r.Appeared {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%s did not exist at the last prepare but does now: it was created during a session. Review it before running anything from it on the host (it is read-only inside the sandbox from now on)", p))
	}
}

// appearedSince compares the previous manifest's missing paths with the filesystem.
func appearedSince(root string) []string {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifestPath))) //nolint:gosec // project-relative
	if err != nil {
		return nil
	}
	var m manifest
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	stat := gen.StatFS(root)
	var out []string
	for _, p := range m.Missing {
		if stat(p).Exists {
			out = append(out, p)
		}
	}
	return out
}

// Appeared is the exported form used by `status`/`down` to report protected paths created during
// a session (docs/decisions/0002).
func Appeared(root string) []string { return appearedSince(root) }

func presetNames(c *policy.Compiled) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range c.Policy.Rules {
		if name, ok := strings.CutPrefix(r.Source, "preset:"); ok && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// effectivePolicy layers the policies and compiles them.
func effectivePolicy(root, globalDir string, cfg *config.Config) (*policy.Compiled, []string, error) {
	var warns []string
	agent := &policy.Policy{Version: policy.Version, Presets: AgentPresets(cfg)}

	var global *policy.Policy
	if globalDir != "" {
		g, err := readPolicy(filepath.Join(globalDir, "policy.yaml"))
		if err != nil {
			return nil, nil, err
		}
		if g != nil {
			for i, r := range g.Rules {
				if r.UnsafeAllowHTTP || r.UnsafeAllowPrivate || r.UnsafeAllowECH || r.UnsafeSkipTLSCheck || r.UnsafeDangerousWildcard {
					return nil, nil, fmt.Errorf("%s: rules[%d] (%s) sets an unsafe_* option, which is only honoured in the project policy where it can be reviewed", filepath.Join(globalDir, "policy.yaml"), i, r.Host)
				}
			}
			if g.Limits != (policy.Limits{}) {
				for _, v := range []int64{int64(g.Limits.MaxConns), g.Limits.MaxBytesPerConn, int64(g.Limits.MaxNewConnsPerHostPerMin)} {
					if v < 0 {
						return nil, nil, fmt.Errorf("%s: unlimited limits are only honoured in the project policy", filepath.Join(globalDir, "policy.yaml"))
					}
				}
			}
			global = g
		}
	}
	projPath := filepath.Join(root, ".cellwall", "policy.yaml")
	project, err := readPolicy(projPath)
	if err != nil {
		return nil, nil, err
	}
	if project == nil {
		warns = append(warns, ".cellwall/policy.yaml not found: only the agent's own hosts are allowed (run `cellwall init`)")
	}
	merged := policy.Merge(agent, global, project)
	c, err := policy.Compile(merged, false)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: %w", err)
	}
	return c, warns, nil
}

// readPolicy returns nil, nil when the file does not exist.
func readPolicy(path string) (*policy.Policy, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-controlled location
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := policy.Parse(path, b)
	if err != nil {
		return nil, err
	}
	if err := p.Validate(false); err != nil {
		return nil, err
	}
	return p, nil
}

// ensureCacheDirs creates cache directories as the invoking user. Left to Docker, a volume mounted
// at a path that does not exist makes Docker create it in the repository owned by root (spike S10).
func ensureCacheDirs(root string, caches []gen.CacheVolume) (made, warns []string) {
	for _, c := range caches {
		if why := safefs.SymlinkOnPath(root, c.Path); why != "" {
			warns = append(warns, "cache volume "+c.Path+": "+why)
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(c.Path))
		fi, err := os.Lstat(abs)
		switch {
		case err == nil && !fi.IsDir():
			warns = append(warns, "cache volume "+c.Path+" exists but is not a directory; the volume cannot be mounted over it")
		case err == nil:
			// already there, owned by whoever created it
		default:
			if err := os.MkdirAll(abs, 0o755); err != nil { //nolint:gosec // an ordinary project directory
				warns = append(warns, "cache volume "+c.Path+": "+err.Error())
				continue
			}
			made = append(made, c.Path)
		}
	}
	sort.Strings(made)
	return made, warns
}

// resolveSecrets expands ~ and checks each secret file exists. It never reads a secret.
func resolveSecrets(cfg *config.Config) (map[string]string, []string, error) {
	out := map[string]string{}
	var warns []string
	for _, s := range cfg.Secrets {
		p := s.SourceFile
		if strings.HasPrefix(p, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, nil, fmt.Errorf("secret %q: cannot expand ~: %w", s.Name, err)
			}
			p = filepath.Join(home, filepath.FromSlash(p[2:]))
		}
		fi, err := os.Stat(p)
		if err != nil {
			return nil, nil, fmt.Errorf("secret %q: %s is not readable (%w). Create it, or remove the secret from .cellwall/config.yaml", s.Name, p, err)
		}
		if !fi.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("secret %q: %s is not a regular file", s.Name, p)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
			warns = append(warns, fmt.Sprintf("secret %q: %s is readable by other users (mode %04o); consider chmod 600", s.Name, p, fi.Mode().Perm()))
		}
		out[s.Name] = filepath.ToSlash(p)
	}
	return out, warns, nil
}

func sandboxIDs(opts Options) (uid, gid int, warns []string) {
	uid, gid = opts.UID, opts.GID
	if uid == 0 && gid == 0 {
		if runtime.GOOS == "windows" {
			return 1000, 1000, nil // no uid concept; Docker Desktop maps ownership
		}
		uid, gid = os.Getuid(), os.Getgid()
	}
	if uid == 0 || gid == 0 {
		return 1000, 1000, []string{"running as root: the sandbox user is uid/gid 1000, not root"}
	}
	if uid < 0 || gid < 0 {
		return 1000, 1000, nil
	}
	return uid, gid, nil
}
