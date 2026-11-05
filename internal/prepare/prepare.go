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
	"strconv"
	"strings"

	"github.com/middle-systems/kennel/internal/config"
	"github.com/middle-systems/kennel/internal/gen"
	"github.com/middle-systems/kennel/internal/policy"
	"github.com/middle-systems/kennel/internal/policyedit"
	"github.com/middle-systems/kennel/internal/safefs"
	"github.com/middle-systems/kennel/internal/scaffold"
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
const DefaultGatewayImage = "kennel-gateway:local"

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
	// GatewayImage is the image reference written to compose.env.
	GatewayImage string
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

	uid, gid, idWarns := sandboxIDs(opts)
	res.Warnings = append(res.Warnings, idWarns...)

	// The state directory is reached through the repository; refuse to follow a planted symlink.
	if why := safefs.SymlinkOnPath(root, gen.StateDirRel); why != "" {
		return nil, fmt.Errorf("%s", why)
	}
	if why := safefs.SymlinkOnPath(root, ".kennel"); why != "" {
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
	res.Relaxations = append(res.Relaxations, SessionRules(root)...)

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
	chownIfRoot(filepath.Join(stateDir, "audit"), uid, gid)
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
		made, w := ensureCacheDirs(root, data.Caches, uid, gid)
		res.CachesMade, res.Warnings = made, append(res.Warnings, w...)
	} else {
		res.Warnings = append(res.Warnings, "workspace.mode: volume — the agent works on its own copy, so protected paths cannot be mounted read-only; `kennel fetch` holds changes to them for your confirmation instead")
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
	image := opts.GatewayImage
	if image == "" {
		// Keep what an earlier `up --gateway-image` chose, so later runs of prepare (from `allow`,
		// `deny`, ...) do not silently switch the gateway back to the default tag.
		image = existingGatewayImage(root)
	}
	if image == "" {
		image = DefaultGatewayImage
	}
	clamp := 0.0
	if opts.EngineCPUs > 0 && cfg.Hardening.CPUs > float64(opts.EngineCPUs) {
		clamp = float64(opts.EngineCPUs)
		res.Warnings = append(res.Warnings, fmt.Sprintf("hardening.cpus is %g but the container engine has %d CPUs; using %d (raise the engine's CPU allocation, or lower hardening.cpus in .kennel/config.yaml)", cfg.Hardening.CPUs, opts.EngineCPUs, opts.EngineCPUs))
	}
	res.GatewayImage = image
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
// this, editing .kennel/config.yaml and forgetting `kennel init` leaves the sandbox running
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
	return []string{"generated files are out of date with .kennel/config.yaml (" + strings.Join(stale, ", ") + "): run `kennel init` to regenerate them"}
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
// MountedPaths returns the protected paths that existed at the last prepare and were mounted
// read-only, relative to the project root.
func MountedPaths(root string) []string {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifestPath))) //nolint:gosec // project-relative
	if err != nil {
		return nil
	}
	var m manifest
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return append([]string(nil), m.Mounted...)
}

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
	merged, warns, err := MergedPolicy(root, globalDir, cfg)
	if err != nil {
		return nil, nil, err
	}
	c, err := policy.Compile(merged, false)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: %w", err)
	}
	return c, warns, nil
}

// MergedPolicy layers the agent's presets, the user-global policy, the project policy and the
// session rules into one unexpanded, uncompiled policy. Compile refuses dangerous rules; this
// does not, so `policy lint` can show them.
func MergedPolicy(root, globalDir string, cfg *config.Config) (*policy.Policy, []string, error) {
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
	projPath := filepath.Join(root, ".kennel", "policy.yaml")
	project, err := readPolicy(projPath)
	if err != nil {
		return nil, nil, err
	}
	if project == nil {
		warns = append(warns, ".kennel/policy.yaml not found: only the agent's own hosts are allowed (run `kennel init`)")
	}
	// The session layer (`kennel allow` / `deny` without --save) has the highest precedence.
	session, err := policyedit.LoadSession(root)
	if err != nil {
		return nil, nil, err
	}
	return policy.Merge(agent, global, project, session), warns, nil
}

// SessionRules describes the rules in the session layer for display next to other relaxations.
func SessionRules(root string) []string {
	sess, _ := policyedit.LoadSession(root)
	if sess == nil {
		return nil
	}
	var out []string
	for _, r := range sess.Rules {
		out = append(out, fmt.Sprintf("session rule (not committed): %s %s%s", actionOf(r), r.Host, portsOf(r)))
	}
	return out
}

func actionOf(r policy.Rule) string {
	if r.IsDeny() {
		return "deny"
	}
	return "allow"
}

func portsOf(r policy.Rule) string {
	if len(r.Ports) == 0 {
		return ""
	}
	var parts []string
	for _, p := range r.Ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return " (ports " + strings.Join(parts, ",") + ")"
}

// existingGatewayImage reads the image recorded by the previous prepare, or "".
func existingGatewayImage(root string) string {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(gen.StateDirRel), "compose.env")) //nolint:gosec // fixed location in the project's state dir
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "KENNEL_GATEWAY_IMAGE="); ok {
			return strings.Trim(strings.TrimSpace(v), "'")
		}
	}
	return ""
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

// chownIfRoot hands a directory this process just created to the sandbox user. When kennel runs
// as root (sudo, a root-only CI runner) the sandbox still runs as an unprivileged uid, and a
// root-owned audit or cache directory would be unwritable for it: the gateway could not open its
// audit log and refuses to start (fail closed). A non-root user needs nothing: the sandbox uid is
// their own.
func chownIfRoot(path string, uid, gid int) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 || uid <= 0 || gid <= 0 {
		return
	}
	_ = os.Chown(path, uid, gid) // best effort: a failure surfaces as the gateway's own clear error
}

// ensureCacheDirs creates cache directories as the invoking user. Left to Docker, a volume mounted
// at a path that does not exist makes Docker create it in the repository owned by root (spike S10).
func ensureCacheDirs(root string, caches []gen.CacheVolume, uid, gid int) (made, warns []string) {
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
			chownIfRoot(abs, uid, gid)
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
			return nil, nil, fmt.Errorf("secret %q: %s is not readable (%w). Create it, or remove the secret from .kennel/config.yaml", s.Name, p, err)
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
