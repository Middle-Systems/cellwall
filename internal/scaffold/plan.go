// Package scaffold decides what `cellwall init` may write into a project and writes it safely.
//
// The rules (docs/decisions/0006): never overwrite a file that did not come from cellwall, never
// overwrite one a human edited, never write through a symlink, and write nothing at all when any
// file is in conflict. Re-running with unchanged inputs writes nothing.
package scaffold

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/middle-systems/cellwall/internal/config"
	"github.com/middle-systems/cellwall/internal/detect"
	"github.com/middle-systems/cellwall/internal/gen"
	"github.com/middle-systems/cellwall/internal/pins"
	"github.com/middle-systems/cellwall/internal/safefs"
)

// Options are the inputs `init` passes in.
type Options struct {
	Root string
	// Project overrides the name derived from the directory.
	Project string
	// Stacks overrides detection ("auto" or empty means detect).
	Stacks []string
	// WorkspaceMode is "bind" or "volume"; empty keeps the default.
	WorkspaceMode string
	// Agent is "claude" or "none"; empty keeps the default.
	Agent string
	// Merge writes into .devcontainer/cellwall/ and leaves any existing devcontainer setup alone.
	Merge bool
	// Force overwrites generated files even if a human edited them or they never came from cellwall.
	// Seed files (.cellwall/config.yaml, policy.yaml) are never overwritten.
	Force bool
	// GlobalConfigDir is the user-global config directory ("" disables it).
	GlobalConfigDir string
	// GOOS is the host operating system; empty means runtime.GOOS. It picks the default
	// workspace mode (tests set it).
	GOOS string
	// HasCommit reports whether root is a git repository with at least one commit; nil runs git.
	HasCommit func(root string) bool
}

// defaultWorkspaceMode follows the spec (section 4.5): bind on Linux, volume on macOS and Windows
// where bind mounts are slow or awkward. Volume mode moves the repository through git, so a
// project that is not a repository with a commit falls back to bind, and says so.
func defaultWorkspaceMode(opts Options, root string) (mode, note string) {
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos != "darwin" && goos != "windows" {
		return "bind", ""
	}
	has := opts.HasCommit
	if has == nil {
		has = gitHasCommit
	}
	if !has(root) {
		return "bind", "workspace.mode is bind: volume mode is the default on " + goos + " (bind mounts are slow there) but needs a git repository with a commit. After `git init && git add -A && git commit`, set workspace.mode: volume"
	}
	return "volume", "workspace.mode is volume (the default on " + goos + ", where bind mounts are slow): the agent works on its own copy, `cellwall up` seeds it from this repository and `cellwall fetch` brings its commits back. Use `cellwall init --workspace bind` to mount this directory instead"
}

func gitHasCommit(root string) bool {
	return exec.CommandContext(context.Background(), "git", "-C", root, "rev-parse", "--verify", "-q", "HEAD").Run() == nil //nolint:gosec // argv only
}

// ActionKind is what will happen to one file.
type ActionKind int

const (
	// Create writes a file that does not exist.
	Create ActionKind = iota
	// Unchanged leaves a file that already has exactly the intended content.
	Unchanged
	// Update regenerates a pristine generated file whose intended content changed.
	Update
	// Keep leaves an existing file alone: a seed the user owns, or a generated file a human edited.
	Keep
	// Overwrite replaces a file because --force was given.
	Overwrite
	// Conflict means the file exists and is not ours to replace; nothing is written.
	Conflict
)

func (k ActionKind) String() string {
	return [...]string{"create", "unchanged", "update", "keep", "overwrite", "CONFLICT"}[k]
}

// Action pairs a file with the decision taken for it.
type Action struct {
	File   gen.File
	Kind   ActionKind
	Reason string
}

// Plan is everything `init` intends to do.
type Plan struct {
	Root     string
	Config   *config.Config
	Detect   *detect.Result
	Detected detect.Plan
	Inputs   gen.Inputs
	Actions  []Action
	Warnings []string
	Notes    []string
	// ConfigExisted is true when .cellwall/config.yaml was already present and was used as is.
	ConfigExisted bool
}

// Conflicts returns the actions that block writing.
func (p *Plan) Conflicts() []Action {
	var out []Action
	for _, a := range p.Actions {
		if a.Kind == Conflict {
			out = append(out, a)
		}
	}
	return out
}

var invalidProjectChars = regexp.MustCompile(`[^a-z0-9_-]+`)

// ProjectName derives a valid compose project name from a directory name.
func ProjectName(dir string) string {
	name := strings.ToLower(filepath.Base(dir))
	name = invalidProjectChars.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-_")
	if name == "" {
		name = "project"
	}
	if len(name) > 39 {
		name = strings.Trim(name[:39], "-_")
	}
	return name
}

// Build computes the plan. It only reads the project; nothing is written.
func Build(opts Options) (*Plan, error) {
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	p := &Plan{Root: root}

	res, err := detect.Detect(root)
	if err != nil {
		return nil, err
	}
	p.Detect = res
	p.Notes = append(p.Notes, res.Notes...)

	cfg, existed, notes, err := loadOrSeed(root, opts, res)
	if err != nil {
		return nil, err
	}
	p.Notes = append(p.Notes, notes...)
	p.Config, p.ConfigExisted = cfg, existed
	if existed {
		if len(opts.Stacks) > 0 || opts.WorkspaceMode != "" || opts.Agent != "" || opts.Project != "" || opts.Merge {
			p.Warnings = append(p.Warnings, ".cellwall/config.yaml already exists, so --stack/--workspace/--agent/--project/--merge were ignored; edit that file instead")
		}
	}

	in, planned, err := InputsFor(root, cfg, res)
	if err != nil {
		return nil, err
	}
	p.Detected = planned
	p.Notes = append(p.Notes, planned.Notes...)
	p.Inputs = in
	planRes := in.Detect

	files, err := gen.Committed(p.Inputs, p.Detected.Presets)
	if err != nil {
		return nil, err
	}
	p.Actions, err = classify(root, files, opts.Force)
	if err != nil {
		return nil, err
	}
	p.addDevcontainerConflicts(root, opts)
	p.addWarnings(root, planRes)
	return p, nil
}

// InputsFor computes the generator inputs for a project: stack detection (adjusted for an explicit
// `stacks:` list), the cache/port/preset plan, and the config. res may be nil, in which case the
// project is scanned.
func InputsFor(root string, cfg *config.Config, res *detect.Result) (gen.Inputs, detect.Plan, error) {
	if res == nil {
		var err error
		if res, err = detect.Detect(root); err != nil {
			return gen.Inputs{}, detect.Plan{}, err
		}
	}
	planRes := effectiveDetect(res, cfg)
	gi := detect.ParseGitIgnore(readText(filepath.Join(root, ".gitignore")))
	plan := detect.PlanFor(planRes, gi.Ignored, func(rel string) bool { return occupied(root, rel) })
	return gen.Inputs{Config: cfg, Detect: planRes, Plan: plan}, plan, nil
}

// effectiveDetect returns the detection result adjusted for an explicit `stacks:` list.
func effectiveDetect(res *detect.Result, cfg *config.Config) *detect.Result {
	if cfg.Stacks.Auto {
		return res
	}
	want := map[string]bool{}
	for _, s := range cfg.Stacks.Items {
		want[s] = true
	}
	out := &detect.Result{Notes: res.Notes}
	have := map[string]bool{}
	for _, s := range res.Stacks {
		if want[s.Name] {
			out.Stacks = append(out.Stacks, s)
			have[s.Name] = true
		}
	}
	for _, name := range config.KnownStacks {
		if want[name] && !have[name] {
			out.Stacks = append(out.Stacks, detect.Stack{Name: name, Dir: "."})
		}
	}
	return out
}

// occupied reports whether root/rel exists and holds something: a non-directory, a symlink, or a
// directory with at least one entry. An absent or empty directory hides nothing.
func occupied(root, rel string) bool {
	p := filepath.Join(root, filepath.FromSlash(rel))
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	if !fi.IsDir() {
		return true
	}
	entries, err := os.ReadDir(p)
	return err != nil || len(entries) > 0
}

func readText(p string) string {
	b, err := os.ReadFile(p) //nolint:gosec // project-relative file
	if err != nil {
		return ""
	}
	return string(b)
}

// loadOrSeed uses the existing config, or builds one from defaults, flags and detection, round-trips
// it through the real parser so what the user sees is exactly what gets validated and generated.
func loadOrSeed(root string, opts Options, res *detect.Result) (*config.Config, bool, []string, error) {
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(config.ProjectFile))); err == nil {
		l, err := config.Load(config.LoadOptions{ProjectDir: root, GlobalDir: opts.GlobalConfigDir})
		if err != nil {
			return nil, true, nil, err
		}
		return l.Config, true, nil, nil
	}

	cfg := config.Default()
	cfg.Project = opts.Project
	if cfg.Project == "" {
		cfg.Project = ProjectName(root)
	}
	if len(opts.Stacks) > 0 && (len(opts.Stacks) != 1 || opts.Stacks[0] != "auto") {
		cfg.Stacks = config.AutoList{Items: opts.Stacks}
	}
	var notes []string
	if opts.WorkspaceMode != "" {
		cfg.Workspace.Mode = opts.WorkspaceMode
	} else if mode, note := defaultWorkspaceMode(opts, root); mode != cfg.Workspace.Mode || note != "" {
		cfg.Workspace.Mode = mode
		if note != "" {
			notes = append(notes, note)
		}
	}
	if opts.Agent != "" {
		cfg.Agent.Preset = opts.Agent
		if opts.Agent == "none" {
			cfg.Agent.Command = []string{"bash"}
		}
	}
	if opts.Merge {
		cfg.Devcontainer.Dir = config.DevcontainerMergeDir
	}
	if err := cfg.Validate(); err != nil {
		return nil, false, nil, fmt.Errorf("invalid options: %w", err)
	}
	planRes := effectiveDetect(res, cfg)
	gi := detect.ParseGitIgnore(readText(filepath.Join(root, ".gitignore")))
	pl := detect.PlanFor(planRes, gi.Ignored, func(rel string) bool { return occupied(root, rel) })
	cfg.Ports = pl.Ports

	seed, err := gen.Committed(gen.Inputs{Config: cfg, Detect: planRes, Plan: pl}, pl.Presets)
	if err != nil {
		return nil, false, nil, err
	}
	var text []byte
	for _, f := range seed {
		if f.Path == config.ProjectFile {
			text = f.Content
		}
	}
	parsed, err := config.Parse(config.ProjectFile, text, config.LayerProject, config.Default())
	if err != nil {
		return nil, false, nil, fmt.Errorf("internal error: generated config does not parse: %w", err)
	}
	if err := parsed.Validate(); err != nil {
		return nil, false, nil, fmt.Errorf("internal error: generated config is invalid: %w", err)
	}
	return parsed, false, notes, nil
}

// classify decides the action for each file, and refuses to touch anything reached via a symlink.
func classify(root string, files []gen.File, force bool) ([]Action, error) {
	// Verbatim files (lockfiles) are ours only if the Dockerfile beside them is a pristine generated one.
	dockerfilePristine := map[string]bool{}
	for _, f := range files {
		if filepath.Base(f.Path) == "Dockerfile" {
			b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path))) //nolint:gosec // project-relative
			dockerfilePristine[filepath.ToSlash(filepath.Dir(f.Path))] = err != nil || gen.Inspect(b) == gen.Pristine
		}
	}
	var out []Action
	for _, f := range files {
		abs := filepath.Join(root, filepath.FromSlash(f.Path))
		if why := safefs.SymlinkOnPath(root, f.Path); why != "" {
			out = append(out, Action{File: f, Kind: Conflict, Reason: why})
			continue
		}
		existing, err := os.ReadFile(abs) //nolint:gosec // project-relative, symlink-checked above
		if errors.Is(err, fs.ErrNotExist) {
			out = append(out, Action{File: f, Kind: Create})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f.Path, err)
		}
		same := string(existing) == string(f.Content)
		switch f.Kind {
		case gen.Seed:
			out = append(out, Action{File: f, Kind: Keep, Reason: "yours to edit; never overwritten"})
		case gen.Verbatim:
			dir := filepath.ToSlash(filepath.Dir(filepath.Dir(filepath.Dir(f.Path)))) // <dir>/agent/claude/x -> <dir>
			switch {
			case same:
				out = append(out, Action{File: f, Kind: Unchanged})
			case dockerfilePristine[dir]:
				out = append(out, Action{File: f, Kind: Update, Reason: "pinned agent files changed"})
			case force:
				out = append(out, Action{File: f, Kind: Overwrite, Reason: "--force"})
			default:
				out = append(out, Action{File: f, Kind: Conflict, Reason: "exists and differs, and the Dockerfile beside it is not an unmodified cellwall file"})
			}
		default:
			switch state := gen.Inspect(existing); {
			case same:
				out = append(out, Action{File: f, Kind: Unchanged})
			case state == gen.Pristine:
				out = append(out, Action{File: f, Kind: Update, Reason: "regenerated from the current configuration"})
			case force:
				out = append(out, Action{File: f, Kind: Overwrite, Reason: "--force (was: " + state.String() + ")"})
			case state == gen.Edited:
				out = append(out, Action{File: f, Kind: Keep, Reason: "you edited this generated file; kept as is (use --force to regenerate it)"})
			default:
				out = append(out, Action{File: f, Kind: Conflict, Reason: "exists and was not generated by cellwall"})
			}
		}
	}
	return out, nil
}

// addDevcontainerConflicts flags an existing devcontainer configuration that would be shadowed.
func (p *Plan) addDevcontainerConflicts(root string, opts Options) {
	if p.Config.Devcontainer.Dir != config.DevcontainerDir || opts.Force {
		return
	}
	if fi, err := os.Lstat(filepath.Join(root, ".devcontainer.json")); err == nil && fi.Mode().IsRegular() {
		b, _ := os.ReadFile(filepath.Join(root, ".devcontainer.json")) //nolint:gosec // project-relative
		if gen.Inspect(b) == gen.Unstamped {
			p.Actions = append(p.Actions, Action{
				File:   gen.File{Path: ".devcontainer.json"},
				Kind:   Conflict,
				Reason: "an existing devcontainer configuration (.devcontainer.json) would be shadowed by .devcontainer/devcontainer.json",
			})
		}
	}
}

func (p *Plan) addWarnings(root string, res *detect.Result) {
	c := p.Config
	if c.Agent.Preset == "claude" {
		if _, _, ok := pins.ClaudeLock(c.Agent.Version); !ok {
			p.Warnings = append(p.Warnings, fmt.Sprintf("agent.version %s has no cellwall integrity pin: the image installs it trusting the npm registry's metadata (pinned: %s)", c.Agent.Version, pins.ClaudeCodeVersion))
		}
	}
	if c.Workspace.Mode == "volume" {
		p.Warnings = append(p.Warnings, "workspace.mode: volume needs seeding and `cellwall fetch`, which arrive in M5; use \"bind\" until then")
	}
	for _, s := range res.Stacks {
		if s.Name == "go" && s.Version != "" && goNewer(s.Version, pins.GoVersion) {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s/go.mod asks for Go %s but the image has Go %s; GOTOOLCHAIN=local stops it downloading a newer one (refresh the pins)", s.Dir, s.Version, pins.GoVersion))
		}
	}
	for _, h := range p.Detected.BindHints {
		p.Notes = append(p.Notes, "dev server must listen on 0.0.0.0 inside the sandbox — "+h)
	}
	if fi, err := os.Lstat(filepath.Join(root, ".git")); err == nil && fi.Mode().IsRegular() {
		p.Warnings = append(p.Warnings, ".git is a file (a git worktree or submodule): the real git directory is outside the project and will not be mounted, so git will not work inside the sandbox")
	}
	if b, err := os.ReadFile(filepath.Join(root, ".git", "config")); err == nil { //nolint:gosec // project-relative
		p.Warnings = append(p.Warnings, gen.GitConfigWarnings(string(b))...)
	}
}

// goNewer reports whether want (e.g. "1.28") is a newer major.minor than have (e.g. "1.27.1").
func goNewer(want, have string) bool {
	parse := func(v string) (int, int) {
		var maj, min int
		_, _ = fmt.Sscanf(v, "%d.%d", &maj, &min) // malformed versions compare as 0.0
		return maj, min
	}
	wm, wn := parse(want)
	hm, hn := parse(have)
	return wm > hm || (wm == hm && wn > hn)
}
