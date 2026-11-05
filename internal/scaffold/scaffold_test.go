package scaffold

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/middle-systems/kennel/internal/config"
	"github.com/middle-systems/kennel/internal/gen"
)

// project copies a fixture into a fresh temp dir named name.
func project(t *testing.T, fixture, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "test", "fixtures", fixture)
	dst := filepath.Join(t.TempDir(), name)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// snapshot records every file's content hash and mtime.
type snap map[string]string

func snapshot(t *testing.T, root string) snap {
	t.Helper()
	s := snap{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		fi, _ := d.Info()
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(root, p)
		s[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:8]) + "@" + fi.ModTime().Format(time.RFC3339Nano)
		return nil
	})
	return s
}

func diff(a, b snap) []string {
	var out []string
	for k, v := range b {
		if a[k] != v {
			out = append(out, k)
		}
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k+" (removed)")
		}
	}
	sort.Strings(out)
	return out
}

func initProject(t *testing.T, root string, o Options) (*Plan, *Report, error) {
	t.Helper()
	o.Root = root
	p, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := p.Apply()
	return p, rep, err
}

func TestInitCreatesTheFiles(t *testing.T) {
	root := project(t, "node-vite", "My App")
	p, rep, err := initProject(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.Project != "my-app" {
		t.Errorf("project name = %q", p.Config.Project)
	}
	for _, want := range []string{
		".kennel/config.yaml", ".kennel/policy.yaml", ".kennel/.gitignore",
		".devcontainer/Dockerfile", ".devcontainer/compose.yaml", ".devcontainer/devcontainer.json",
		".devcontainer/entrypoint.sh", ".devcontainer/.gitattributes",
		".devcontainer/agent/claude/package.json", ".devcontainer/agent/claude/package-lock.json",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(want))); err != nil {
			t.Errorf("missing %s", want)
		}
	}
	if len(rep.Written) != 10 {
		t.Errorf("wrote %d files: %v", len(rep.Written), rep.Written)
	}
	fi, _ := os.Stat(filepath.Join(root, ".devcontainer/entrypoint.sh"))
	if fi.Mode()&0o111 == 0 && os.PathSeparator == '/' {
		t.Error("entrypoint.sh must be executable")
	}
	// The seed config is exactly what generation used: it parses and validates on its own.
	l, err := config.Load(config.LoadOptions{ProjectDir: root})
	if err != nil {
		t.Fatalf("seed config does not load: %v", err)
	}
	if l.Config.Hash() != p.Config.Hash() {
		t.Error("the config written must be the config generated from")
	}
	if got := l.Config.Ports; len(got) != 1 || got[0] != 5173 {
		t.Errorf("ports = %v", got)
	}
}

func TestInitIsIdempotent(t *testing.T) {
	for _, fx := range []string{"node-vite", "python-flask", "go-http", "rust-axum", "polyglot"} {
		root := project(t, fx, fx)
		if _, _, err := initProject(t, root, Options{}); err != nil {
			t.Fatalf("%s: %v", fx, err)
		}
		before := snapshot(t, root)
		time.Sleep(10 * time.Millisecond) // any rewrite would change mtime
		p, rep, err := initProject(t, root, Options{})
		if err != nil {
			t.Fatalf("%s second run: %v", fx, err)
		}
		if len(rep.Written) != 0 {
			t.Errorf("%s: second run wrote %v", fx, rep.Written)
		}
		if d := diff(before, snapshot(t, root)); len(d) != 0 {
			t.Errorf("%s: second run changed the tree: %v", fx, d)
		}
		if !p.ConfigExisted {
			t.Errorf("%s: second run should use the config it wrote", fx)
		}
	}
}

func TestExistingDevcontainerIsNeverClobbered(t *testing.T) {
	root := project(t, "existing-devcontainer", "x")
	orig, _ := os.ReadFile(filepath.Join(root, ".devcontainer", "devcontainer.json"))
	before := snapshot(t, root)

	p, err := Build(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	conflicts := p.Conflicts()
	if len(conflicts) == 0 || conflicts[0].File.Path != ".devcontainer/devcontainer.json" {
		t.Fatalf("expected a conflict on devcontainer.json, got %+v", conflicts)
	}
	_, err = p.Apply()
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("Apply must refuse: %v", err)
	}
	if d := diff(before, snapshot(t, root)); len(d) != 0 {
		t.Errorf("a refused init must write NOTHING (not even the non-conflicting files): %v", d)
	}
	now, _ := os.ReadFile(filepath.Join(root, ".devcontainer", "devcontainer.json"))
	if string(now) != string(orig) {
		t.Error("the user's devcontainer.json changed")
	}
}

func TestMergeLeavesTheExistingSetupUntouched(t *testing.T) {
	root := project(t, "existing-devcontainer", "x")
	orig := snapshot(t, root)

	p, rep, err := initProject(t, root, Options{Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.Devcontainer.Dir != config.DevcontainerMergeDir {
		t.Errorf("dir = %q", p.Config.Devcontainer.Dir)
	}
	for _, w := range rep.Written {
		if strings.HasPrefix(w, ".devcontainer/") && !strings.HasPrefix(w, ".devcontainer/kennel/") {
			t.Errorf("--merge wrote outside .devcontainer/kennel/: %s", w)
		}
	}
	after := snapshot(t, root)
	if orig[".devcontainer/devcontainer.json"] != after[".devcontainer/devcontainer.json"] {
		t.Error("the existing devcontainer.json was modified by --merge")
	}
	if _, err := os.Stat(filepath.Join(root, ".devcontainer", "kennel", "devcontainer.json")); err != nil {
		t.Error("merge-mode devcontainer.json missing")
	}
	// The merged layout points back at the project root two levels up.
	b, _ := os.ReadFile(filepath.Join(root, ".devcontainer", "kennel", "compose.yaml"))
	if !strings.Contains(string(b), "${KENNEL_WORKSPACE:-../..}") {
		t.Errorf("merge layout must resolve the workspace as ../..:\n%s", b)
	}
}

func TestForceOverwritesGeneratedButNeverSeeds(t *testing.T) {
	root := project(t, "existing-devcontainer", "x")
	if _, _, err := initProject(t, root, Options{Force: true}); err != nil {
		t.Fatalf("--force must proceed: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ".devcontainer", "devcontainer.json"))
	if gen.Inspect(b) != gen.Pristine {
		t.Error("--force should have replaced the foreign devcontainer.json")
	}
	// Seeds are the user's: edit, then --force again.
	cfgPath := filepath.Join(root, ".kennel", "config.yaml")
	edited := strings.Replace(readFile(t, cfgPath), "mode: bind", "mode: bind # edited", 1)
	_ = os.WriteFile(cfgPath, []byte(edited), 0o644)
	polPath := filepath.Join(root, ".kennel", "policy.yaml")
	_ = os.WriteFile(polPath, []byte("version: 1\nrules:\n  - host: mine.example.com\n"), 0o644)
	if _, _, err := initProject(t, root, Options{Force: true}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, cfgPath) != edited || !strings.Contains(readFile(t, polPath), "mine.example.com") {
		t.Error("--force must never overwrite config.yaml or policy.yaml")
	}
}

func TestEditedGeneratedFilesAreKeptAndReported(t *testing.T) {
	root := project(t, "node-vite", "x")
	initProject(t, root, Options{})
	df := filepath.Join(root, ".devcontainer", "Dockerfile")
	edited := readFile(t, df) + "\nRUN echo my own tweak\n"
	_ = os.WriteFile(df, []byte(edited), 0o644)

	p, rep, err := initProject(t, root, Options{})
	if err != nil {
		t.Fatalf("an edited generated file is kept, not a failure: %v", err)
	}
	if readFile(t, df) != edited {
		t.Error("the user's edit to the Dockerfile was lost")
	}
	kept := strings.Join(rep.Kept, ",")
	if !strings.Contains(kept, ".devcontainer/Dockerfile") {
		t.Errorf("the edit must be reported: %v", rep.Kept)
	}
	var reason string
	for _, a := range p.Actions {
		if a.File.Path == ".devcontainer/Dockerfile" {
			reason = a.Reason
		}
	}
	if !strings.Contains(reason, "--force") {
		t.Errorf("the report should say how to regenerate: %q", reason)
	}
	// --force regenerates it.
	if _, _, err := initProject(t, root, Options{Force: true}); err != nil {
		t.Fatal(err)
	}
	if gen.Inspect([]byte(readFile(t, df))) != gen.Pristine {
		t.Error("--force should regenerate the edited Dockerfile")
	}
}

func TestConfigChangeRegeneratesPristineFiles(t *testing.T) {
	root := project(t, "node-vite", "x")
	initProject(t, root, Options{})
	cfgPath := filepath.Join(root, ".kennel", "config.yaml")
	_ = os.WriteFile(cfgPath, []byte(strings.Replace(readFile(t, cfgPath), `memory: "8g"`, `memory: "2g"`, 1)), 0o644)

	_, rep, err := initProject(t, root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Written) != 1 || rep.Written[0] != ".devcontainer/compose.yaml" {
		t.Errorf("only compose.yaml depends on memory: wrote %v", rep.Written)
	}
	if !strings.Contains(readFile(t, filepath.Join(root, ".devcontainer", "compose.yaml")), "mem_limit: 2g") {
		t.Error("compose.yaml not regenerated")
	}
}

func TestInitNeverWritesThroughSymlinks(t *testing.T) {
	outside := t.TempDir()
	root := project(t, "node-vite", "x")
	if err := os.Symlink(outside, filepath.Join(root, ".devcontainer")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	p, err := Build(Options{Root: root, Force: true}) // even --force
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conflicts()) == 0 {
		t.Fatal("a symlinked .devcontainer must be a conflict")
	}
	if _, err := p.Apply(); err == nil {
		t.Fatal("Apply must refuse")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("files were written OUTSIDE the project through the symlink: %v", entries)
	}

	// A symlinked .kennel directory too.
	root2 := project(t, "node-vite", "y")
	_ = os.Symlink(outside, filepath.Join(root2, ".kennel"))
	p2, _ := Build(Options{Root: root2})
	if _, err := p2.Apply(); err == nil {
		t.Error("a symlinked .kennel must be refused")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("files were written through the .kennel symlink: %v", entries)
	}
}

func TestRootLevelDevcontainerJSONIsRespected(t *testing.T) {
	root := project(t, "node-vite", "x")
	_ = os.WriteFile(filepath.Join(root, ".devcontainer.json"), []byte(`{"image":"x"}`), 0o644)
	p, _ := Build(Options{Root: root})
	found := false
	for _, c := range p.Conflicts() {
		found = found || c.File.Path == ".devcontainer.json"
	}
	if !found {
		t.Error("a root-level .devcontainer.json would be shadowed and must be reported")
	}
	// --merge works alongside it.
	if _, _, err := initProject(t, root, Options{Merge: true}); err != nil {
		t.Errorf("--merge should coexist with a root .devcontainer.json: %v", err)
	}
}

func TestExplicitStacksAndFlags(t *testing.T) {
	root := project(t, "empty", "x")
	p, _, err := initProject(t, root, Options{Stacks: []string{"python", "go"}, Agent: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.Stacks.Auto || strings.Join(p.Config.Stacks.Items, ",") != "python,go" {
		t.Errorf("stacks = %+v", p.Config.Stacks)
	}
	if p.Config.Agent.Preset != "none" || p.Config.Agent.Command[0] != "bash" {
		t.Errorf("agent = %+v", p.Config.Agent)
	}
	df := readFile(t, filepath.Join(root, ".devcontainer", "Dockerfile"))
	if !strings.Contains(df, "tool-go") || strings.Contains(df, "agent-claude") {
		t.Errorf("explicit stacks must drive the toolchains and agent none must skip claude:\n%s", df)
	}
	if _, err := Build(Options{Root: root, Stacks: []string{"cobol"}}); err != nil {
		// existing config wins, so a bad flag is only an error on a fresh project
		t.Logf("existing config ignores flags: %v", err)
	}
	fresh := project(t, "empty", "y")
	if _, err := Build(Options{Root: fresh, Stacks: []string{"cobol"}}); err == nil {
		t.Error("an unknown stack must be rejected")
	}
	if _, err := Build(Options{Root: fresh, WorkspaceMode: "nfs"}); err == nil {
		t.Error("an unknown workspace mode must be rejected")
	}
}

func TestFlagsIgnoredWhenConfigExistsAreReported(t *testing.T) {
	root := project(t, "node-vite", "x")
	initProject(t, root, Options{})
	p, err := Build(Options{Root: root, Stacks: []string{"go"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) == 0 || !strings.Contains(p.Warnings[0], "already exists") {
		t.Errorf("silently ignoring a flag is a trap: %v", p.Warnings)
	}
}

func TestWarnings(t *testing.T) {
	root := project(t, "node-vite", "x")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, ".git", "config"), []byte("[core]\n\tfsmonitor = /tmp/evil\n[alias]\n\tx = !rm -rf ~\n"), 0o644)
	p, err := Build(Options{Root: root, WorkspaceMode: "volume"})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(p.Warnings, "\n")
	for _, want := range []string{"fsmonitor", "shell alias", "volume"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning about %q:\n%s", want, all)
		}
	}
	// A gitfile (worktree) is flagged.
	root2 := project(t, "node-vite", "w")
	_ = os.WriteFile(filepath.Join(root2, ".git"), []byte("gitdir: /elsewhere\n"), 0o644)
	p2, _ := Build(Options{Root: root2})
	if !strings.Contains(strings.Join(p2.Warnings, "\n"), "worktree") {
		t.Errorf("worktree warning missing: %v", p2.Warnings)
	}
	// An unpinned agent version is flagged.
	root3 := project(t, "node-vite", "v")
	initProject(t, root3, Options{})
	cfgPath := filepath.Join(root3, ".kennel", "config.yaml")
	_ = os.WriteFile(cfgPath, []byte(strings.Replace(readFile(t, cfgPath), `"2.1.286"`, `"2.1.200"`, 1)), 0o644)
	p3, _ := Build(Options{Root: root3})
	if !strings.Contains(strings.Join(p3.Warnings, "\n"), "no kennel integrity pin") {
		t.Errorf("unpinned warning missing: %v", p3.Warnings)
	}
	df := ""
	for _, a := range p3.Actions {
		if a.File.Path == ".devcontainer/Dockerfile" {
			df = string(a.File.Content)
		}
	}
	if !strings.Contains(df, "WARNING") || strings.Contains(df, "npm ci") || strings.Contains(df, "sha512") {
		t.Errorf("an unpinned version must not claim a verified install:\n%s", df)
	}
}

func TestProjectName(t *testing.T) {
	for in, want := range map[string]string{
		"/x/My App": "my-app", "/x/Foo_Bar.baz": "foo_bar-baz", "/x/---": "project", "/x/ÄÖ": "project",
		"/x/" + strings.Repeat("a", 60): strings.Repeat("a", 39), "/x/9lives": "9lives",
	} {
		if got := ProjectName(in); got != want {
			t.Errorf("ProjectName(%q) = %q, want %q", in, got, want)
		}
		if err := (&config.Config{Version: 1, Project: ProjectName(in)}).Validate(); err != nil && strings.Contains(err.Error(), "project:") {
			t.Errorf("derived name %q is invalid: %v", ProjectName(in), err)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWorkspaceModeDefaultsPerOS(t *testing.T) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	cases := []struct {
		goos string
		has  func(string) bool
		want string
		note string
	}{
		{"linux", yes, "bind", ""},
		{"darwin", yes, "volume", "default on darwin"},
		{"windows", yes, "volume", "default on windows"},
		{"darwin", no, "bind", "needs a git repository with a commit"},
		{"windows", no, "bind", "needs a git repository with a commit"},
	}
	for _, c := range cases {
		root := t.TempDir()
		plan, err := Build(Options{Root: root, GlobalConfigDir: t.TempDir(), GOOS: c.goos, HasCommit: c.has})
		if err != nil {
			t.Fatal(err)
		}
		if plan.Config.Workspace.Mode != c.want {
			t.Errorf("%s: mode = %s, want %s", c.goos, plan.Config.Workspace.Mode, c.want)
		}
		joined := strings.Join(plan.Notes, "\n")
		if c.note != "" && !strings.Contains(joined, c.note) {
			t.Errorf("%s: notes lack %q:\n%s", c.goos, c.note, joined)
		}
		if c.note == "" && strings.Contains(joined, "workspace.mode") {
			t.Errorf("%s: unexpected note:\n%s", c.goos, joined)
		}
	}
	// An explicit choice is never overridden, even on macOS.
	root := t.TempDir()
	plan, err := Build(Options{Root: root, GlobalConfigDir: t.TempDir(), GOOS: "darwin", HasCommit: yes, WorkspaceMode: "bind"})
	if err != nil || plan.Config.Workspace.Mode != "bind" {
		t.Errorf("--workspace bind must win: %v %v", plan.Config.Workspace.Mode, err)
	}
}
