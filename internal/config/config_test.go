package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-systems/cellwall/internal/pins"
)

func mustParse(t *testing.T, src string, layer Layer) *Config {
	t.Helper()
	c, err := Parse("c.yaml", []byte(src), layer, Default())
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, src)
	}
	return c
}

func problems(t *testing.T, src string) string {
	t.Helper()
	c := mustParse(t, src, LayerProject)
	err := c.Validate()
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestDefaultsAreValidAndStrict(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if c.Agent.Version != pins.ClaudeCodeVersion || c.Workspace.Mode != "bind" || c.Agent.Telemetry || c.Agent.MCPConnectors {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if rel := c.Relaxations(); len(rel) != 0 {
		t.Errorf("defaults must contain no relaxations: %v", rel)
	}
	if !c.Stacks.Auto || !c.Workspace.CacheVolumes.Auto {
		t.Error("stacks and cache volumes default to auto")
	}
}

func TestParseOverlaysOnBase(t *testing.T) {
	c := mustParse(t, "version: 1\nproject: demo\nhardening: {memory: 4g}\nports: [5173]\n", LayerProject)
	if c.Project != "demo" || c.Hardening.Memory != "4g" || c.Hardening.PidsLimit != DefaultPidsLimit || c.Agent.Preset != "claude" {
		t.Errorf("absent keys must keep their default: %+v", c)
	}
	base := Default()
	_, _ = Parse("c.yaml", []byte("version: 1\nagent: {env: {A: b}}\nports: [5173]\n"), LayerProject, base)
	if base.Agent.Env != nil || base.Ports != nil {
		t.Error("Parse must not modify its base")
	}
}

func TestLayering(t *testing.T) {
	dir := t.TempDir()
	global := filepath.Join(dir, "global")
	project := filepath.Join(dir, "proj")
	_ = os.MkdirAll(global, 0o755)
	_ = os.MkdirAll(filepath.Join(project, ".cellwall"), 0o755)
	_ = os.WriteFile(filepath.Join(global, "config.yaml"), []byte("version: 1\nhardening: {memory: 2g, cpus: 2}\ngit: {user_name: Global}\nagent: {env: {FROM_GLOBAL: '1'}}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(project, ".cellwall", "config.yaml"), []byte("version: 1\nproject: p1\nhardening: {memory: 6g}\nagent: {env: {FROM_PROJECT: '2'}}\n"), 0o644)

	l, err := Load(LoadOptions{ProjectDir: project, GlobalDir: global})
	if err != nil {
		t.Fatal(err)
	}
	c := l.Config
	if c.Hardening.Memory != "6g" || c.Hardening.CPUs != 2 || c.Git.UserName != "Global" {
		t.Errorf("project must override global, global must override defaults: %+v", c.Hardening)
	}
	if c.Agent.Env["FROM_GLOBAL"] != "1" || c.Agent.Env["FROM_PROJECT"] != "2" {
		t.Errorf("env maps merge across layers: %v", c.Agent.Env)
	}
	if l.GlobalFile == "" || l.ProjectFile == "" {
		t.Errorf("sources not reported: %+v", l)
	}

	// No global dir / missing global file is fine; a missing project file is a clear error.
	if _, err := Load(LoadOptions{ProjectDir: project}); err != nil {
		t.Error(err)
	}
	if _, err := Load(LoadOptions{ProjectDir: t.TempDir()}); !errors.Is(err, ErrNoProjectConfig) {
		t.Errorf("want ErrNoProjectConfig, got %v", err)
	}
}

func TestUserGlobalCannotRelaxOrInjectSecrets(t *testing.T) {
	for _, src := range []string{
		"version: 1\ndevcontainer: {dir: .devcontainer/cellwall}\n",
		"version: 1\nunsafe: {publish_all_interfaces: true}\n",
		"version: 1\nunsafe: {unprotect: [.mcp.json]}\n",
		"version: 1\nsecrets:\n  - {name: tok, source_file: ~/tok}\n",
		"version: 1\nproject: x\n",
		"version: 1\nports: [3000]\n",
		"version: 1\nstacks: [node]\n",
	} {
		_, err := Parse("g.yaml", []byte(src), LayerUserGlobal, Default())
		var se *SyntaxError
		if !errors.As(err, &se) || !strings.Contains(se.Msg, "user-global") || se.Line != 2 {
			t.Errorf("want a positioned user-global refusal for:\n%s\ngot %v", src, err)
		}
	}
	// Tuning is fine there.
	if _, err := Parse("g.yaml", []byte("version: 1\nhardening: {memory: 4g}\ngit: {user_email: a@b.c}\n"), LayerUserGlobal, Default()); err != nil {
		t.Error(err)
	}
}

func TestParseRejectsStructure(t *testing.T) {
	for _, src := range []string{
		"version: 1\nagnet: {}\n",                  // typo
		"version: 1\nagent: {comand: [x]}\n",       // nested typo
		"version: 1\nversion: 1\n",                 // duplicate
		"version: 1\nagent: &a {preset: claude}\n", // anchor
		"version: 1\nports: 5173\n",                // wrong shape
		"version: 1\nsecrets: [a]\n",               // wrong shape
		"version: 1\nworkspace: {cache_volumes: lots}\n",
	} {
		if _, err := Parse("c.yaml", []byte(src), LayerProject, Default()); err == nil {
			t.Errorf("must be rejected:\n%s", src)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{"bad project", "project: Bad_Name!\n", "project:"},
		{"project too long", "project: " + strings.Repeat("a", 40) + "\n", "project:"},
		{"unknown stack", "stacks: [cobol]\n", "unknown stack"},
		{"bad preset", "agent: {preset: gpt}\n", "agent.preset"},
		{"empty command", "agent: {command: []}\n", "agent.command"},
		{"command control char", "agent: {command: [\"a\\nb\"]}\n", "agent.command"},
		{"floating version", "agent: {version: latest}\n", "exact version"},
		{"short version", "agent: {version: '2.1'}\n", "exact version"},
		{"bad apt", "agent: {apt_packages: ['Bad Pkg']}\n", "Debian package"},
		{"dup apt", "agent: {apt_packages: [curl, curl]}\n", "twice"},
		{"unpinned base", "agent: {base_image: 'debian:bookworm'}\n", "pinned by digest"},
		{"bad image ref", "agent: {base_image: 'Not An Image'}\n", "valid image reference"},
		{"proxy env", "agent: {env: {HTTPS_PROXY: 'http://evil'}}\n", "reserved"},
		{"lowercase proxy env", "agent: {env: {http_proxy: 'x'}}\n", "reserved"},
		{"no_proxy env", "agent: {env: {NO_PROXY: '*'}}\n", "reserved"},
		{"ld_preload", "agent: {env: {LD_PRELOAD: /x.so}}\n", "reserved"},
		{"ld prefix", "agent: {env: {LD_SOMETHING: x}}\n", "reserved"},
		{"cellwall prefix", "agent: {env: {CELLWALL_X: x}}\n", "reserved"},
		{"docker prefix", "agent: {env: {DOCKER_HOST: tcp://x}}\n", "reserved"},
		{"telemetry env", "agent: {env: {DISABLE_TELEMETRY: '0'}}\n", "reserved"},
		{"git identity env", "agent: {env: {GIT_AUTHOR_NAME: x}}\n", "reserved"},
		{"bad devcontainer dir", "devcontainer: {dir: '/etc'}\n", "devcontainer.dir"},
		{"node_options", "agent: {env: {NODE_OPTIONS: --require /x}}\n", "reserved"},
		{"bad env name", "agent: {env: {'1BAD': x}}\n", "not a valid variable name"},
		{"env newline", "agent: {env: {OK: \"a\\nb\"}}\n", "control characters"},
		{"bad mode", "workspace: {mode: nfs}\n", "workspace.mode"},
		{"cache escapes", "workspace: {cache_volumes: ['../x']}\n", "inside the workspace"},
		{"cache absolute", "workspace: {cache_volumes: ['/x']}\n", "relative"},
		{"cache dup", "workspace: {cache_volumes: [a, a]}\n", "twice"},
		{"cache over protected", "workspace: {cache_volumes: ['.git/hooks']}\n", "protected"},
		{"low port", "ports: [80]\n", "1024-65535"},
		{"high port", "ports: [70000]\n", "1024-65535"},
		{"gateway port", "ports: [3128]\n", "used by the gateway"},
		{"admin port", "ports: [3129]\n", "used by the gateway"},
		{"dup port", "ports: [3000, 3000]\n", "twice"},
		{"pids too low", "hardening: {pids_limit: 2}\n", "pids_limit"},
		{"pids negative (unlimited)", "hardening: {pids_limit: -1}\n", "unlimited is not available"},
		{"memory format", "hardening: {memory: lots}\n", "hardening.memory"},
		{"memory tiny", "hardening: {memory: 1m}\n", "below the minimum"},
		{"cpus zero", "hardening: {cpus: 0}\n", "hardening.cpus"},
		{"runtime junk", "hardening: {runtime: 'a b'}\n", "hardening.runtime"},
		{"gateway audit files", "gateway: {audit_max_files: 0}\n", "audit_max_files"},
		{"protected traversal", "protected_paths: ['../etc']\n", "inside the workspace"},
		{"protected absolute", "protected_paths: ['/etc']\n", "relative"},
		{"protected glob", "protected_paths: ['src/*']\n", "glob"},
		{"unprotect custom", "unsafe: {unprotect: ['src/x']}\n", "not a built-in protected path"},
		{"secret repo path", "secrets:\n  - {name: tok, source_file: .env}\n", "version control"},
		{"secret relative", "secrets:\n  - {name: tok, source_file: ./tok}\n", "version control"},
		{"secret bad name", "secrets:\n  - {name: Tok, source_file: ~/t}\n", "secrets[0].name"},
		{"secret dup", "secrets:\n  - {name: tok, source_file: ~/a}\n  - {name: tok, source_file: ~/b}\n", "declared twice"},
		{"secret reserved env", "secrets:\n  - {name: tok, source_file: ~/a, env: HTTPS_PROXY}\n", "reserved"},
		{"secret env clash", "agent: {env: {GH_TOKEN: x}}\nsecrets:\n  - {name: tok, source_file: ~/a, env: GH_TOKEN}\n", "also set in agent.env"},
		{"secret env dup", "secrets:\n  - {name: a, source_file: ~/a, env: T}\n  - {name: b, source_file: ~/b, env: T}\n", "two secrets"},
		{"git newline", "git: {user_name: \"a\\nb\"}\n", "git.user_name"},
		{"cap net_admin", "unsafe: {cap_add: [NET_ADMIN]}\n", "not permitted"},
		{"cap net_raw", "unsafe: {cap_add: [NET_RAW]}\n", "not permitted"},
		{"cap sys_admin", "unsafe: {cap_add: [SYS_ADMIN]}\n", "not permitted"},
		{"cap all", "unsafe: {cap_add: [ALL]}\n", "not permitted"},
	}
	for _, tt := range tests {
		got := problems(t, "version: 1\n"+tt.src)
		if got == "" || !strings.Contains(got, tt.want) {
			t.Errorf("%s: got %q, want it to contain %q", tt.name, got, tt.want)
		}
	}
}

func TestValidateCollectsEveryProblem(t *testing.T) {
	got := problems(t, "version: 1\nports: [80]\nhardening: {memory: lots, cpus: 0}\n")
	for _, want := range []string{"ports", "hardening.memory", "hardening.cpus", "3 problems"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestValidateAccepts(t *testing.T) {
	good := `
version: 1
project: my-app_2
stacks: [node, python]
agent:
  preset: claude
  command: [claude, --model, opus]
  version: 2.1.286
  env: {NODE_ENV: development, FEATURE_X: "on"}
  apt_packages: [ripgrep, jq, libpq-dev]
  base_image: "debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251"
workspace: {mode: volume, cache_volumes: [node_modules, .venv]}
ports: [3000, 5173]
hardening: {readonly_rootfs: true, runtime: runsc, pids_limit: 512, memory: 4g, cpus: 2.5}
gateway: {memory: 128m, pids_limit: 128, audit_max_size_mb: 10, audit_max_files: 3}
protected_paths: [Makefile, scripts/release.sh]
secrets:
  - {name: github_token, source_file: ~/.config/cellwall/github_token, env: GH_TOKEN}
  - {name: npm_rc, source_file: /home/me/.npmrc}
git: {user_name: "Agent Smith", user_email: agent@example.com}
unsafe: {cap_add: [SYS_PTRACE], unprotect: [.vscode/tasks.json]}
`
	if got := problems(t, good); got != "" {
		t.Fatalf("a rich valid config was rejected:\n%s", got)
	}
}

func TestUnpinnedBaseImageNeedsExplicitRelaxation(t *testing.T) {
	src := "version: 1\nagent: {base_image: 'ubuntu:24.04'}\nunsafe: {unpinned_base_image: true}\n"
	if got := problems(t, src); got != "" {
		t.Fatal(got)
	}
	c := mustParse(t, src, LayerProject)
	if r := strings.Join(c.Relaxations(), "\n"); !strings.Contains(r, "unpinned_base_image") {
		t.Errorf("relaxation not listed: %s", r)
	}
}

func TestProtectedSet(t *testing.T) {
	c := Default()
	got := c.ProtectedSet()
	for _, want := range []string{".devcontainer", ".cellwall", ".git/hooks", ".mcp.json", ".claude", ".vscode/tasks.json", ".husky"} {
		if !contains(got, want) {
			t.Errorf("default protected set missing %s: %v", want, got)
		}
	}
	if contains(got, ".git/config") || contains(got, ".git") {
		t.Errorf(".git/config is warned about, not mounted; .git itself must stay writable: %v", got)
	}

	// Additive: listing extras never removes defaults; trailing slashes and ./ are normalised.
	c.ProtectedPaths = []string{"./Makefile", "scripts/", ".mcp.json"}
	got = c.ProtectedSet()
	if !contains(got, "Makefile") || !contains(got, "scripts") || !contains(got, ".claude") {
		t.Errorf("%v", got)
	}
	count := 0
	for _, g := range got {
		if g == ".mcp.json" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("duplicates must collapse: %v", got)
	}

	// The only way to drop a default is unsafe.unprotect, and it is reported.
	c.Unsafe.Unprotect = []string{".vscode/tasks.json"}
	if got = c.ProtectedSet(); contains(got, ".vscode/tasks.json") || !contains(got, ".vscode/settings.json") {
		t.Errorf("%v", got)
	}
	if rel := strings.Join(c.Relaxations(), "\n"); !strings.Contains(rel, ".vscode/tasks.json") {
		t.Errorf("unprotect must be listed as a relaxation: %s", rel)
	}
	// A config copied from the spec's example (which lists the defaults) is still fully protected.
	c2 := mustParse(t, "version: 1\nprotected_paths: [.devcontainer, .cellwall]\n", LayerProject)
	if len(c2.ProtectedSet()) < len(DefaultProtected) {
		t.Errorf("trimming the list must not weaken the defaults: %v", c2.ProtectedSet())
	}
}

func TestRelaxationsListEverything(t *testing.T) {
	c := mustParse(t, `
version: 1
agent: {telemetry: true, mcp_connectors: true}
unsafe: {publish_all_interfaces: true, audit_fail_open: true, allow_old_engine: true, cap_add: [SYS_PTRACE], unprotect: [.mcp.json]}
`, LayerProject)
	joined := strings.Join(c.Relaxations(), "\n")
	for _, want := range []string{"publish_all_interfaces", "audit_fail_open", "allow_old_engine", "SYS_PTRACE", ".mcp.json", "agent.telemetry", "agent.mcp_connectors"} {
		if !strings.Contains(joined, want) {
			t.Errorf("relaxation %q not reported:\n%s", want, joined)
		}
	}
}

func TestAutoList(t *testing.T) {
	for src, want := range map[string]AutoList{
		"workspace: {cache_volumes: auto}":   {Auto: true},
		"workspace: {cache_volumes: none}":   {},
		"workspace: {cache_volumes: [a, b]}": {Items: []string{"a", "b"}},
	} {
		c := mustParse(t, "version: 1\n"+src+"\n", LayerProject)
		got := c.Workspace.CacheVolumes
		if got.Auto != want.Auto || strings.Join(got.Items, ",") != strings.Join(want.Items, ",") {
			t.Errorf("%s -> %+v", src, got)
		}
	}
	if _, err := Parse("c", []byte("version: 1\nstacks: sometimes\n"), LayerProject, Default()); err == nil {
		t.Error("an unknown scalar must be rejected")
	}
	b, _ := json.Marshal(AutoList{Auto: true})
	b2, _ := json.Marshal(AutoList{})
	b3, _ := json.Marshal(AutoList{Items: []string{"x"}})
	if string(b) != `"auto"` || string(b2) != `"none"` || string(b3) != `["x"]` {
		t.Errorf("%s %s %s", b, b2, b3)
	}
}

func TestHashIsStableAndSensitive(t *testing.T) {
	a, b := Default(), Default()
	if a.Hash() != b.Hash() || len(a.Hash()) != 64 {
		t.Error("hash must be deterministic")
	}
	b.Ports = []int{3000}
	if a.Hash() == b.Hash() {
		t.Error("hash must change with config")
	}
}

func TestParseMemory(t *testing.T) {
	for in, want := range map[string]int64{"512m": 512 << 20, "8g": 8 << 30, "1G": 1 << 30, "64k": 64 << 10, "1048576": 1048576, "2M": 2 << 20} {
		if got, err := ParseMemory(in); err != nil || got != want {
			t.Errorf("%s = %d, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "-1g", "1.5g", "8gb", "g", "99999999999999999999g", " 8g", "8 g"} {
		if _, err := ParseMemory(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestNormalizeRelPath(t *testing.T) {
	good := map[string]string{"a": "a", "./a": "a", "a/": "a", "a/b/../c": "a/c", ".git/hooks": ".git/hooks", "a/./b": "a/b"}
	for in, want := range good {
		if got, err := NormalizeRelPath(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "..", "../a", "a/../../b", "/a", "~/a", "a//b", "a\x00b", "a\nb", "a*", "a?", "a[0]", "a{b}", "$HOME", "a`b`", "a\\b", "C:\\x", "a:b", "./~", "./~/x", "a/../~", "~x"} {
		if got, err := NormalizeRelPath(in); err == nil {
			t.Errorf("%q must be rejected, got %q", in, got)
		}
	}
}
