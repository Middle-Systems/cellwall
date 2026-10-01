package detect

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "test", "fixtures", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("missing fixture %s: %v", name, err)
	}
	return p
}

func TestDetectFixtures(t *testing.T) {
	tests := []struct {
		fixture string
		want    []string // "name@dir:tool"
		fw      map[string][]string
	}{
		{"node-vite", []string{"node@.:npm"}, map[string][]string{"node": {"vite"}}},
		{"python-flask", []string{"python@.:pip"}, map[string][]string{"python": {"flask"}}},
		{"go-http", []string{"go@.:go"}, nil},
		{"rust-axum", []string{"rust@.:cargo"}, map[string][]string{"rust": {"axum"}}},
		{"java-maven", []string{"java@.:maven"}, map[string][]string{"java": {"spring-boot"}}},
		{"dotnet-api", []string{"dotnet@.:dotnet"}, nil},
		{"ruby-rails", []string{"ruby@.:bundler"}, map[string][]string{"ruby": {"rails"}}},
		{"php-laravel", []string{"php@.:composer"}, map[string][]string{"php": {"laravel"}}},
		{"polyglot", []string{"node@web:pnpm", "python@api:uv", "go@tools/cli:go"}, map[string][]string{"node": {"vite"}, "python": {"fastapi", "uvicorn"}}},
		{"existing-devcontainer", []string{"node@.:npm"}, nil},
		{"empty", nil, nil},
	}
	for _, tt := range tests {
		r, err := Detect(fixture(t, tt.fixture))
		if err != nil {
			t.Fatalf("%s: %v", tt.fixture, err)
		}
		var got []string
		for _, s := range r.Stacks {
			got = append(got, s.Name+"@"+s.Dir+":"+s.Tool)
			if want, ok := tt.fw[s.Name]; ok && !reflect.DeepEqual(s.Frameworks, want) {
				t.Errorf("%s/%s frameworks = %v, want %v", tt.fixture, s.Name, s.Frameworks, want)
			}
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: stacks = %v, want %v", tt.fixture, got, tt.want)
		}
	}
}

func TestGoVersionIsReported(t *testing.T) {
	r, _ := Detect(fixture(t, "go-http"))
	if r.Stacks[0].Version != "1.24" {
		t.Errorf("version = %q", r.Stacks[0].Version)
	}
	for in, want := range map[string]string{
		"module x\n\ngo 1.22.3\n":                 "1.22.3",
		"module x\ngo 1.21\ntoolchain go1.22.1\n": "1.21",
		"module x\n// go 1.99\n":                  "",
		"module x\n":                              "",
	} {
		if got := goVersion(in); got != want {
			t.Errorf("goVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNamesAreInCanonicalOrder(t *testing.T) {
	r, _ := Detect(fixture(t, "polyglot"))
	if got := strings.Join(r.Names(), ","); got != "node,python,go" {
		t.Errorf("Names() = %s", got)
	}
}

func TestDetectBounds(t *testing.T) {
	root := t.TempDir()
	mk := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("package.json", "{}")
	mk("a/b/package.json", "{}")            // depth 2: found
	mk("a/b/c/package.json", "{}")          // depth 3: beyond MaxDepth
	mk("node_modules/x/package.json", "{}") // dependency tree: skipped
	mk("vendor/y/go.mod", "module y\n")     // skipped
	mk(".hidden/package.json", "{}")        // hidden dirs: skipped
	mk("target/Cargo.toml", "")             // build output: skipped
	r, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, s := range r.Stacks {
		dirs = append(dirs, s.Dir)
	}
	if !reflect.DeepEqual(dirs, []string{".", "a/b"}) {
		t.Errorf("dirs = %v", dirs)
	}
}

func TestDetectNeverFollowsSymlinks(t *testing.T) {
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "package.json"), []byte(`{"devDependencies":{"vite":"1"}}`), 0o644)
	_ = os.WriteFile(filepath.Join(outside, "go.mod"), []byte("module secret\ngo 1.99\n"), 0o644)

	root := t.TempDir()
	// A symlinked directory pointing outside the repo, and symlinked marker files.
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Skip("symlinks unavailable: ", err)
	}
	_ = os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(root, "package.json"))
	_ = os.Symlink(filepath.Join(outside, "go.mod"), filepath.Join(root, "go.mod"))
	r, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Stacks) != 0 {
		t.Errorf("symlinks must not be followed or trusted as markers: %+v", r.Stacks)
	}
	// And readSmall refuses symlinks directly.
	if got := readSmall(filepath.Join(root, "package.json")); got != "" {
		t.Errorf("readSmall followed a symlink: %q", got)
	}
}

func TestDetectBoundsFileRead(t *testing.T) {
	root := t.TempDir()
	big := `{"devDependencies":{"vite":"1"}}` + strings.Repeat(" ", 2<<20)
	_ = os.WriteFile(filepath.Join(root, "package.json"), []byte(big), 0o644)
	if got := len(readSmall(filepath.Join(root, "package.json"))); got > maxFileRead {
		t.Errorf("read %d bytes, limit %d", got, maxFileRead)
	}
}

func TestDetectMalformedMarkers(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "package.json"), []byte("{not json"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "go.mod"), []byte("\x00\x01garbage"), 0o644)
	r, err := Detect(root)
	if err != nil || len(r.Stacks) != 2 {
		t.Fatalf("a malformed marker still identifies the stack: %v %+v", err, r)
	}
}

func TestDetectErrors(t *testing.T) {
	if _, err := Detect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing root must fail")
	}
	f := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(f, nil, 0o644)
	if _, err := Detect(f); err == nil {
		t.Error("a file is not a project directory")
	}
}

func TestNodeToolDetection(t *testing.T) {
	for _, tc := range []struct {
		files map[string]bool
		pkg   string
		want  string
	}{
		{map[string]bool{"pnpm-lock.yaml": true}, `{}`, "pnpm"},
		{map[string]bool{"yarn.lock": true}, `{}`, "yarn"},
		{map[string]bool{"bun.lockb": true}, `{}`, "bun"},
		{map[string]bool{"package-lock.json": true}, `{"packageManager":"pnpm@9"}`, "npm"},
		{map[string]bool{}, `{"packageManager":"yarn@4.0.0"}`, "yarn"},
		{map[string]bool{}, `{}`, "npm"},
		{map[string]bool{}, `not json`, "npm"},
	} {
		if tool, _, _ := nodeInfo(tc.pkg, tc.files); tool != tc.want {
			t.Errorf("%v %s -> %s, want %s", tc.files, tc.pkg, tool, tc.want)
		}
	}
}

func TestPythonFrameworkWordBoundaries(t *testing.T) {
	read := func(f string) string {
		if f == "requirements.txt" {
			return "flask-cors==4.0\nmyflaskapp==1\ndjango>=4\n"
		}
		return ""
	}
	got := pythonFrameworks(read, map[string]bool{"requirements.txt": true})
	if !reflect.DeepEqual(got, []string{"django"}) {
		t.Errorf("%v: flask-cors and myflaskapp are not flask", got)
	}
}

func plan(t *testing.T, fixture string, ignored map[string]bool, existing map[string]bool) Plan {
	t.Helper()
	r, err := Detect(fixture2(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	return PlanFor(r, func(d string) bool { return ignored[d] }, func(d string) bool { return existing[d] })
}

func fixture2(t *testing.T, name string) string { return fixture(t, name) }

func TestPlan(t *testing.T) {
	p := plan(t, "node-vite", map[string]bool{"node_modules": true}, nil)
	if !reflect.DeepEqual(p.Presets, []string{"node"}) || !reflect.DeepEqual(p.Caches, []string{"node_modules"}) || !reflect.DeepEqual(p.Ports, []int{5173}) {
		t.Errorf("%+v", p)
	}
	if len(p.BindHints) != 1 || !strings.Contains(p.BindHints[0], "--host") {
		t.Errorf("hints: %v", p.BindHints)
	}

	p = plan(t, "polyglot", map[string]bool{"web/node_modules": true, "api/.venv": true}, nil)
	if !reflect.DeepEqual(p.Presets, []string{"node", "python", "go"}) {
		t.Errorf("presets %v", p.Presets)
	}
	for _, want := range []string{"web/node_modules", "api/.venv", "api/.mypy_cache"} {
		found := false
		for _, c := range p.Caches {
			found = found || c == want
		}
		if !found {
			t.Errorf("cache %s missing from %v", want, p.Caches)
		}
	}
	if !reflect.DeepEqual(p.Ports, []int{5173, 8000}) {
		t.Errorf("ports %v", p.Ports)
	}
}

func TestPlanNeverCoversTrackedDirectories(t *testing.T) {
	// node_modules exists and is NOT gitignored: a volume over it would hide committed files.
	p := plan(t, "node-vite", nil, map[string]bool{"node_modules": true})
	if len(p.Caches) != 0 {
		t.Errorf("tracked directory was planned as a cache volume: %v", p.Caches)
	}
	if len(p.Notes) == 0 || !strings.Contains(p.Notes[0], "node_modules") {
		t.Errorf("the user must be told why: %v", p.Notes)
	}
	// Absent directories are fine (nothing to hide).
	if p := plan(t, "node-vite", nil, nil); !reflect.DeepEqual(p.Caches, []string{"node_modules"}) {
		t.Errorf("%v", p.Caches)
	}
}

func TestPlanMavenVersusGradle(t *testing.T) {
	r := &Result{Stacks: []Stack{{Name: "java", Dir: ".", Tool: "maven"}}}
	p := PlanFor(r, func(string) bool { return true }, func(string) bool { return true })
	if !reflect.DeepEqual(p.Caches, []string{"target"}) {
		t.Errorf("maven: %v", p.Caches)
	}
	r = &Result{Stacks: []Stack{{Name: "java", Dir: "svc", Tool: "gradle"}}}
	p = PlanFor(r, func(string) bool { return true }, func(string) bool { return true })
	if !reflect.DeepEqual(p.Caches, []string{"svc/.gradle", "svc/build"}) {
		t.Errorf("gradle: %v", p.Caches)
	}
}

func TestGitIgnore(t *testing.T) {
	g := ParseGitIgnore(`
# comment
node_modules
/dist
target/
**/.venv
*.log
!keep
build/*
`)
	for dir, want := range map[string]bool{
		"node_modules": true, "web/node_modules": true, "node_modules/x": true,
		"dist": true, "web/dist": false, // anchored: only the root dist
		"target": true, "svc/target": true,
		".venv": true, "api/.venv": true,
		"src": false, "build": false, // build/* is a glob: treated as not ignored (conservative)
		"keep": false,
	} {
		if got := g.Ignored(dir); got != want {
			t.Errorf("Ignored(%q) = %v, want %v", dir, got, want)
		}
	}
	var nilIgnore *GitIgnore
	if nilIgnore.Ignored("x") {
		t.Error("nil GitIgnore ignores nothing")
	}
}

func TestEveryStackHasInfoAndPreset(t *testing.T) {
	for _, n := range order {
		info, ok := InfoFor(n)
		if !ok || info.Preset == "" {
			t.Errorf("stack %s has no info/preset", n)
		}
	}
	for name, fw := range frameworks {
		if fw.Port < 1024 || fw.Port > 65535 || fw.BindHint == "" || fw.Name != name {
			t.Errorf("bad framework entry %s: %+v", name, fw)
		}
	}
}
