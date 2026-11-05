// Package detect finds which language stacks a repository uses, from marker files, so `init` can
// choose toolchains, allowlist presets, cache volumes and preview ports.
//
// The repository is untrusted input: detection never follows symlinks, reads only small regular
// files, and is bounded in depth and in the number of directories visited.
package detect

import (
	"bufio"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Bounds on the scan.
const (
	MaxDepth    = 2    // root is depth 0
	MaxDirs     = 2000 // directories visited before the scan is cut short
	maxFileRead = 256 << 10
)

// Stack is one detected stack at one location.
type Stack struct {
	Name       string   `json:"name"`
	Dir        string   `json:"dir"` // workspace-relative, "." for the root
	Markers    []string `json:"markers"`
	Tool       string   `json:"tool,omitempty"`    // package manager or build tool
	Version    string   `json:"version,omitempty"` // toolchain version the repo asks for, if stated
	Frameworks []string `json:"frameworks,omitempty"`
}

// Result is what Detect found.
type Result struct {
	Stacks []Stack  `json:"stacks"`
	Notes  []string `json:"notes,omitempty"`
}

// Names returns the distinct stack names, in canonical order.
func (r *Result) Names() []string {
	seen := map[string]bool{}
	for _, s := range r.Stacks {
		seen[s.Name] = true
	}
	var out []string
	for _, n := range order {
		if seen[n] {
			out = append(out, n)
		}
	}
	return out
}

// order is the canonical stack order, used wherever output must be deterministic.
var order = []string{"node", "python", "go", "rust", "java", "dotnet", "ruby", "php"}

// skipDirs are never descended into: dependency trees, build output and tool state.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "target": true, "dist": true, "build": true, "out": true,
	"venv": true, "env": true, "__pycache__": true, "bin": true, "obj": true, "coverage": true,
	"site-packages": true, "bower_components": true, "testdata": true, "fixtures": true,
}

// markers maps a stack to the file names (or *.ext globs) that identify it.
var markers = map[string][]string{
	"node":   {"package.json"},
	"python": {"pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "setup.cfg"},
	"go":     {"go.mod", "go.work"},
	"rust":   {"Cargo.toml"},
	"java":   {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"},
	"dotnet": {"*.csproj", "*.fsproj", "*.sln"},
	"ruby":   {"Gemfile"},
	"php":    {"composer.json"},
}

// Detect scans root. It does not fail on unreadable subdirectories (they are noted and skipped).
func Detect(root string) (*Result, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, &fs.PathError{Op: "detect", Path: root, Err: fs.ErrInvalid}
	}
	res := &Result{}
	visited := 0
	var walk func(rel string, depth int)
	walk = func(rel string, depth int) {
		if visited >= MaxDirs {
			return
		}
		visited++
		abs := filepath.Join(root, filepath.FromSlash(rel))
		entries, err := os.ReadDir(abs)
		if err != nil {
			res.Notes = append(res.Notes, "could not read "+displayDir(rel)+": "+err.Error())
			return
		}
		files := map[string]bool{}
		var dirs []string
		for _, e := range entries {
			switch {
			case e.Type()&fs.ModeSymlink != 0:
				// Never follow or read symlinks: they can point outside the repository.
			case e.IsDir():
				dirs = append(dirs, e.Name())
			case e.Type().IsRegular():
				files[e.Name()] = true
			}
		}
		for _, name := range order {
			if found := matchMarkers(files, markers[name]); len(found) > 0 {
				res.Stacks = append(res.Stacks, describe(root, rel, name, found, files))
			}
		}
		if depth >= MaxDepth {
			return
		}
		sort.Strings(dirs)
		for _, d := range dirs {
			if skipDirs[d] || strings.HasPrefix(d, ".") {
				continue
			}
			walk(path.Join(rel, d), depth+1)
		}
	}
	walk(".", 0)
	if visited >= MaxDirs {
		res.Notes = append(res.Notes, "directory scan stopped after "+strconv.Itoa(MaxDirs)+" directories; pass --stack to choose stacks explicitly")
	}
	sort.SliceStable(res.Stacks, func(i, j int) bool {
		a, b := res.Stacks[i], res.Stacks[j]
		if ai, bi := orderIndex(a.Name), orderIndex(b.Name); ai != bi {
			return ai < bi
		}
		return a.Dir < b.Dir
	})
	return res, nil
}

func orderIndex(n string) int {
	for i, o := range order {
		if o == n {
			return i
		}
	}
	return len(order)
}

func displayDir(rel string) string {
	if rel == "." {
		return "the project root"
	}
	return rel
}

func matchMarkers(files map[string]bool, patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			ext := p[1:]
			var matches []string
			for f := range files {
				if strings.HasSuffix(f, ext) {
					matches = append(matches, f)
				}
			}
			sort.Strings(matches)
			out = append(out, matches...)
			continue
		}
		if files[p] {
			out = append(out, p)
		}
	}
	return out
}

func describe(root, rel, name string, found []string, files map[string]bool) Stack {
	s := Stack{Name: name, Dir: rel, Markers: found}
	read := func(file string) string { return readSmall(filepath.Join(root, filepath.FromSlash(rel), file)) }
	switch name {
	case "node":
		s.Tool, s.Frameworks, s.Version = nodeInfo(read("package.json"), files)
	case "python":
		s.Tool = pythonTool(files)
		s.Frameworks = pythonFrameworks(read, files)
	case "go":
		s.Tool = "go"
		s.Version = goVersion(read("go.mod"))
	case "rust":
		s.Tool = "cargo"
		s.Frameworks = containsAny(read("Cargo.toml"), map[string]string{"axum": "axum", "actix-web": "actix-web", "rocket": "rocket", "warp": "warp"})
	case "java":
		s.Tool = "maven"
		if files["build.gradle"] || files["build.gradle.kts"] || files["settings.gradle"] || files["settings.gradle.kts"] {
			s.Tool = "gradle"
		}
		text := read("pom.xml") + read("build.gradle") + read("build.gradle.kts")
		s.Frameworks = containsAny(text, map[string]string{"spring-boot": "spring-boot", "quarkus": "quarkus"})
	case "dotnet":
		s.Tool = "dotnet"
	case "ruby":
		s.Tool = "bundler"
		s.Frameworks = containsAny(read("Gemfile"), map[string]string{"rails": "rails", "sinatra": "sinatra"})
	case "php":
		s.Tool = "composer"
		s.Frameworks = containsAny(read("composer.json"), map[string]string{"laravel/framework": "laravel", "symfony/": "symfony"})
	}
	return s
}

// readSmall reads a regular file up to maxFileRead bytes; anything else yields "".
func readSmall(p string) string {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(p) //nolint:gosec // path is built from a directory scan of the project root
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, maxFileRead))
	return string(b)
}

func containsAny(text string, needles map[string]string) []string {
	var out []string
	for needle, label := range needles {
		if strings.Contains(text, needle) {
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// ---- node ----

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	PackageManager  string            `json:"packageManager"`
	Engines         map[string]string `json:"engines"`
}

// nodeFrameworks maps dependency names to the dev server they imply.
var nodeFrameworks = map[string]string{
	"vite": "vite", "next": "next", "nuxt": "nuxt", "astro": "astro", "@angular/cli": "angular",
	"webpack-dev-server": "webpack-dev-server", "react-scripts": "react-scripts",
	"@sveltejs/kit": "sveltekit", "storybook": "storybook",
}

func nodeInfo(pkg string, files map[string]bool) (tool string, frameworks []string, version string) {
	tool = "npm"
	switch {
	case files["pnpm-lock.yaml"]:
		tool = "pnpm"
	case files["yarn.lock"]:
		tool = "yarn"
	case files["bun.lock"] || files["bun.lockb"]:
		tool = "bun"
	case files["package-lock.json"]:
		tool = "npm"
	}
	var p packageJSON
	if json.Unmarshal([]byte(pkg), &p) != nil {
		return tool, nil, ""
	}
	if tool == "npm" && !files["package-lock.json"] {
		if name, _, ok := strings.Cut(p.PackageManager, "@"); ok && (name == "pnpm" || name == "yarn") {
			tool = name
		}
	}
	seen := map[string]bool{}
	for _, deps := range []map[string]string{p.Dependencies, p.DevDependencies} {
		for dep := range deps {
			if fw, ok := nodeFrameworks[dep]; ok && !seen[fw] {
				seen[fw] = true
				frameworks = append(frameworks, fw)
			}
		}
	}
	sort.Strings(frameworks)
	return tool, frameworks, p.Engines["node"]
}

// ---- python ----

func pythonTool(files map[string]bool) string {
	switch {
	case files["uv.lock"]:
		return "uv"
	case files["poetry.lock"]:
		return "poetry"
	case files["Pipfile"]:
		return "pipenv"
	}
	return "pip"
}

var pythonFrameworkNames = map[string]string{
	"flask": "flask", "django": "django", "fastapi": "fastapi", "uvicorn": "uvicorn",
	"streamlit": "streamlit", "gradio": "gradio",
}

func pythonFrameworks(read func(string) string, files map[string]bool) []string {
	var text strings.Builder
	for _, f := range []string{"pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "setup.cfg"} {
		if files[f] {
			text.WriteString(strings.ToLower(read(f)))
			text.WriteByte('\n')
		}
	}
	var out []string
	for needle, label := range pythonFrameworkNames {
		if regexp.MustCompile(`(^|[^a-z0-9_-])` + regexp.QuoteMeta(needle) + `($|[^a-z0-9_-])`).MatchString(text.String()) {
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// ---- go ----

var goDirective = regexp.MustCompile(`(?m)^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$`)

func goVersion(mod string) string {
	sc := bufio.NewScanner(strings.NewReader(mod))
	for sc.Scan() {
		if m := goDirective.FindStringSubmatch(sc.Text()); m != nil {
			return m[1]
		}
	}
	return ""
}
