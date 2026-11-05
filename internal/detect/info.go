package detect

import (
	"bufio"
	"path"
	"sort"
	"strings"
)

// Info is static knowledge about a stack that init and the generator use.
type Info struct {
	Name string
	// Preset is the gateway allowlist preset for the stack's package registries.
	Preset string
	// CacheDirs are regenerable directories (relative to the stack's dir) that belong on named
	// volumes so they stay off a slow bind mount.
	CacheDirs []string
}

var infos = map[string]Info{
	"node":   {Name: "node", Preset: "node", CacheDirs: []string{"node_modules"}},
	"python": {Name: "python", Preset: "python", CacheDirs: []string{".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache"}},
	"go":     {Name: "go", Preset: "go"}, // GOCACHE and GOMODCACHE live in the agent-home volume
	"rust":   {Name: "rust", Preset: "rust", CacheDirs: []string{"target"}},
	"java":   {Name: "java", Preset: "java", CacheDirs: []string{".gradle", "target", "build"}},
	"dotnet": {Name: "dotnet", Preset: "dotnet", CacheDirs: []string{"obj", "bin"}},
	"ruby":   {Name: "ruby", Preset: "ruby"},
	"php":    {Name: "php", Preset: "php", CacheDirs: []string{"vendor"}},
}

// InfoFor returns the static info for a stack name.
func InfoFor(name string) (Info, bool) {
	i, ok := infos[name]
	return i, ok
}

// frameworkCaches are extra cache dirs implied by a detected framework.
var frameworkCaches = map[string][]string{
	"next": {".next"}, "nuxt": {".nuxt", ".output"}, "sveltekit": {".svelte-kit"}, "angular": {".angular"}, "astro": {".astro"},
}

// Framework describes a dev server: its default port and how to make it listen on all interfaces
// (inside the container it must, or the gateway's forwarder cannot reach it).
type Framework struct {
	Name     string
	Port     int
	BindHint string
}

var frameworks = map[string]Framework{
	"vite":               {"vite", 5173, "vite --host 0.0.0.0   (npm: `npm run dev -- --host`)"},
	"next":               {"next", 3000, "next dev -H 0.0.0.0"},
	"nuxt":               {"nuxt", 3000, "nuxt dev --host 0.0.0.0"},
	"astro":              {"astro", 4321, "astro dev --host 0.0.0.0"},
	"angular":            {"angular", 4200, "ng serve --host 0.0.0.0"},
	"webpack-dev-server": {"webpack-dev-server", 8080, "webpack serve --host 0.0.0.0"},
	"react-scripts":      {"react-scripts", 3000, "HOST=0.0.0.0 npm start"},
	"sveltekit":          {"sveltekit", 5173, "vite dev --host 0.0.0.0"},
	"storybook":          {"storybook", 6006, "storybook dev --host 0.0.0.0"},
	"flask":              {"flask", 5000, "flask run --host=0.0.0.0"},
	"django":             {"django", 8000, "python manage.py runserver 0.0.0.0:8000"},
	"fastapi":            {"fastapi", 8000, "fastapi dev --host 0.0.0.0   (or uvicorn app:app --host 0.0.0.0)"},
	"uvicorn":            {"uvicorn", 8000, "uvicorn app:app --host 0.0.0.0"},
	"streamlit":          {"streamlit", 8501, "streamlit run app.py --server.address 0.0.0.0"},
	"gradio":             {"gradio", 7860, `launch(server_name="0.0.0.0")`},
	"rails":              {"rails", 3000, "bin/rails server -b 0.0.0.0"},
	"laravel":            {"laravel", 8000, "php artisan serve --host=0.0.0.0"},
	"spring-boot":        {"spring-boot", 8080, "server.address=0.0.0.0 (Spring binds all interfaces by default)"},
}

// FrameworkFor returns the dev-server info for a detected framework name.
func FrameworkFor(name string) (Framework, bool) {
	f, ok := frameworks[name]
	return f, ok
}

// Plan is the result of applying static knowledge to a detection result.
type Plan struct {
	Presets   []string // gateway allowlist presets for the detected registries, canonical order
	Caches    []string // workspace-relative cache directories
	Ports     []int    // preview ports implied by detected frameworks, sorted
	BindHints []string // human-readable "make the dev server listen on 0.0.0.0" hints
	Notes     []string
}

// PlanFor derives presets, caches, ports and hints. gitignored reports whether a workspace-relative
// directory is excluded from version control, and occupied whether it exists and has content (or is
// not a directory at all).
//
// A cache volume is planned for a directory that is gitignored, or has nothing in it, because a
// volume mounted over a directory with tracked content would hide committed files. "Empty" counts
// as safe on purpose: `prepare` pre-creates cache directories (spike S10), and judging by mere
// existence would make the plan change after prepare ran.
func PlanFor(r *Result, gitignored func(dir string) bool, occupied func(dir string) bool) Plan {
	var p Plan
	presets := map[string]bool{}
	caches := map[string]bool{}
	ports := map[int]bool{}
	hints := map[string]bool{}

	addCache := func(dir string) {
		if gitignored(dir) || !occupied(dir) {
			caches[dir] = true
			return
		}
		p.Notes = append(p.Notes, dir+"/ has content that is not gitignored, so it was not moved to a cache volume (add it to .gitignore to enable)")
	}
	for _, s := range r.Stacks {
		info, ok := InfoFor(s.Name)
		if !ok {
			continue
		}
		presets[info.Preset] = true
		caches2 := append([]string(nil), info.CacheDirs...)
		for _, fw := range s.Frameworks {
			caches2 = append(caches2, frameworkCaches[fw]...)
		}
		// Maven and Gradle disagree about what "build output" is called.
		if s.Name == "java" && s.Tool == "maven" {
			caches2 = filterOut(caches2, ".gradle", "build")
		}
		if s.Name == "java" && s.Tool == "gradle" {
			caches2 = filterOut(caches2, "target")
		}
		for _, c := range caches2 {
			addCache(path.Clean(path.Join(s.Dir, c)))
		}
		for _, fw := range s.Frameworks {
			if f, ok := FrameworkFor(fw); ok {
				// One hint per port: fastapi and uvicorn both serve 8000 and one note is enough.
				if !ports[f.Port] {
					hints[f.Name+": "+f.BindHint] = true
				}
				ports[f.Port] = true
			}
		}
	}
	for _, n := range order {
		if info, ok := infos[n]; ok && presets[info.Preset] {
			p.Presets = append(p.Presets, info.Preset)
		}
	}
	p.Caches = sortedKeys(caches)
	for port := range ports {
		p.Ports = append(p.Ports, port)
	}
	sort.Ints(p.Ports)
	p.BindHints = sortedKeys(hints)
	return p
}

func filterOut(list []string, drop ...string) []string {
	var out []string
	for _, x := range list {
		skip := false
		for _, d := range drop {
			skip = skip || x == d
		}
		if !skip {
			out = append(out, x)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GitIgnore is a deliberately small .gitignore reader: enough to tell whether a directory such as
// node_modules or target is excluded. It understands exact names, trailing slashes, leading
// slashes and "**/" prefixes; anything fancier (negations, globs) is treated as "not ignored",
// which errs toward NOT creating a volume over possibly tracked files.
type GitIgnore struct{ patterns []string }

// ParseGitIgnore reads .gitignore text.
func ParseGitIgnore(text string) *GitIgnore {
	g := &GitIgnore{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.ContainsAny(line, "*?[") && !strings.HasPrefix(line, "**/") {
			continue
		}
		line = strings.TrimPrefix(line, "**/")
		if strings.ContainsAny(line, "*?[") {
			continue
		}
		g.patterns = append(g.patterns, strings.Trim(line, "/")+"|"+boolStr(strings.HasPrefix(strings.TrimSpace(sc.Text()), "/")))
	}
	return g
}

func boolStr(b bool) string {
	if b {
		return "anchored"
	}
	return "any"
}

// Ignored reports whether the workspace-relative directory dir is covered by a pattern.
func (g *GitIgnore) Ignored(dir string) bool {
	if g == nil {
		return false
	}
	for _, p := range g.patterns {
		pat, mode, _ := strings.Cut(p, "|")
		if mode == "anchored" {
			if dir == pat || strings.HasPrefix(dir, pat+"/") {
				return true
			}
			continue
		}
		// Unanchored: matches that name at any depth (or the full relative path).
		if dir == pat || path.Base(dir) == pat || strings.HasSuffix(dir, "/"+pat) || strings.HasPrefix(dir, pat+"/") {
			return true
		}
	}
	return false
}
