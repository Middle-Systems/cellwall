package gen

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

var goldenFixtures = []string{
	"node-vite", "python-flask", "go-http", "rust-axum", "polyglot",
	"java-maven", "dotnet-api", "ruby-rails", "php-laravel", "empty",
}

func goldenRoot(fixture string) string { return filepath.Join("testdata", "golden", fixture) }

// TestGolden pins the exact bytes generated for each fixture. A diff here is a deliberate review
// point: generated files are what users run, so every change to them should be seen.
func TestGolden(t *testing.T) {
	for _, fx := range goldenFixtures {
		t.Run(fx, func(t *testing.T) {
			in, presets := inputsFor(t, fx, nil)
			files, err := Committed(in, presets)
			if err != nil {
				t.Fatal(err)
			}
			dir := goldenRoot(fx)
			want := map[string]bool{}
			for _, f := range files {
				want[f.Path] = true
				p := filepath.Join(dir, filepath.FromSlash(f.Path))
				if *update {
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, f.Content, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				got, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("no golden for %s (run: go test ./internal/gen -update): %v", f.Path, err)
				}
				if !bytes.Equal(got, f.Content) {
					t.Errorf("%s differs from golden (run: go test ./internal/gen -update, then review the diff)", f.Path)
				}
			}
			if *update {
				return
			}
			// A removed output must not linger as a stale golden.
			err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(dir, p)
				if !want[filepath.ToSlash(rel)] {
					t.Errorf("stale golden file %s: the generator no longer produces it", rel)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Rendering twice must give identical bytes (map ordering, timestamps and the like must not leak).
func TestDeterministic(t *testing.T) {
	for _, fx := range goldenFixtures {
		in, presets := inputsFor(t, fx, nil)
		a, err := Committed(in, presets)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := Committed(in, presets)
		if len(a) != len(b) {
			t.Fatalf("%s: file count changed between renders", fx)
		}
		for i := range a {
			if a[i].Path != b[i].Path || !bytes.Equal(a[i].Content, b[i].Content) {
				t.Errorf("%s: %s is not deterministic", fx, a[i].Path)
			}
		}
	}
}

// Every generated file must be well formed, and carry a stamp that matches its body, so init can
// tell pristine from edited.
func TestGeneratedFilesAreValid(t *testing.T) {
	for _, fx := range goldenFixtures {
		in, presets := inputsFor(t, fx, nil)
		files, err := Committed(in, presets)
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, f := range files {
			paths = append(paths, f.Path)
			switch {
			case strings.HasSuffix(f.Path, ".yaml"):
				var v any
				if err := yaml.Unmarshal(f.Content, &v); err != nil {
					t.Errorf("%s/%s: invalid YAML: %v", fx, f.Path, err)
				}
			case strings.HasSuffix(f.Path, "devcontainer.json"):
				if err := json.Unmarshal(stripLineComments(f.Content), &struct{}{}); err != nil {
					t.Errorf("%s/%s: invalid JSON: %v", fx, f.Path, err)
				}
			}
			if f.Kind == Generated {
				if st := Inspect(f.Content); st != Pristine {
					t.Errorf("%s/%s: freshly generated file does not inspect as pristine (%v)", fx, f.Path, st)
				}
			}
		}
		sort.Strings(paths)
		for _, must := range []string{".devcontainer/Dockerfile", ".devcontainer/compose.yaml", ".devcontainer/devcontainer.json"} {
			if contentOf(t, files, must) == "" {
				t.Errorf("%s: %s is empty", fx, must)
			}
		}
	}
}

// stripLineComments removes whole-line // comments (devcontainer.json allows them).
func stripLineComments(b []byte) []byte {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "//") {
			continue
		}
		out = append(out, l)
	}
	return []byte(strings.Join(out, "\n"))
}
