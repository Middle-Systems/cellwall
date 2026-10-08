package configedit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/middle-systems/cellwall/internal/config"
)

const cfg = `# my config
version: 1
project: demo

# Dev-server ports (keep this comment)
ports: [5173]

hardening:
  pids_limit: 512 # trailing
`

func project(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".cellwall"), 0o755)
	if err := os.WriteFile(filepath.Join(root, config.ProjectFile), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func load(t *testing.T, root string) *config.Config {
	t.Helper()
	l, err := config.Load(config.LoadOptions{ProjectDir: root})
	if err != nil {
		t.Fatalf("config no longer loads: %v", err)
	}
	return l.Config
}

func TestSetPortsKeepsEverythingElse(t *testing.T) {
	root := project(t, cfg)
	ch, err := SetPorts(root, []int{8080, 3000, 5173, 3000})
	if err != nil || !ch.Changed {
		t.Fatalf("%v %v", ch, err)
	}
	b, _ := os.ReadFile(filepath.Join(root, config.ProjectFile))
	text := string(b)
	for _, want := range []string{"# my config", "# Dev-server ports (keep this comment)", "ports: [3000, 5173, 8080]", "pids_limit: 512 # trailing", "project: demo"} {
		if !strings.Contains(text, want) {
			t.Errorf("lost %q:\n%s", want, text)
		}
	}
	if got := load(t, root).Ports; !reflect.DeepEqual(got, []int{3000, 5173, 8080}) {
		t.Errorf("ports = %v", got)
	}
	// Blank lines are part of how people lay a file out; yaml.v3 drops them, so they are restored.
	if strings.Count(text, "\n\n") != strings.Count(cfg, "\n\n") {
		t.Errorf("blank lines were not preserved:\n%s", text)
	}
}

func TestSetPortsIsIdempotentAndReversible(t *testing.T) {
	root := project(t, cfg)
	if ch, err := SetPorts(root, []int{5173}); err != nil || ch.Changed {
		t.Fatalf("setting the same ports must not rewrite the file: %v %v", ch, err)
	}
	ch, err := SetPorts(root, nil)
	if err != nil || !ch.Changed {
		t.Fatal(err)
	}
	if got := load(t, root).Ports; len(got) != 0 {
		t.Errorf("ports = %v", got)
	}
	if err := ch.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := load(t, root).Ports; !reflect.DeepEqual(got, []int{5173}) {
		t.Errorf("rollback did not restore: %v", got)
	}
}

func TestSetPortsAddsTheKeyWhenMissing(t *testing.T) {
	root := project(t, "version: 1\nproject: demo\n")
	if _, err := SetPorts(root, []int{3000}); err != nil {
		t.Fatal(err)
	}
	if got := load(t, root).Ports; !reflect.DeepEqual(got, []int{3000}) {
		t.Errorf("ports = %v", got)
	}
}

func TestSetPortsWithoutAConfigPointsAtInit(t *testing.T) {
	if _, err := SetPorts(t.TempDir(), []int{3000}); err == nil || !strings.Contains(err.Error(), "cellwall init") {
		t.Fatalf("got %v", err)
	}
}

func TestSetPortsRefusesASymlinkedConfigDirectory(t *testing.T) {
	root := t.TempDir()
	target := project(t, cfg)
	if err := os.Symlink(filepath.Join(target, ".cellwall"), filepath.Join(root, ".cellwall")); err != nil {
		t.Skip(err)
	}
	if _, err := SetPorts(root, []int{3000}); err == nil {
		t.Fatal("must not write through a symlinked .cellwall")
	}
}
