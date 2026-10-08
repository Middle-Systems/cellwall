package compose

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/middle-systems/cellwall/internal/prepare"
	"github.com/middle-systems/cellwall/internal/scaffold"
)

func initProject(t *testing.T, merge bool) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := scaffold.Build(scaffold.Options{Root: root, Merge: merge, GlobalConfigDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.Apply(); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestOpenWithoutInitSaysWhatToDo(t *testing.T) {
	_, err := Open(t.TempDir(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "cellwall init") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenFindsFilesAndArgsAreStable(t *testing.T) {
	root := initProject(t, false)
	g := t.TempDir()
	p, err := Open(root, g)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 1 || p.EnvFile != "" {
		t.Fatalf("before prepare there is only the base file: %+v", p)
	}
	if _, err := prepare.Run(prepare.Options{Root: root, GlobalConfigDir: g}); err != nil {
		t.Fatal(err)
	}
	p, _ = Open(root, g)
	args := p.Args("up", "-d")
	if len(p.Files) != 2 || p.EnvFile == "" {
		t.Fatalf("after prepare the override and env file are used: %+v", p)
	}
	if args[0] != "compose" || !slices.Contains(args, "--project-directory") || args[len(args)-2] != "up" {
		t.Errorf("args = %v", args)
	}
	if !strings.HasPrefix(p.Name, "cw-") {
		t.Errorf("name = %q", p.Name)
	}
}

func TestOpenHonoursTheMergeLayout(t *testing.T) {
	root := initProject(t, true)
	// --merge only relocates files when an existing devcontainer is present; without one the
	// default layout is kept. Both must be openable.
	if _, err := Open(root, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
