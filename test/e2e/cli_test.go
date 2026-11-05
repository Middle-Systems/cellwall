//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
)

// staticBinary builds kennel once per test run, statically linked like a release, so `up` can
// build the gateway image from it.
func staticBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "kennel-e2e-bin-")
		if err != nil {
			buildErr = err
			return
		}
		builtBin = filepath.Join(dir, "kennel")
		if runtime.GOOS == "windows" {
			builtBin += ".exe"
		}
		cmd := exec.Command("go", "build", "-trimpath", "-o", builtBin, filepath.Join(repoRoot(t), "cmd", "kennel"))
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = errors.New(string(out))
		}
	})
	if buildErr != nil {
		t.Fatalf("build kennel: %v", buildErr)
	}
	return builtBin
}

// project is a copy of a fixture driven through the shipped binary.
type project struct {
	t   *testing.T
	bin string
	ws  string
	env []string
}

type result struct {
	out, err string
	code     int
}

// newProject copies a fixture into a temp dir with a .git/hooks directory, and arranges for the
// sandbox to be torn down (with its volumes) when the test ends.
func newProject(t *testing.T, fixture string) *project {
	t.Helper()
	// A distinct directory name gives each test its own compose project, images and volumes.
	name := strings.NewReplacer("/", "-", "_", "-").Replace(strings.ToLower(t.Name()))
	if len(name) > 36 {
		name = name[:36]
	}
	ws := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	p := &project{t: t, bin: staticBinary(t), ws: ws}
	copyTree(t, filepath.Join(repoRoot(t), "test", "fixtures", fixture), p.ws)
	if err := os.MkdirAll(filepath.Join(p.ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.env = append(os.Environ(), "KENNEL_CONFIG_DIR="+t.TempDir())
	t.Cleanup(func() { p.cw("", "down", "--volumes", "--yes") })
	return p
}

func (p *project) cw(stdin string, args ...string) result {
	p.t.Helper()
	cmd := exec.Command(p.bin, args...)
	cmd.Dir, cmd.Env = p.ws, p.env
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		p.t.Fatalf("kennel %s: %v", strings.Join(args, " "), err)
	}
	return result{o.String(), e.String(), code}
}

func (p *project) must(r result, what string) result {
	p.t.Helper()
	if r.code != 0 {
		p.t.Fatalf("%s: exit %d\nstdout:\n%s\nstderr:\n%s", what, r.code, r.out, r.err)
	}
	return r
}

// sh runs a shell script in the agent container and returns its output and exit code.
func (p *project) sh(script string) result {
	p.t.Helper()
	return p.cw(script+"\n", "shell", "--no-tty")
}
