//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVolumeMode is the M5 round trip on a real engine: the agent works on its own copy of the
// repository, its commits come back through `fetch` (strictly verified), and nothing it does is
// visible on the host until `fetch --apply`.
func TestVolumeMode(t *testing.T) {
	requireDocker(t)
	root := repoRoot(t)

	bin := filepath.Join(t.TempDir(), "cellwall")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, filepath.Join(root, "cmd", "cellwall"))
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cellwall: %v\n%s", err, out)
	}

	ws := t.TempDir()
	copyTree(t, filepath.Join(root, "test", "fixtures", "node-vite"), ws)
	env := append(os.Environ(), "CELLWALL_CONFIG_DIR="+t.TempDir(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")

	run := func(name string, stdin string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir, cmd.Env = ws, env
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
			t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
		}
		return o.String(), e.String(), code
	}
	must := func(name, stdin string, args ...string) string {
		t.Helper()
		o, e, c := run(name, stdin, args...)
		if c != 0 {
			t.Fatalf("%s %s: exit %d\n%s\n%s", name, strings.Join(args, " "), c, o, e)
		}
		return o
	}

	must("git", "", "init", "-q", "-b", "main")
	must("git", "", "add", "-A")
	must("git", "", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")
	t.Cleanup(func() { run(bin, "", "down", "--volumes", "--yes") })

	must(bin, "", "init", "--workspace", "volume")
	if out := must(bin, "", "up"); !strings.Contains(out, "seeded") && !strings.Contains(out, "copy") {
		t.Errorf("up should say it seeded the volume:\n%s", out)
	}

	t.Run("the agent's work is invisible on the host until fetched", func(t *testing.T) {
		must(bin, "", "shell", "--no-tty")
		script := "cd /workspace && git config user.email a@b && git config user.name a && " +
			"git checkout -q -b agent/work && echo hi > agent-made.txt && git add -A && git commit -q -m 'agent change'\nexit 0\n"
		must(bin, script, "shell", "--no-tty")
		if _, err := os.Stat(filepath.Join(ws, "agent-made.txt")); err == nil {
			t.Fatal("the agent's file appeared on the host before fetch")
		}
		out := must(bin, "", "fetch")
		if !strings.Contains(out, "agent-made.txt") {
			t.Errorf("fetch should list the changed file:\n%s", out)
		}
		if _, err := os.Stat(filepath.Join(ws, "agent-made.txt")); err == nil {
			t.Fatal("fetch alone must not touch the working tree")
		}
	})

	t.Run("a change to a protected file stops --apply", func(t *testing.T) {
		script := "cd /workspace && git checkout -q agent/work && mkdir -p .husky && echo x > .husky/pre-commit && git add -A && git commit -q -m hook\nexit 0\n"
		must(bin, script, "shell", "--no-tty")
		must("git", "", "checkout", "-q", "-b", "agent/work")
		_, e, c := run(bin, "", "fetch", "--apply")
		if c == 0 || !strings.Contains(e+"", "protected") {
			t.Errorf("--apply must stop at a protected file without confirmation (exit %d):\n%s", c, e)
		}
	})

	t.Run("--apply with confirmation fast-forwards", func(t *testing.T) {
		must(bin, "", "fetch", "--apply", "--allow-protected")
		if _, err := os.Stat(filepath.Join(ws, "agent-made.txt")); err != nil {
			t.Errorf("agent-made.txt should be present after --apply: %v", err)
		}
	})

	t.Run("verify passes with host isolation checks", func(t *testing.T) {
		must(bin, "", "verify", "--strict")
	})
}
