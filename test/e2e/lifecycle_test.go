//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestLifecycle drives the shipped binary the way a person does: init, run, a blocked request,
// logs --denied, allow, status, down. It is the M3 "done when" on a real engine:
//   - `init && run` gives a working agent session,
//   - `allow` unblocks a host live (no restart),
//   - exit codes propagate.
func TestLifecycle(t *testing.T) {
	requireDocker(t)
	root := repoRoot(t)

	// A static binary, as a release is: `up` builds the gateway image from this very file.
	bin := filepath.Join(t.TempDir(), "kennel")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath", "-o", bin, filepath.Join(root, "cmd", "kennel"))
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build kennel: %v\n%s", err, out)
	}

	ws := t.TempDir()
	copyTree(t, filepath.Join(root, "test", "fixtures", "node-vite"), ws)
	if err := os.MkdirAll(filepath.Join(ws, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "KENNEL_CONFIG_DIR="+t.TempDir())

	type result struct {
		out, err string
		code     int
	}
	cw := func(stdin string, args ...string) result {
		t.Helper()
		cmd := exec.Command(bin, args...)
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
			t.Fatalf("kennel %s: %v", strings.Join(args, " "), err)
		}
		return result{o.String(), e.String(), code}
	}
	must := func(r result, what string) result {
		t.Helper()
		if r.code != 0 {
			t.Fatalf("%s: exit %d\nstdout:\n%s\nstderr:\n%s", what, r.code, r.out, r.err)
		}
		return r
	}
	t.Cleanup(func() { cw("", "down", "--volumes", "--yes") })

	must(cw("", "init"), "init")

	t.Run("init then run gives a working agent session", func(t *testing.T) {
		r := must(cw("", "run", "--no-tty", "--", "--version"), "run -- --version")
		if !strings.Contains(r.out, "Claude Code") && !strings.Contains(r.out, ".") {
			t.Errorf("the agent did not print a version:\n%s", r.out)
		}
	})

	t.Run("a second up changes nothing", func(t *testing.T) {
		r := must(cw("", "up"), "up")
		if !strings.Contains(r.out, "is up") {
			t.Errorf("up output:\n%s", r.out)
		}
	})

	t.Run("exit codes propagate", func(t *testing.T) {
		if r := cw("exit 9\n", "shell", "--no-tty"); r.code != 9 {
			t.Errorf("shell exit = %d, want 9\n%s", r.code, r.err)
		}
		if r := cw("exit 0\n", "shell", "--no-tty"); r.code != 0 {
			t.Errorf("shell exit = %d, want 0\n%s", r.code, r.err)
		}
	})

	probe := func() string {
		t.Helper()
		r := cw("curl -sS -m 20 -o /dev/null https://example.org 2>&1; echo done\n", "shell", "--no-tty")
		return r.out + r.err
	}

	t.Run("a blocked request is explained, listed and allowed live", func(t *testing.T) {
		if got := probe(); !strings.Contains(got, "403") {
			t.Fatalf("an unlisted host must be refused with 403 before allow, got:\n%s", got)
		}
		r := must(cw("", "logs", "--denied"), "logs --denied")
		if !strings.Contains(r.out, "example.org:443") || !strings.Contains(r.out, "kennel allow example.org") {
			t.Fatalf("logs --denied should list the host and the command to allow it:\n%s", r.out)
		}

		start := time.Now()
		a := must(cw("", "allow", "example.org"), "allow")
		if !strings.Contains(a.out, "gateway is enforcing it now") {
			t.Fatalf("allow should confirm the running gateway loaded it:\n%s", a.out)
		}
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("allow took %s", d)
		}
		if got := probe(); strings.Contains(got, "403") {
			t.Fatalf("the host is still refused after allow (no restart should be needed):\n%s", got)
		}

		var allowed bool
		for _, line := range strings.Split(strings.TrimSpace(must(cw("", "logs", "--json"), "logs --json").out), "\n") {
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) == nil && rec["host"] == "example.org" && rec["action"] == "allow" {
				allowed = true
			}
		}
		if !allowed {
			t.Error("the audit log has no allow decision for example.org after allow")
		}
	})

	t.Run("deny overrides within the session", func(t *testing.T) {
		must(cw("", "deny", "example.org"), "deny")
		if got := probe(); !strings.Contains(got, "403") {
			t.Fatalf("a denied host must be refused again:\n%s", got)
		}
	})

	t.Run("status reports an isolated network and a gateway in sync", func(t *testing.T) {
		r := must(cw("", "status", "--json"), "status --json")
		var rep struct {
			Network struct {
				Internal bool `json:"internal"`
				Isolated bool `json:"host_isolated"`
			} `json:"network"`
			Policy struct {
				InSync bool `json:"in_sync"`
			} `json:"policy"`
			Containers []struct{ Service, State string }
		}
		if err := json.Unmarshal([]byte(r.out), &rep); err != nil {
			t.Fatalf("status --json: %v\n%s", err, r.out)
		}
		if !rep.Network.Internal || !rep.Network.Isolated {
			t.Errorf("sandbox network not isolated: %+v", rep.Network)
		}
		if !rep.Policy.InSync {
			t.Errorf("gateway not in sync with the policy on disk:\n%s", r.out)
		}
		if len(rep.Containers) != 2 {
			t.Errorf("containers = %+v", rep.Containers)
		}
	})

	t.Run("down removes the containers", func(t *testing.T) {
		must(cw("", "down"), "down")
		r := must(cw("", "status", "--json"), "status after down")
		var rep struct {
			Containers []struct{} `json:"containers"`
		}
		_ = json.Unmarshal([]byte(r.out), &rep)
		if len(rep.Containers) != 0 {
			t.Errorf("containers remain after down:\n%s", r.out)
		}
		// Session rules survive a restart of the sandbox: they live in the project's state.
		if r := cw("", "shell", "--no-tty"); r.code == 0 || !strings.Contains(r.err, "kennel up") {
			t.Errorf("shell without a sandbox should fail and say `kennel up`: %d %s", r.code, r.err)
		}
	})
}
