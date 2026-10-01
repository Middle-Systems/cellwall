//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestGeneratedTopology runs what `cellwall init` + `cellwall prepare` produce, end to end: the
// image builds, the gateway becomes healthy, and from inside the agent the sandbox holds (no route
// around the proxy, protected paths read-only, caches writable, the policy denies by default).
// It needs the gateway image tagged cellwall-gateway:local (make gateway-image) and network access
// to build the agent image.
func TestGeneratedTopology(t *testing.T) {
	requireDocker(t)
	root := repoRoot(t)

	bin := filepath.Join(t.TempDir(), "cellwall")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, filepath.Join(root, "cmd", "cellwall")).CombinedOutput(); err != nil {
		t.Fatalf("build cellwall: %v\n%s", err, out)
	}

	ws := t.TempDir()
	copyTree(t, filepath.Join(root, "test", "fixtures", "node-vite"), ws)
	for _, d := range []string{".git/hooks"} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	env := append(os.Environ(), "CELLWALL_CONFIG_DIR="+t.TempDir(), "COMPOSE_PROJECT_NAME=cwe2egen")
	runIn := func(name string, args ...string) string {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = ws
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	runIn(bin, "init")
	runIn(bin, "prepare")

	compose := []string{"compose",
		"-f", ".devcontainer/compose.yaml", "-f", ".cellwall/state/compose.override.yaml",
		"--env-file", ".cellwall/state/compose.env", "--project-directory", ".devcontainer"}
	dc := func(args ...string) string { return runIn("docker", append(append([]string{}, compose...), args...)...) }
	t.Cleanup(func() {
		cmd := exec.Command("docker", append(append([]string{}, compose...), "down", "-v", "--remove-orphans", "-t", "1")...)
		cmd.Dir, cmd.Env = ws, env
		_ = cmd.Run()
	})

	dc("build")
	dc("up", "-d", "--wait", "--wait-timeout", "90", "gateway")
	dc("up", "-d", "--no-build", "agent")
	time.Sleep(time.Second)

	sh := func(script string) (string, error) {
		cmd := exec.Command("docker", append(append([]string{}, compose...), "exec", "-T", "agent", "sh", "-c", script)...)
		cmd.Dir, cmd.Env = ws, env
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	t.Run("proxy environment is set", func(t *testing.T) {
		out, err := sh(`echo "$HTTPS_PROXY"`)
		if err != nil || out != "http://gateway:3128" {
			t.Fatalf("HTTPS_PROXY = %q (%v)", out, err)
		}
	})
	t.Run("no route around the gateway", func(t *testing.T) {
		if out, err := sh(`curl -sS --noproxy '*' -m 5 -o /dev/null https://1.1.1.1`); err == nil {
			t.Fatalf("direct connection succeeded: %s", out)
		}
	})
	t.Run("unlisted host is denied by policy", func(t *testing.T) {
		out, _ := sh(`curl -sS -m 10 -o /dev/null -w '%{http_code}' https://example.com 2>&1`)
		if strings.Contains(out, "200") {
			t.Fatalf("an unlisted host was reachable: %s", out)
		}
	})
	t.Run("protected paths are read-only", func(t *testing.T) {
		if out, err := sh(`echo x > /workspace/.git/hooks/pre-commit`); err == nil {
			t.Fatalf("wrote a git hook: %s", out)
		}
		if out, err := sh(`echo x > /workspace/.devcontainer/devcontainer.json`); err == nil {
			t.Fatalf("modified devcontainer.json: %s", out)
		}
	})
	t.Run("gateway state is hidden from the agent", func(t *testing.T) {
		out, _ := sh(`ls -A /workspace/.cellwall/state | wc -l`)
		if strings.TrimSpace(out) != "0" {
			t.Fatalf("agent can see gateway state: %q", out)
		}
	})
	t.Run("workspace and caches are writable", func(t *testing.T) {
		if out, err := sh(`touch /workspace/.probe && rm /workspace/.probe && mkdir -p /workspace/node_modules/.probe && rmdir /workspace/node_modules/.probe`); err != nil {
			t.Fatalf("not writable: %v %s", err, out)
		}
	})
	t.Run("runs as the unprivileged user", func(t *testing.T) {
		out, _ := sh(`id -u`)
		if out == "0" {
			t.Fatal("agent runs as root")
		}
	})
	t.Run("agent tool is installed", func(t *testing.T) {
		if out, err := sh(`claude --version`); err != nil {
			t.Fatalf("claude --version: %v %s", err, out)
		}
	})
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}
