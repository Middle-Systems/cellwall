package cli

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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

func fixture(t *testing.T, name string) string {
	t.Helper()
	dst := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "test", "fixtures", name), dst)
	t.Setenv("CELLWALL_CONFIG_DIR", t.TempDir()) // an empty user-global layer
	return dst
}

func TestInitCreatesThenIsIdempotent(t *testing.T) {
	dir := fixture(t, "polyglot")
	out, _, err := run(t, "init", "--project-dir", dir)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	for _, want := range []string{".cellwall/config.yaml", ".devcontainer/compose.yaml", "detected:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	out, _, err = run(t, "init", "--project-dir", dir)
	if err != nil || !strings.Contains(out, "nothing to do") {
		t.Fatalf("second init should be a no-op: err=%v\n%s", err, out)
	}
}

func TestInitJSON(t *testing.T) {
	dir := fixture(t, "node-vite")
	out, _, err := run(t, "init", "--project-dir", dir, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rep initReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(rep.Actions) == 0 || rep.Conflicts {
		t.Errorf("report = %+v", rep)
	}
}

func TestInitDryRunWritesNothing(t *testing.T) {
	dir := fixture(t, "go-http")
	if _, _, err := run(t, "init", "--project-dir", dir, "--dry-run"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{".cellwall", ".devcontainer"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			t.Errorf("dry run created %s", p)
		}
	}
}

func TestInitRefusesToClobberAndExplainsHow(t *testing.T) {
	dir := fixture(t, "existing-devcontainer")
	before, _ := os.ReadFile(filepath.Join(dir, ".devcontainer", "devcontainer.json"))
	_, errOut, err := run(t, "init", "--project-dir", dir)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	for _, want := range []string{"nothing was written", "--merge", "--force"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("message lacks %q:\n%s", want, errOut)
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".devcontainer", "devcontainer.json"))
	if string(before) != string(after) {
		t.Error("the user's devcontainer.json was modified")
	}
	if _, err := os.Stat(filepath.Join(dir, ".cellwall")); err == nil {
		t.Error("a refused init must write nothing, but .cellwall exists")
	}
}

func TestInitMergeLeavesExistingSetupAlone(t *testing.T) {
	dir := fixture(t, "existing-devcontainer")
	before, _ := os.ReadFile(filepath.Join(dir, ".devcontainer", "devcontainer.json"))
	if _, _, err := run(t, "init", "--project-dir", dir, "--merge"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".devcontainer", "devcontainer.json"))
	if string(before) != string(after) {
		t.Error("--merge modified the user's devcontainer.json")
	}
	if _, err := os.Stat(filepath.Join(dir, ".devcontainer", "cellwall", "compose.yaml")); err != nil {
		t.Errorf("merge layout missing: %v", err)
	}
}

func TestPrepareAfterInitIsQuietAndStable(t *testing.T) {
	dir := fixture(t, "polyglot")
	if _, _, err := run(t, "init", "--project-dir", dir); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, "prepare", "--project-dir", dir)
	if err != nil {
		t.Fatalf("prepare: %v\n%s", err, out)
	}
	if strings.Contains(out, "out of date") {
		t.Errorf("prepare reported drift right after init:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cellwall", "state", "policy", "policy.json")); err != nil {
		t.Errorf("policy.json not written: %v", err)
	}
}

func TestPrepareWithoutInitExplainsNextStep(t *testing.T) {
	dir := fixture(t, "empty")
	_, _, err := run(t, "prepare", "--project-dir", dir)
	if err == nil || !strings.Contains(err.Error(), "cellwall init") {
		t.Fatalf("want an error pointing at `cellwall init`, got %v", err)
	}
}

// The generated files must be accepted by the real `docker compose`. `config` validates the schema
// and interpolation without needing a daemon, so this runs wherever the compose plugin is installed
// (CI's Linux jobs) and is skipped elsewhere.
func TestGeneratedComposeIsValid(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose plugin not available")
	}
	for _, fx := range []string{"node-vite", "python-flask", "go-http", "rust-axum", "polyglot", "java-maven", "dotnet-api", "ruby-rails", "php-laravel", "empty"} {
		t.Run(fx, func(t *testing.T) {
			dir := fixture(t, fx)
			if _, _, err := run(t, "init", "--project-dir", dir); err != nil {
				t.Fatal(err)
			}
			if _, _, err := run(t, "prepare", "--project-dir", dir); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("docker", "compose",
				"-f", filepath.Join(dir, ".devcontainer", "compose.yaml"),
				"-f", filepath.Join(dir, ".cellwall", "state", "compose.override.yaml"),
				"config", "--quiet")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("docker compose rejected the generated files: %v\n%s", err, b)
			}
		})
	}
}
