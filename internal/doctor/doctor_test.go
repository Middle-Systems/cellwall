package doctor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/middle-systems/cellwall/internal/engine"
)

// fakeRunner maps "name arg arg" to canned output or an error.
type fakeRunner map[string]struct {
	out string
	err error
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	r, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("unexpected command %q", key)
	}
	return []byte(r.out), r.err
}

const (
	kClientVer  = "docker version --format {{.Client.Version}}"
	kInfo       = "docker info --format {{json .}}"
	kCompose    = "docker compose version --short"
	kServerJSON = "docker version --format {{json .}}"
)

func healthy() fakeRunner {
	return fakeRunner{
		kClientVer:  {out: "29.6.2\n"},
		kInfo:       {out: `{"ServerVersion":"29.6.2","OperatingSystem":"Ubuntu 24.04","NCPU":8,"MemTotal":17179869184,"SecurityOptions":["name=seccomp,profile=builtin"]}`},
		kCompose:    {out: "5.3.1\n"},
		kServerJSON: {out: `{"Server":{"Version":"29.6.2","Components":[{"Name":"Engine"}]}}`},
	}
}

func byID(r Report, id string) Result {
	for _, res := range r.Results {
		if res.ID == id {
			return res
		}
	}
	return Result{}
}

func opts(r engine.Runner) Options {
	return Options{Runner: r, GOOS: "linux", GOARCH: "amd64", ReadFile: func(string) ([]byte, error) { return []byte("Linux version 6.1"), nil }}
}

func TestHealthyHost(t *testing.T) {
	rep := Run(context.Background(), opts(healthy()))
	if rep.Failed() {
		t.Fatalf("expected no failures: %+v", rep.Results)
	}
	for _, id := range []string{"engine-cli", "engine-daemon", "engine-version", "compose", "engine-flavor", "resources"} {
		if got := byID(rep, id).Status; got != Pass {
			t.Errorf("%s = %q, want pass", id, got)
		}
	}
}

func TestMissingDockerCLI(t *testing.T) {
	r := fakeRunner{
		kClientVer: {err: fmt.Errorf("%w: docker", engine.ErrNotFound)},
		kCompose:   {err: fmt.Errorf("%w: docker", engine.ErrNotFound)},
	}
	rep := Run(context.Background(), opts(r))
	if !rep.Failed() {
		t.Fatal("expected failure")
	}
	res := byID(rep, "engine-cli")
	if res.Status != Fail || res.Fix == "" {
		t.Errorf("engine-cli = %+v, want fail with a fix", res)
	}
	if byID(rep, "engine-daemon").Status != Skip {
		t.Errorf("daemon check should be skipped when the CLI is missing")
	}
}

func TestDaemonDown(t *testing.T) {
	r := healthy()
	r[kInfo] = struct {
		out string
		err error
	}{err: errors.New("Cannot connect to the Docker daemon")}
	rep := Run(context.Background(), opts(r))
	if byID(rep, "engine-daemon").Status != Fail {
		t.Errorf("daemon down should fail: %+v", rep.Results)
	}
	if byID(rep, "engine-version").Status != Skip {
		t.Errorf("version check should be skipped when the daemon is down")
	}
}

// Security-first: an engine too old to isolate the host from the sandbox network is a failure,
// not a warning (docs/decisions/0001-isolated-gateway-mode.md).
func TestOldEngineFails(t *testing.T) {
	r := healthy()
	r[kInfo] = struct {
		out string
		err error
	}{out: `{"ServerVersion":"27.5.1","NCPU":8,"MemTotal":17179869184}`}
	rep := Run(context.Background(), opts(r))
	res := byID(rep, "engine-version")
	if res.Status != Fail || !strings.Contains(res.Fix, "28") {
		t.Errorf("engine-version = %+v, want fail mentioning 28", res)
	}
}

func TestUnparseableEngineVersionWarnsNotPasses(t *testing.T) {
	r := healthy()
	r[kInfo] = struct {
		out string
		err error
	}{out: `{"ServerVersion":"weird","NCPU":8,"MemTotal":17179869184}`}
	if got := byID(Run(context.Background(), opts(r)), "engine-version").Status; got != Warn {
		t.Errorf("unparseable version = %q, want warn (never silently pass)", got)
	}
}

func TestComposeV1Fails(t *testing.T) {
	r := healthy()
	r[kCompose] = struct {
		out string
		err error
	}{out: "1.29.2\n"}
	if got := byID(Run(context.Background(), opts(r)), "compose").Status; got != Fail {
		t.Errorf("compose v1 = %q, want fail", got)
	}
}

func TestPodmanAndRootlessWarn(t *testing.T) {
	r := healthy()
	r[kServerJSON] = struct {
		out string
		err error
	}{out: `{"Server":{"Components":[{"Name":"Podman Engine"}]}}`}
	r[kInfo] = struct {
		out string
		err error
	}{out: `{"ServerVersion":"5.2.0","NCPU":8,"MemTotal":17179869184,"SecurityOptions":["name=rootless"]}`}
	res := byID(Run(context.Background(), opts(r)), "engine-flavor")
	if res.Status != Warn || !strings.Contains(res.Detail, "Podman") || !strings.Contains(res.Detail, "rootless") {
		t.Errorf("flavor = %+v", res)
	}
}

func TestLowResourcesWarn(t *testing.T) {
	r := healthy()
	r[kInfo] = struct {
		out string
		err error
	}{out: `{"ServerVersion":"29.6.2","NCPU":2,"MemTotal":4294967296}`}
	res := byID(Run(context.Background(), opts(r)), "resources")
	if res.Status != Warn || res.Fix == "" {
		t.Errorf("resources = %+v", res)
	}
}

func TestWSL2Detection(t *testing.T) {
	o := opts(healthy())
	o.ReadFile = func(string) ([]byte, error) { return []byte("Linux version 5.15 (microsoft-standard-WSL2)"), nil }
	if got := byID(Run(context.Background(), o), "wsl2").Status; got != Warn {
		t.Errorf("wsl2 = %q, want warn", got)
	}
	// Not reported on non-WSL Linux or other OSes.
	if byID(Run(context.Background(), opts(healthy())), "wsl2").ID != "" {
		t.Error("wsl2 reported on plain Linux")
	}
	o = opts(healthy())
	o.GOOS = "darwin"
	if byID(Run(context.Background(), o), "wsl2").ID != "" {
		t.Error("wsl2 reported on darwin")
	}
}

func TestMajorVersion(t *testing.T) {
	for in, want := range map[string]int{"29.6.2": 29, "v28.0.0-rc.1": 28, " 5.3.1\n": 5} {
		if got, ok := majorVersion(in); !ok || got != want {
			t.Errorf("majorVersion(%q) = %d,%v want %d", in, got, ok, want)
		}
	}
	if _, ok := majorVersion("abc"); ok {
		t.Error("expected parse failure")
	}
}
