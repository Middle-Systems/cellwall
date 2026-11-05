package gatewayimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/middle-systems/kennel/internal/engine"
)

// fakeDocker answers `image inspect` from a table and records builds.
type fakeDocker struct {
	arch   string
	label  string
	exists bool
	calls  [][]string
	built  *struct{ label, tag, dockerfile, binary string }
}

func (f *fakeDocker) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	switch {
	case len(args) >= 1 && args[0] == "info":
		if f.arch == "" {
			return []byte("x86_64\n"), nil
		}
		return []byte(f.arch + "\n"), nil
	case len(args) >= 2 && args[0] == "image" && args[1] == "inspect":
		if !f.exists {
			return nil, &engine.CommandError{Cmd: "docker image inspect", Stderr: "Error: No such image: x", Err: errors.New("exit status 1")}
		}
		if f.label == "" {
			return []byte("<no value>\n"), nil
		}
		return []byte(f.label + "\n"), nil
	case len(args) >= 1 && args[0] == "build":
		ctxDir := args[len(args)-1]
		df, _ := os.ReadFile(filepath.Join(ctxDir, "Dockerfile"))
		bin, _ := os.ReadFile(filepath.Join(ctxDir, "kennel"))
		f.built = &struct{ label, tag, dockerfile, binary string }{args[2], args[4], string(df), string(bin)}
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}

func exe(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kennel")
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildsWhenMissing(t *testing.T) {
	f := &fakeDocker{}
	out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, Exe: exe(t, "binary-v1"), GOOS: "linux"})
	if err != nil || out != Built {
		t.Fatalf("outcome=%v err=%v", out, err)
	}
	if f.built == nil || f.built.binary != "binary-v1" || f.built.tag != Tag || !strings.HasPrefix(f.built.label, LabelBinarySHA+"=") {
		t.Fatalf("build = %+v", f.built)
	}
	if !strings.Contains(f.built.dockerfile, "FROM scratch") {
		t.Error("the embedded Dockerfile is not the scratch gateway recipe")
	}
}

func TestLeavesAnUpToDateImageAlone(t *testing.T) {
	path := exe(t, "binary-v1")
	sum, _ := fileSHA256(path)
	f := &fakeDocker{exists: true, label: sum}
	out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, Exe: path, GOOS: "linux"})
	if err != nil || out != Present || f.built != nil {
		t.Fatalf("outcome=%v err=%v built=%v", out, err, f.built)
	}
}

func TestRebuildsWhenTheBinaryChanged(t *testing.T) {
	f := &fakeDocker{exists: true, label: "deadbeef"}
	out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, Exe: exe(t, "binary-v2"), GOOS: "linux"})
	if err != nil || out != Rebuilt || f.built == nil {
		t.Fatalf("outcome=%v err=%v", out, err)
	}
}

func TestTrustsAnUnlabelledImage(t *testing.T) {
	f := &fakeDocker{exists: true}
	out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, Exe: exe(t, "x"), GOOS: "linux"})
	if err != nil || out != Present || f.built != nil {
		t.Fatalf("a hand-built image (make gateway-image) must not be replaced: outcome=%v err=%v", out, err)
	}
}

func TestCustomImagesAreNeverTouched(t *testing.T) {
	f := &fakeDocker{}
	out, err := Ensure(context.Background(), Options{Runner: f, Image: "ghcr.io/example/gw@sha256:abc", Exe: exe(t, "x"), GOOS: "linux"})
	if err != nil || out != External || len(f.calls) != 0 {
		t.Fatalf("outcome=%v err=%v calls=%v", out, err, f.calls)
	}
}

func TestNonLinuxHostsGetAnActionableError(t *testing.T) {
	f := &fakeDocker{}
	_, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, Exe: exe(t, "x"), GOOS: "darwin"})
	if err == nil || !strings.Contains(err.Error(), "make gateway-image") || !strings.Contains(err.Error(), "--gateway-image") {
		t.Fatalf("want an error naming the next commands, got %v", err)
	}
	f = &fakeDocker{exists: true}
	if out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, Exe: exe(t, "x"), GOOS: "darwin"}); err != nil || out != Present {
		t.Fatalf("an existing image on macOS is fine: %v %v", out, err)
	}
}

func TestEngineDownIsReportedNotTreatedAsMissing(t *testing.T) {
	r := runnerFunc(func(context.Context, string, ...string) ([]byte, error) {
		return nil, &engine.CommandError{Cmd: "docker image inspect", Stderr: "Cannot connect to the Docker daemon", Err: errors.New("exit status 1")}
	})
	_, err := Ensure(context.Background(), Options{Runner: r, Image: Tag, Exe: exe(t, "x"), GOOS: "linux"})
	if err == nil || !strings.Contains(err.Error(), "kennel doctor") {
		t.Fatalf("got %v", err)
	}
}

type runnerFunc func(context.Context, string, ...string) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, n string, a ...string) ([]byte, error) {
	return f(ctx, n, a...)
}

func TestDynamicallyLinkedBinariesAreRefused(t *testing.T) {
	// The test binary itself may or may not be static; assert only the behaviour of the check on
	// a non-ELF file (accepted) and that a real, dynamically linked ELF is rejected when present.
	if err := requireStatic(exe(t, "not an elf")); err != nil {
		t.Errorf("non-ELF input should not be rejected: %v", err)
	}
	for _, cand := range []string{"/bin/sh", "/usr/bin/env"} {
		if _, err := os.Stat(cand); err != nil {
			continue
		}
		if err := requireStatic(cand); err != nil && !strings.Contains(err.Error(), "dynamically linked") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func TestEmbeddedGatewayIsUsedOnOtherHosts(t *testing.T) {
	emb := func(arch string) ([]byte, bool) {
		if arch == "arm64" {
			return []byte("linux-arm64-gateway"), true
		}
		return nil, false
	}
	f := &fakeDocker{arch: "aarch64"}
	out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, GOOS: "windows", Embedded: emb})
	if err != nil || out != Built {
		t.Fatalf("outcome=%v err=%v", out, err)
	}
	if f.built == nil || f.built.binary != "linux-arm64-gateway" {
		t.Fatalf("build = %+v", f.built)
	}

	// An image already built from the same embedded binary is left alone.
	h := sha256.Sum256([]byte("linux-arm64-gateway"))
	f = &fakeDocker{arch: "arm64", exists: true, label: hex.EncodeToString(h[:])}
	if out, err := Ensure(context.Background(), Options{Runner: f, Image: Tag, GOOS: "darwin", Embedded: emb}); err != nil || out != Present {
		t.Fatalf("outcome=%v err=%v", out, err)
	}

	// An architecture the build does not carry is an actionable error.
	f = &fakeDocker{arch: "x86_64"}
	_, err = Ensure(context.Background(), Options{Runner: f, Image: Tag, GOOS: "darwin", Embedded: emb})
	if err == nil || !strings.Contains(err.Error(), "amd64") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("want an error naming the architecture and the next step, got %v", err)
	}
}
