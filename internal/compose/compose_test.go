//go:build !windows

package compose

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeDocker installs a `docker` on PATH that runs the given shell body. $@ is the argv.
func fakeDocker(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil { //nolint:gosec // test double
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestExitCodesPropagate(t *testing.T) {
	for _, want := range []int{0, 1, 2, 42, 126, 127} {
		fakeDocker(t, "exit "+strconv.Itoa(want))
		got, err := runDocker(context.Background(), Streams{Out: new(bytes.Buffer), Err: new(bytes.Buffer)}, []string{"x"})
		if err != nil || got != want {
			t.Errorf("exit %d: got %d, %v", want, got, err)
		}
	}
}

func TestStreamsAndArgvAreForwarded(t *testing.T) {
	fakeDocker(t, `printf 'args:'; for a in "$@"; do printf ' [%s]' "$a"; done; echo; cat; echo oops >&2; exit 3`)
	var out, errb bytes.Buffer
	code, err := runDocker(context.Background(), Streams{In: strings.NewReader("hello\n"), Out: &out, Err: &errb}, []string{"compose", "exec", "-T", "agent", "a b", "$(touch pwned)"})
	if err != nil || code != 3 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(out.String(), "[a b] [$(touch pwned)]") {
		t.Errorf("arguments must reach docker verbatim, got %q", out.String())
	}
	if !strings.Contains(out.String(), "hello") || !strings.Contains(errb.String(), "oops") {
		t.Errorf("stdin/stdout/stderr not wired: out=%q err=%q", out.String(), errb.String())
	}
}

func TestSignalsAreForwardedAndReportedAs128PlusN(t *testing.T) {
	fakeDocker(t, `trap 'echo got-term; exit 9' TERM; echo ready; while :; do sleep 0.05; done`)
	pr, pw, _ := os.Pipe()
	defer func() { _ = pr.Close() }()
	type res struct {
		code int
		err  error
	}
	done := make(chan res, 1)
	go func() {
		c, err := runDocker(context.Background(), Streams{Out: pw, Err: pw}, []string{"x"})
		done <- res{c, err}
	}()
	buf := make([]byte, 64)
	_, _ = pr.Read(buf) // wait for "ready"
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		_ = pw.Close()
		if r.err != nil || r.code != 9 {
			t.Fatalf("code=%d err=%v (the child's own exit status after handling SIGTERM)", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM was not forwarded to the child")
	}
}

func TestKilledChildIsReportedAs128PlusSignal(t *testing.T) {
	fakeDocker(t, `kill -9 $$`)
	code, err := runDocker(context.Background(), Streams{Out: new(bytes.Buffer), Err: new(bytes.Buffer)}, []string{"x"})
	if err != nil || code != 137 {
		t.Fatalf("code=%d err=%v, want 137", code, err)
	}
}

func TestMissingDockerIsActionable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := runDocker(context.Background(), Streams{}, []string{"x"})
	if err == nil || !strings.Contains(err.Error(), "cellwall doctor") {
		t.Fatalf("got %v", err)
	}
}

func TestIsTerminalIsFalseForPipesAndNull(t *testing.T) {
	r, w, _ := os.Pipe()
	defer func() { _ = r.Close(); _ = w.Close() }()
	if IsTerminal(r) || IsTerminal(w) {
		t.Error("a pipe is not a terminal")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	if IsTerminal(null) {
		t.Error("/dev/null is not a terminal")
	}
}
