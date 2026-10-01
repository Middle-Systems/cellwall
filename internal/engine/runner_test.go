package engine

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestExecRunnerNotFound(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), "cellwall-definitely-not-a-real-binary")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestExecRunnerSuccessAndFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX utilities")
	}
	out, err := ExecRunner{}.Run(context.Background(), "echo", "hi")
	if err != nil || strings.TrimSpace(string(out)) != "hi" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	_, err = ExecRunner{}.Run(context.Background(), "sh", "-c", "echo boom >&2; exit 3")
	var ce *CommandError
	if !errors.As(err, &ce) || !strings.Contains(ce.Stderr, "boom") {
		t.Fatalf("err = %v, want CommandError carrying stderr", err)
	}
}

// Arguments are an argv vector, never re-parsed by a shell.
func TestExecRunnerDoesNotInvokeShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX utilities")
	}
	out, err := ExecRunner{}.Run(context.Background(), "echo", "$(id); `id`; a && b")
	if err != nil || strings.TrimSpace(string(out)) != "$(id); `id`; a && b" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestExecRunnerHonoursContext(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX utilities")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (ExecRunner{}).Run(ctx, "sleep", "5"); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
