// Package engine abstracts how kennel talks to the container engine.
//
// v1 shells out to the docker CLI for maximum compatibility (Docker Desktop, Colima,
// OrbStack, Rancher Desktop, Podman's docker-compatible socket). Everything that runs a
// host command goes through Runner so it can be faked in tests.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes a host command and returns its stdout.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner is the real Runner. It never invokes a shell: arguments are passed as an argv
// vector, so values derived from config or project files cannot inject shell syntax.
type ExecRunner struct{}

// CommandError carries the failed command's stderr so callers can show the cause.
type CommandError struct {
	Cmd    string
	Stderr string
	Err    error
}

func (e *CommandError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("%s: %v", e.Cmd, e.Err)
	}
	return fmt.Sprintf("%s: %v: %s", e.Cmd, e.Err, msg)
}

func (e *CommandError) Unwrap() error { return e.Err }

// ErrNotFound is returned when the executable is not on PATH.
var ErrNotFound = errors.New("executable not found")

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // argv-only: no shell, and callers pass fixed program names
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return stdout.Bytes(), &CommandError{Cmd: name + " " + strings.Join(args, " "), Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}
