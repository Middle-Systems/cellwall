// Package volume implements workspace.mode=volume: the repository lives in a named volume inside
// the agent's container, is seeded from the host repository, and the agent's commits come back
// through `kennel fetch`.
//
// Nothing here trusts the agent's repository. Its commits are transferred as a git bundle, the
// bundle is verified against the host history, objects are checked with fsck while fetching, and
// they land only in refs/kennel/* — never in a branch the host has checked out. Bringing them
// into the working tree is a separate, explicit step that stops at changes to files the host may
// later execute (docs/decisions/0009).
package volume

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Repo is the host repository.
type Repo struct {
	Dir string
	// Git is the git executable; "" means "git" from PATH.
	Git string
}

// hostGit runs git against the host repository. The environment is pinned so output is parseable
// and git never prompts.
func (r Repo) hostGit(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) (stderr string, err error) {
	bin := r.Git
	if bin == "" {
		bin = "git"
	}
	cmd := exec.CommandContext(ctx, bin, append([]string{"-C", r.Dir}, args...)...) //nolint:gosec // argv only; fixed program
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "GIT_OPTIONAL_LOCKS=0")
	cmd.Stdin = stdin
	var eb bytes.Buffer
	cmd.Stderr = &eb
	var ob bytes.Buffer
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &ob
	}
	err = cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return eb.String(), fmt.Errorf("git %s: exit %d: %s", firstArg(args), ee.ExitCode(), strings.TrimSpace(eb.String()))
		}
		if errors.Is(err, exec.ErrNotFound) {
			return "", errors.New("git was not found on PATH\n  next: install git; volume mode moves your repository through git")
		}
		return eb.String(), err
	}
	if stdout == nil {
		return ob.String(), nil
	}
	return eb.String(), nil
}

// out runs hostGit and returns trimmed stdout.
func (r Repo) out(ctx context.Context, args ...string) (string, error) {
	o, err := r.hostGit(ctx, nil, nil, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(o), nil
}

func firstArg(a []string) string {
	for _, x := range a {
		if !strings.HasPrefix(x, "-") {
			return x
		}
	}
	return ""
}

// Agent runs commands inside the agent container.
type Agent interface {
	// Run executes argv. stdin and stdout may be nil. It returns the command's stderr and exit
	// status; err is set only if the command could not be run at all.
	Run(ctx context.Context, stdin io.Reader, stdout io.Writer, argv ...string) (stderr string, exit int, err error)
}

// agentOut runs argv in the agent and returns stdout, failing on a non-zero exit.
func agentOut(ctx context.Context, ag Agent, argv ...string) (string, error) {
	var ob bytes.Buffer
	se, code, err := ag.Run(ctx, nil, &ob, argv...)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("in the agent: %s: exit %d: %s", strings.Join(argv[:min(len(argv), 3)], " "), code, strings.TrimSpace(se))
	}
	return ob.String(), nil
}
