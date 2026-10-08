// Package compose runs `docker compose` for a cellwall project.
//
// Every invocation is an argv vector (never a shell string). The same file list is used for every
// command so `up`, `exec`, `down` and `ps` always agree about the project.
package compose

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/middle-systems/cellwall/internal/config"
	"github.com/middle-systems/cellwall/internal/engine"
	"github.com/middle-systems/cellwall/internal/gen"
)

// Service names in the generated compose file.
const (
	AgentService   = "agent"
	GatewayService = "gateway"
)

// EntrypointPath is the agent image's entrypoint. `docker exec` does not run the image's
// ENTRYPOINT, so interactive commands are started through it to get declared secrets exported.
const EntrypointPath = "/usr/local/bin/cellwall-entrypoint"

// Project is a cellwall project's compose configuration.
type Project struct {
	Root    string
	Cfg     *config.Config
	Name    string   // compose project name
	Dir     string   // absolute directory holding compose.yaml
	Files   []string // absolute compose files, base first
	EnvFile string   // absolute path, "" when `prepare` has not written one
}

// Open loads the project's config and locates its compose files. It does not run prepare.
func Open(root, globalDir string) (*Project, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	loaded, err := config.Load(config.LoadOptions{ProjectDir: abs, GlobalDir: globalDir})
	if err != nil {
		return nil, err
	}
	cfg := loaded.Config
	lay := gen.LayoutFor(cfg)
	dir := filepath.Join(abs, filepath.FromSlash(lay.Dir))
	base := filepath.Join(dir, "compose.yaml")
	if _, err := os.Stat(base); err != nil {
		return nil, fmt.Errorf("%s does not exist\n  next: run `cellwall init` to generate the sandbox files", filepath.ToSlash(filepath.Join(lay.Dir, "compose.yaml")))
	}
	p := &Project{Root: abs, Cfg: cfg, Name: "cw-" + cfg.Project, Dir: dir, Files: []string{base}}
	state := filepath.Join(abs, filepath.FromSlash(gen.StateDirRel))
	if o := filepath.Join(state, "compose.override.yaml"); exists(o) {
		p.Files = append(p.Files, o)
	}
	if e := filepath.Join(state, "compose.env"); exists(e) {
		p.EnvFile = e
	}
	return p, nil
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// Args returns the argument vector for `docker compose <sub...>` with this project's files.
func (p *Project) Args(sub ...string) []string {
	args := []string{"compose"}
	for _, f := range p.Files {
		args = append(args, "-f", f)
	}
	if p.EnvFile != "" {
		args = append(args, "--env-file", p.EnvFile)
	}
	args = append(args, "--project-directory", p.Dir)
	return append(args, sub...)
}

// Output runs a compose subcommand and returns its stdout.
func (p *Project) Output(ctx context.Context, r engine.Runner, sub ...string) ([]byte, error) {
	return r.Run(ctx, "docker", p.Args(sub...)...)
}

// Streams are the standard streams handed to an attached command.
type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Run executes `docker compose <sub...>` attached to the given streams, forwards termination
// signals to it, and returns its exit status. A non-zero status is not an error: the caller
// decides what it means. An error means docker could not be started at all.
func (p *Project) Run(ctx context.Context, st Streams, sub ...string) (int, error) {
	return runDocker(ctx, st, p.Args(sub...))
}

// Exec runs a command in a service container. tty allocates a pseudo-terminal; leave it false when
// stdin or stdout is not a terminal.
func (p *Project) Exec(ctx context.Context, st Streams, service string, tty bool, argv ...string) (int, error) {
	sub := []string{"exec"}
	if !tty {
		sub = append(sub, "-T")
	}
	sub = append(sub, service)
	sub = append(sub, argv...)
	return p.Run(ctx, st, sub...)
}

func runDocker(ctx context.Context, st Streams, args []string) (int, error) {
	// Not CommandContext: cancellation must forward a signal and let docker finish its own
	// cleanup, not kill it outright.
	cmd := exec.Command("docker", args...) //nolint:gosec,noctx // fixed binary, argv-only
	cmd.Stdin, cmd.Stdout, cmd.Stderr = st.In, st.Out, st.Err

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return 0, fmt.Errorf("docker was not found on PATH\n  next: install Docker (or a compatible engine) and run `cellwall doctor`")
		}
		return 0, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case sig := <-sigs:
			// Terminals deliver Ctrl-C to the whole foreground group already; sending it again to
			// the child is harmless, and for signals from `kill` it is the only delivery.
			_ = cmd.Process.Signal(sig)
		case <-ctx.Done():
			_ = cmd.Process.Signal(os.Interrupt)
			ctx = context.Background() // signal once
		case err := <-done:
			return exitCode(err)
		}
	}
}

// exitCode maps a finished command to a shell-style status: the command's own code, or 128+N when
// it was killed by signal N.
func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 0, err
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	if c := ee.ExitCode(); c >= 0 {
		return c, nil
	}
	return 1, nil
}

// IsTerminal reports whether f is an interactive terminal. It uses only the standard library, so
// it treats any character device other than the null device as a terminal.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(fi, null) {
		return false
	}
	return true
}
