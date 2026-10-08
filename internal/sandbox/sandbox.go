// Package sandbox implements the lifecycle commands (up, run, shell, down, status, allow, deny)
// on top of prepare, the gateway image builder and docker compose. It prints nothing itself: it
// returns results and writes progress to Env.Log, so the CLI decides how to present them.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/middle-systems/cellwall/internal/compose"
	"github.com/middle-systems/cellwall/internal/engine"
	"github.com/middle-systems/cellwall/internal/gatewayimage"
	"github.com/middle-systems/cellwall/internal/prepare"
	"github.com/middle-systems/cellwall/internal/volume"
)

// Env carries the host dependencies, all replaceable in tests.
type Env struct {
	Runner    engine.Runner
	Streams   compose.Streams // attached to run/shell/up
	Log       io.Writer       // progress and build output
	GlobalDir string          // user-global config directory
	TTY       bool            // allocate a pseudo-terminal for run/shell
	// Exe and GOOS describe the running binary for the gateway image build; zero values mean the
	// real executable and runtime.GOOS.
	Exe  string
	GOOS string
}

func (e Env) logw() io.Writer {
	if e.Log == nil {
		return io.Discard
	}
	return e.Log
}

// UpOptions configures Up.
type UpOptions struct {
	Rebuild      bool          // rebuild the agent image
	GatewayImage string        // gateway image reference; "" keeps the current choice
	Timeout      time.Duration // how long to wait for health; default 2 minutes
}

// UpResult describes a started sandbox.
type UpResult struct {
	Prepare      *prepare.Result
	GatewayImage gatewayimage.Outcome
	Project      *compose.Project
	// Seeded is set in volume mode: what was copied into the workspace volume (or Already).
	Seeded *volume.SeedResult
}

// delayedWriter swallows output until it has been going for a while, then shows everything and
// streams the rest: a no-op image build stays silent, a real one shows live progress.
type delayedWriter struct {
	mu    sync.Mutex
	w     io.Writer
	after time.Duration
	start time.Time
	buf   bytes.Buffer
	live  bool
}

func newDelayedWriter(w io.Writer, after time.Duration) *delayedWriter {
	return &delayedWriter{w: w, after: after, start: time.Now()}
}

func (d *delayedWriter) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.live {
		return d.w.Write(p)
	}
	d.buf.Write(p)
	if time.Since(d.start) >= d.after {
		d.live = true
		_, _ = d.w.Write(d.buf.Bytes())
		d.buf.Reset()
	}
	return len(p), nil
}

// Flush shows whatever has been held back (used when the command failed).
func (d *delayedWriter) Flush() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.live {
		d.live = true
		_, _ = d.w.Write(d.buf.Bytes())
		d.buf.Reset()
	}
}

// Brief reduces a failed host command to the part a person needs: what the command printed on
// stderr, not the (very long) command line.
func Brief(err error) string {
	var ce *engine.CommandError
	if errors.As(err, &ce) {
		if s := strings.TrimSpace(ce.Stderr); s != "" {
			return s
		}
		if ce.Err != nil {
			return ce.Err.Error() // "exit status 1": the command line is noise to a person
		}
	}
	return err.Error()
}

// CheckEngine verifies that a container engine answers, with an actionable error if not.
func CheckEngine(ctx context.Context, r engine.Runner) error {
	if _, err := r.Run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		if errors.Is(err, engine.ErrNotFound) {
			return errors.New("docker was not found on PATH\n  next: install Docker (or a compatible engine), then run `cellwall doctor`")
		}
		return fmt.Errorf("the container engine is not reachable: %s\n  next: start Docker, then run `cellwall doctor`", Brief(err))
	}
	return nil
}

// EngineCPUs reports how many CPUs the engine has, or 0 if it cannot be determined.
func EngineCPUs(ctx context.Context, r engine.Runner) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := r.Run(ctx, "docker", "info", "--format", "{{.NCPU}}")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}

// Up prepares the project, makes sure the gateway image exists, and starts the gateway and then
// the agent, waiting until the gateway reports healthy.
func Up(ctx context.Context, e Env, root string, o UpOptions) (*UpResult, error) {
	if _, err := compose.Open(root, e.GlobalDir); err != nil {
		return nil, err
	}
	if err := CheckEngine(ctx, e.Runner); err != nil {
		return nil, err
	}
	res, err := prepare.Run(prepare.Options{
		Root: root, GlobalConfigDir: e.GlobalDir, GatewayImage: o.GatewayImage,
		EngineCPUs: EngineCPUs(ctx, e.Runner),
	})
	if err != nil {
		return nil, fmt.Errorf("%w\n  next: fix the problem above, then re-run", err)
	}
	// A preview port something else already holds would make `compose up` fail obscurely. Only
	// check while the gateway is down: when it is up, it holds those ports itself.
	if p0, err := compose.Open(root, e.GlobalDir); err == nil {
		if up, _ := Running(ctx, e, p0, compose.GatewayService); !up {
			if err := CheckHostPorts(res.Config.Ports); err != nil {
				return nil, err
			}
		}
	}
	outcome, err := gatewayimage.Ensure(ctx, gatewayimage.Options{
		Runner: e.Runner, Image: res.GatewayImage, Exe: e.Exe, GOOS: e.GOOS, Log: e.logw(),
	})
	if err != nil {
		return nil, err
	}
	switch outcome {
	case gatewayimage.Built:
		_, _ = fmt.Fprintf(e.logw(), "built the gateway image %s from this binary\n", res.GatewayImage)
	case gatewayimage.Rebuilt:
		_, _ = fmt.Fprintf(e.logw(), "rebuilt the gateway image %s (cellwall was updated)\n", res.GatewayImage)
	}

	p, err := compose.Open(root, e.GlobalDir) // re-open: prepare just wrote the override and env file
	if err != nil {
		return nil, err
	}
	// `compose up` builds an image only when none exists, so an agent image built for a different
	// stack, cache set or UID would be reused silently after `init` regenerated the Dockerfile.
	// Always run the build: BuildKit's cache makes an unchanged one a no-op, and its output is
	// shown only if it turns out to do real work.
	buildArgs := []string{"build"}
	if o.Rebuild {
		buildArgs = append(buildArgs, "--no-cache")
	}
	dw := newDelayedWriter(e.logw(), 2*time.Second)
	code, err := p.Run(ctx, compose.Streams{Out: dw, Err: dw}, buildArgs...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		dw.Flush()
		return nil, fmt.Errorf("building the agent image failed (docker compose exited %d)\n  next: read the build output above; image builds use the host network, so check it can reach the package mirrors, then re-run `cellwall up`", code)
	}

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	args := []string{"up", "-d", "--wait", "--wait-timeout", strconv.Itoa(int(timeout.Seconds()))}
	code, err = p.Run(ctx, compose.Streams{Out: e.logw(), Err: e.logw()}, args...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("the sandbox did not start (docker compose exited %d)%s\n  next: fix the cause above and re-run `cellwall up`; `cellwall doctor` checks the host", code, e.gatewayLogTail(ctx, p))
	}
	out := &UpResult{Prepare: res, GatewayImage: outcome, Project: p}
	if p.Cfg.Workspace.Mode == "volume" {
		seeded, err := SeedVolume(ctx, e, root)
		if err != nil {
			return nil, fmt.Errorf("the sandbox is up but its workspace could not be seeded: %w", err)
		}
		out.Seeded = seeded
	}
	return out, nil
}

// gatewayLogTail returns the end of the gateway's log for an error message ("" if unavailable).
func (e Env) gatewayLogTail(ctx context.Context, p *compose.Project) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := p.Output(ctx, e.Runner, "logs", "--no-color", "--tail", "20", compose.GatewayService)
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return ""
	}
	return "\n  gateway log:\n    " + strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", "\n    ")
}

// Running reports whether the service has a running container.
func Running(ctx context.Context, e Env, p *compose.Project, service string) (bool, error) {
	out, err := p.Output(ctx, e.Runner, "ps", "--status", "running", "-q", service)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// Exec runs argv in the agent container through its entrypoint (so declared secrets are exported)
// and returns the command's exit status. The sandbox must already be running.
func Exec(ctx context.Context, e Env, root string, argv []string) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("internal error: nothing to run")
	}
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return 0, err
	}
	up, err := Running(ctx, e, p, compose.AgentService)
	if err != nil {
		return 0, fmt.Errorf("could not query the sandbox: %s\n  next: run `cellwall doctor`", Brief(err))
	}
	if !up {
		return 0, errors.New("the agent container is not running\n  next: run `cellwall up` (or `cellwall run`, which starts it)")
	}
	return p.Exec(ctx, e.Streams, compose.AgentService, e.TTY, append([]string{compose.EntrypointPath}, argv...)...)
}

// DownOptions configures Down.
type DownOptions struct{ Volumes bool }

// Down stops and removes the containers (and, with Volumes, the named volumes: the agent's home
// and the dependency caches).
func Down(ctx context.Context, e Env, root string, o DownOptions) error {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return err
	}
	args := []string{"down", "--remove-orphans", "--timeout", "10"}
	if o.Volumes {
		args = append(args, "--volumes")
	}
	code, err := p.Run(ctx, compose.Streams{Out: e.logw(), Err: e.logw()}, args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("docker compose down exited %d\n  next: run `cellwall doctor`, then retry `cellwall down`", code)
	}
	return nil
}

// gatewayStatus is the part of the gateway's /status document the host uses.
type gatewayStatus struct {
	Policy struct {
		PolicyHash string `json:"policy_hash"`
		Rules      int    `json:"rules"`
		Reloads    int    `json:"reloads"`
		Failures   int    `json:"reload_failures"`
		LastError  string `json:"last_reload_error"`
	} `json:"policy"`
	ActiveConnections int `json:"active_connections"`
}

func fetchGatewayStatus(ctx context.Context, e Env, p *compose.Project) (*gatewayStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := p.Output(ctx, e.Runner, "exec", "-T", compose.GatewayService, "/cellwall", "gateway", "status")
	if err != nil {
		return nil, err
	}
	var st gatewayStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("unreadable gateway status: %w", err)
	}
	return &st, nil
}
