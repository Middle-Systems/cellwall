package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/auditlog"
	"github.com/middle-systems/cellwall/internal/compose"
	"github.com/middle-systems/cellwall/internal/gen"
	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/policyedit"
	"github.com/middle-systems/cellwall/internal/prepare"
	"github.com/middle-systems/cellwall/internal/verify"
)

// VerifyEnv connects the escape suite to a running sandbox. Both containers must be up: verify
// attacks the sandbox that exists, it does not start one.
func VerifyEnv(ctx context.Context, e Env, root string, mutate bool) (*verify.Env, error) {
	p, err := compose.Open(root, e.GlobalDir)
	if err != nil {
		return nil, err
	}
	for _, svc := range []string{compose.GatewayService, compose.AgentService} {
		up, err := Running(ctx, e, p, svc)
		if err != nil {
			return nil, fmt.Errorf("could not query the sandbox: %s\n  next: run `cellwall doctor`", Brief(err))
		}
		if !up {
			return nil, fmt.Errorf("the %s container is not running, so there is nothing to verify\n  next: run `cellwall up`, then `cellwall verify`", svc)
		}
	}

	pol, err := readEffective(root)
	if err != nil {
		return nil, err
	}
	auditDir := filepath.Join(root, filepath.FromSlash(gen.StateDirRel), "audit")

	ve := &verify.Env{
		Policy: pol, Protected: prepare.MountedPaths(root), Ports: append([]int(nil), p.Cfg.Ports...),
		Mutate: mutate, Now: time.Now,
		Token: func() string {
			b := make([]byte, 4)
			_, _ = rand.Read(b)
			return hex.EncodeToString(b)
		},
	}
	ve.Exec = func(ctx context.Context, argv ...string) (verify.Out, error) {
		var o, er bytes.Buffer
		code, err := p.Exec(ctx, compose.Streams{Out: &o, Err: &er}, compose.AgentService, false, argv...)
		if err != nil {
			return verify.Out{}, err
		}
		return verify.Out{Stdout: o.String(), Stderr: er.String(), Code: code}, nil
	}
	ve.Hold = func(ctx context.Context, argv ...string) (verify.Held, error) {
		return startHeld(ctx, p, argv)
	}
	ve.Audit = func() ([]audit.Record, error) {
		recs, _, err := auditlog.Read(auditDir, auditlog.Filter{})
		return recs, err
	}
	ve.Listeners = func(ctx context.Context) (map[int]string, error) {
		out, err := p.Output(ctx, e.Runner, "exec", "-T", compose.AgentService, "sh", "-c", "cat /proc/net/tcp; cat /proc/net/tcp6 2>/dev/null; true")
		if err != nil {
			return nil, errors.New(Brief(err))
		}
		return ClassifyListeners(string(out)), nil
	}
	ve.HostGet = hostGet
	ve.AllowTemp = func(ctx context.Context, hosts []string) (func(), time.Duration, error) {
		return allowTemp(ctx, e, root, auditDir, hosts)
	}
	return ve, nil
}

func readEffective(root string) (*policy.Compiled, error) {
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(gen.StateDirRel), "policy", "policy.json")) //nolint:gosec // fixed location in the project's state dir
	if err != nil {
		return nil, fmt.Errorf("no prepared policy found: %w\n  next: run `cellwall up`", err)
	}
	parsed, err := policy.Parse("policy.json", b)
	if err != nil {
		return nil, err
	}
	return policy.Compile(parsed, true)
}

// allowTemp adds a session allow, waits until the gateway enforces it and measures how long that
// took from the gateway's own record of the reload (the host and the container share a clock on
// Linux; when they visibly do not, the wall-clock wait is used instead).
func allowTemp(ctx context.Context, e Env, root, auditDir string, hosts []string) (func(), time.Duration, error) {
	wrote := time.Now()
	res, err := Edit(ctx, e, root, EditOptions{
		Edit: policyedit.Edit{Action: policy.ActionAllow, Hosts: hosts, Note: "cellwall verify (temporary)"},
		Wait: 10 * time.Second,
	})
	undo := func() {
		if ch, rerr := policyedit.RemoveSession(root, hosts); rerr == nil && ch.Changed {
			_, _ = prepare.Run(prepare.Options{Root: root, GlobalConfigDir: e.GlobalDir})
		}
	}
	if err != nil {
		return nil, 0, err
	}
	if !res.Applied {
		undo()
		msg := res.GatewayError
		if msg == "" {
			msg = "the gateway did not report the new policy"
		}
		return nil, 0, errors.New(msg)
	}
	took := res.Waited
	if st, serr := os.Stat(filepath.Join(root, filepath.FromSlash(gen.StateDirRel), "policy", "policy.json")); serr == nil {
		short := res.PolicyHash
		if len(short) > 12 {
			short = short[:12]
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			recs, _, _ := auditlog.Read(auditDir, auditlog.Filter{Since: wrote.Add(-time.Minute)})
			for i := len(recs) - 1; i >= 0; i-- {
				r := recs[i]
				if r.Event == audit.EventPolicy && r.Action == "reload" && r.Policy == short {
					if d := r.TS.Sub(st.ModTime()); d >= 0 && d < 30*time.Second {
						took = d
					}
					return undo, took, nil
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return undo, took, nil
}

func hostGet(ctx context.Context, port int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(port))+"/", nil)
	if err != nil {
		return "", err
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Proto + " " + resp.Status, nil
}

// heldProc is a long-running command in the agent container with line-oriented stdin and stdout.
type heldProc struct {
	stdin  *io.PipeWriter
	lines  chan string
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func startHeld(ctx context.Context, p *compose.Project, argv []string) (verify.Held, error) {
	cctx, cancel := context.WithCancel(ctx)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	h := &heldProc{stdin: inW, lines: make(chan string, 16), cancel: cancel, done: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(outR)
		for sc.Scan() {
			h.lines <- sc.Text()
		}
		close(h.lines)
	}()
	go func() {
		defer close(h.done)
		_, _ = p.Exec(cctx, compose.Streams{In: inR, Out: outW, Err: io.Discard}, compose.AgentService, false, argv...)
		_ = outW.Close()
	}()
	return h, nil
}

func (h *heldProc) Send(line string) error {
	_, err := io.WriteString(h.stdin, line+"\n")
	return err
}

func (h *heldProc) ReadLine(timeout time.Duration) (string, error) {
	select {
	case l, ok := <-h.lines:
		if !ok {
			return "", errors.New("the command ended without answering")
		}
		return l, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("no answer within %s", timeout)
	}
}

func (h *heldProc) Close() error {
	h.once.Do(func() {
		_ = h.stdin.Close()
		h.cancel()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
		}
	})
	return nil
}
