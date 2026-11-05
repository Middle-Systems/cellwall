// Package verify is the escape suite: named, independently reported checks that try to break out
// of a running sandbox and report whether each attempt failed. It is shared by `kennel verify`
// and by CI, so a claim in the README is exactly as strong as the check behind it.
//
// A check can end in three ways. PASS means the sandbox held. FAIL means it did not (or the check
// itself could not be carried out, which is never reported as a pass). SKIP means the check needs
// something the environment lacks (outbound network, a preview port); a skip is reported loudly and
// `--strict` turns it into a failure, which is what CI uses.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/middle-systems/kennel/internal/audit"
	"github.com/middle-systems/kennel/internal/policy"
)

// Status is the outcome of one check.
type Status string

// Outcomes.
const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Result is one check's report.
type Result struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Millis int64  `json:"millis"`
}

// Out is the outcome of a command run in the agent container.
type Out struct {
	Stdout, Stderr string
	Code           int
}

// Held is a long-running command in the agent container that the check talks to line by line.
type Held interface {
	Send(line string) error
	// ReadLine returns the next stdout line, or an error on timeout or EOF.
	ReadLine(timeout time.Duration) (string, error)
	Close() error
}

// Env is everything the suite needs from the sandbox. The real implementation lives in
// internal/sandbox; tests use fakes, which is how the suite itself is tested to fail.
type Env struct {
	// Exec runs argv in the agent container as the unprivileged agent user.
	Exec func(ctx context.Context, argv ...string) (Out, error)
	// Hold starts argv in the agent container and keeps it open for line-oriented conversation.
	Hold func(ctx context.Context, argv ...string) (Held, error)
	// Audit returns every audit record written so far, oldest first.
	Audit func() ([]audit.Record, error)
	// Policy is the compiled policy on disk (what the gateway should be enforcing).
	Policy *policy.Compiled
	// Protected lists protected paths that exist and are mounted read-only, relative to /workspace.
	Protected []string
	// Ports are the configured preview ports.
	Ports []int
	// Listeners reports what the agent is listening on, per port (see sandbox.ClassifyListeners).
	Listeners func(ctx context.Context) (map[int]string, error)
	// HostGet fetches http://127.0.0.1:<port>/ from the HOST and returns the response status line.
	HostGet func(ctx context.Context, port int) (string, error)
	// AllowTemp adds a session allow rule, waits for the running gateway to enforce it, and
	// returns how long that took plus a function that removes the rule again.
	AllowTemp func(ctx context.Context, hosts []string) (undo func(), took time.Duration, err error)
	// VolumeMode is true when the workspace is a named volume rather than a bind mount. The
	// protected-paths check then proves the isolation volume mode relies on instead.
	VolumeMode bool
	// HostMarker creates an empty file with the given name in the host repository's root and
	// returns a function that removes it; HostHas reports whether such a file exists there.
	HostMarker func(name string) (cleanup func(), err error)
	HostHas    func(name string) bool
	// Mutate permits checks that briefly add (and remove) a session rule.
	Mutate bool
	// Token returns a short random token for unique names.
	Token func() string
	// Now is the host clock.
	Now func() time.Time
	// AuditWait bounds how long a check waits for an expected audit record (default 5s). The
	// gateway writes before it answers, so this only absorbs file-sharing latency.
	AuditWait time.Duration
}

// Check is one named test.
type Check struct {
	ID      int
	Name    string
	Title   string
	Mutates bool
	Run     func(ctx context.Context, e *Env) (Status, string)
}

// Run executes the selected checks (all of them when only is empty) in order. A panic or an
// error inside a check is a FAIL for that check, never a pass and never the end of the run.
func Run(ctx context.Context, e *Env, only []string) []Result {
	want := map[string]bool{}
	for _, o := range only {
		want[strings.ToLower(strings.TrimSpace(o))] = true
	}
	var out []Result
	for _, c := range Checks() {
		if len(want) > 0 && !want[c.Name] && !want[fmt.Sprint(c.ID)] {
			continue
		}
		out = append(out, runOne(ctx, e, c))
	}
	return out
}

func runOne(ctx context.Context, e *Env, c Check) (r Result) {
	r = Result{ID: c.ID, Name: c.Name, Title: c.Title}
	start := time.Now()
	defer func() {
		if p := recover(); p != nil {
			r.Status, r.Detail = Fail, fmt.Sprintf("the check itself crashed: %v", p)
		}
		r.Millis = time.Since(start).Milliseconds()
	}()
	if c.Mutates && !e.Mutate {
		r.Status, r.Detail = Skip, "skipped: this check briefly adds a session rule and --read-only was given"
		return r
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r.Status, r.Detail = c.Run(cctx, e)
	return r
}

// Failed reports whether the run should exit non-zero.
func Failed(rs []Result, strict bool) bool {
	for _, r := range rs {
		if r.Status == Fail || (strict && r.Status == Skip) {
			return true
		}
	}
	return false
}

// pyJSON runs a Python program in the agent and decodes the JSON it prints on its last line.
func pyJSON(ctx context.Context, e *Env, v any, script string, args ...string) error {
	argv := append([]string{"python3", "-c", script}, args...)
	o, err := e.Exec(ctx, argv...)
	if err != nil {
		return fmt.Errorf("could not run the probe in the agent container: %w", err)
	}
	if o.Code == 127 || strings.Contains(o.Stderr, "python3: not found") || strings.Contains(o.Stderr, "executable file not found") {
		return fmt.Errorf("python3 is not installed in the agent image, so this check cannot run (install it with agent.apt_packages)")
	}
	lines := strings.Split(strings.TrimSpace(o.Stdout), "\n")
	last := lines[len(lines)-1]
	if err := json.Unmarshal([]byte(last), v); err != nil {
		return fmt.Errorf("unreadable probe output (exit %d): %q %s", o.Code, truncate(o.Stdout, 300), truncate(o.Stderr, 300))
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// waitAudit polls the audit log until match finds a record or the wait expires.
func waitAudit(e *Env, match func(audit.Record) bool) (audit.Record, bool) {
	wait := e.AuditWait
	if wait <= 0 {
		wait = 5 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if recs, err := e.Audit(); err == nil {
			for i := len(recs) - 1; i >= 0; i-- {
				if match(recs[i]) {
					return recs[i], true
				}
			}
		}
		if time.Now().After(deadline) {
			return audit.Record{}, false
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// allowedHost picks an exact, plain-allow, HTTPS-only host from the policy on disk, for checks that
// need a destination the gateway will let through. "" when there is none.
func allowedHost(p *policy.Compiled) string {
	if p == nil {
		return ""
	}
	for _, r := range p.Policy.Rules {
		if r.IsDeny() || strings.Contains(r.Host, "*") {
			continue
		}
		if r.UnsafeAllowHTTP || r.UnsafeAllowPrivate || r.UnsafeAllowECH || r.UnsafeSkipTLSCheck {
			continue
		}
		if len(r.Ports) > 0 {
			ok := false
			for _, port := range r.Ports {
				ok = ok || port == 443
			}
			if !ok {
				continue
			}
		}
		if d := p.Match(r.Host, 443, policy.ProtoTunnel); d.Allowed {
			return r.Host
		}
	}
	return ""
}
