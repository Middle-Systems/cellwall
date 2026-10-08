package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/policy"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

// replace writes the policy the way the host CLI and editors do: temp file then atomic rename,
// which swaps the inode (see spike S9).
func replace(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func policyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const (
	polA = "version: 1\nrules:\n  - host: a.example.com\n"
	polB = "version: 1\nrules:\n  - host: b.example.com\n"
)

func allowed(s *State, host string) bool {
	return s.Current().Match(host, 443, policy.ProtoTunnel).Allowed
}

func TestNewStateRefusesBadPolicies(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewState(filepath.Join(dir, "missing.json"), quiet()); err == nil {
		t.Error("missing file must be an error: never start without a policy")
	}
	for name, content := range map[string]string{
		"empty":         "",
		"garbage":       "{{{",
		"allow default": "version: 1\ndefault: allow\n",
		"unknown key":   "version: 1\nrulez: []\n",
		"tld wildcard":  "version: 1\nrules:\n  - host: '*.com'\n",
	} {
		p := filepath.Join(dir, name+".json")
		_ = os.WriteFile(p, []byte(content), 0o644)
		if _, err := NewState(p, quiet()); err == nil {
			t.Errorf("%s: must be refused at startup", name)
		}
	}
}

func TestPollDetectsAtomicReplaceAndInPlaceWrites(t *testing.T) {
	path := policyFile(t, polA)
	s, err := NewState(path, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if !allowed(s, "a.example.com") || allowed(s, "b.example.com") {
		t.Fatal("initial policy wrong")
	}
	if r := s.Poll(); r.Changed || r.Failed {
		t.Fatalf("unchanged file must be a no-op: %+v", r)
	}
	old := s.Current().Hash

	replace(t, path, polB) // atomic rename: new inode
	r := s.Poll()
	if !r.Changed || r.Old.Hash != old || r.New.Hash == old {
		t.Fatalf("atomic replace not detected: %+v", r)
	}
	if allowed(s, "a.example.com") || !allowed(s, "b.example.com") {
		t.Error("new policy not in effect")
	}

	if err := os.WriteFile(path, []byte(polA), 0o644); err != nil { // in-place: same inode
		t.Fatal(err)
	}
	if r := s.Poll(); !r.Changed {
		t.Fatal("in-place write not detected")
	}
	if st := s.Status(); st.Reloads != 2 || st.Failures != 0 {
		t.Errorf("%+v", st)
	}
}

func TestBadReloadKeepsPreviousPolicy(t *testing.T) {
	path := policyFile(t, polA)
	s, _ := NewState(path, quiet())
	good := s.Current().Hash

	for name, bad := range map[string]string{
		"syntax":             "version: 1\nrules: [",
		"unknown key":        "version: 1\nrulez: []\n",
		"allow by default":   "version: 1\ndefault: allow\n",
		"dangerous wildcard": "version: 1\nrules:\n  - host: '*.github.io'\n",
		"ip rule":            "version: 1\nrules:\n  - host: 10.0.0.1\n",
		"empty (mid-write)":  "",
		"wrong version":      "version: 9\n",
	} {
		replace(t, path, bad)
		r := s.Poll()
		if !r.Failed || r.Err == nil {
			t.Errorf("%s: want a reported failure, got %+v", name, r)
			continue
		}
		if s.Current().Hash != good || !allowed(s, "a.example.com") {
			t.Errorf("%s: previous policy must stay active", name)
		}
		if again := s.Poll(); again.Failed || again.Changed {
			t.Errorf("%s: the same bad content must be reported once, not on every poll", name)
		}
		if st := s.Status(); st.LastError == "" {
			t.Errorf("%s: status must expose the last reload error", name)
		}
	}

	// Recovery: a valid file clears the error.
	replace(t, path, polB)
	if r := s.Poll(); !r.Changed {
		t.Fatalf("recovery not applied: %+v", r)
	}
	if st := s.Status(); st.LastError != "" || st.Failures == 0 {
		t.Errorf("%+v", st)
	}
}

func TestDeletedPolicyFileKeepsPreviousPolicy(t *testing.T) {
	path := policyFile(t, polA)
	s, _ := NewState(path, quiet())
	_ = os.Remove(path)
	if r := s.Poll(); !r.Failed {
		t.Fatalf("%+v", r)
	}
	if !allowed(s, "a.example.com") {
		t.Error("deleting the file must not drop the policy (or open anything)")
	}
}

func TestRelaxationsAreReportedInStatus(t *testing.T) {
	path := policyFile(t, "version: 1\nrules:\n  - {host: a.example.com, unsafe_allow_http: true}\nlimits: {max_conns: -1}\n")
	s, err := NewState(path, quiet())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(s.Status().Relaxations, "\n")
	for _, want := range []string{"unsafe-http", "unlimited-max_conns"} {
		if !strings.Contains(joined, want) {
			t.Errorf("status missing relaxation %s:\n%s", want, joined)
		}
	}
}

func TestValidateAdminAddr(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:3129", "[::1]:3129", "127.0.0.1:0", "127.5.5.5:80"} {
		if err := ValidateAdminAddr(ok); err != nil {
			t.Errorf("%s should be allowed: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:3129", ":3129", "localhost:3129", "10.0.0.1:3129", "[::]:3129", "192.168.1.1:80", "8.8.8.8:80", "garbage", "127.0.0.1", ""} {
		if err := ValidateAdminAddr(bad); err == nil {
			t.Errorf("%q must be refused: the control surface is never exposed to the agent's network", bad)
		}
	}
}

func startGateway(t *testing.T, policyContent string) (proxyAddr, adminAddr, auditDir, policyPath string, stop func() error) {
	t.Helper()
	policyPath = policyFile(t, policyContent)
	auditDir = t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan [2]string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			PolicyPath: policyPath, Listen: "127.0.0.1:0", Admin: "127.0.0.1:0", AuditDir: auditDir,
			ReloadInterval: 30 * time.Millisecond, ShutdownGrace: time.Second, Logger: quiet(),
			OnListening: func(p, a net.Addr) { ready <- [2]string{p.String(), a.String()} },
		})
	}()
	select {
	case addrs := <-ready:
		proxyAddr, adminAddr = addrs[0], addrs[1]
	case err := <-done:
		t.Fatalf("gateway exited early: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not start")
	}
	stopped := false
	stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return fmt.Errorf("gateway did not stop")
		}
	}
	t.Cleanup(func() { _ = stop() })
	return
}

func connectReason(t *testing.T, proxyAddr, target string) (int, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header.Get("X-Cellwall-Reason")
}

// The in-process version of escape-suite check 12: an `allow` takes effect within 2 s.
func TestRunHotReloadAppliesWithinTwoSeconds(t *testing.T) {
	proxyAddr, _, auditDir, policyPath, stop := startGateway(t, polA)
	// "localhost" resolves to loopback, which the guard always refuses, so a policy that allows
	// it is a safe way to observe the switch from default-deny to a later pipeline stage.
	if code, reason := connectReason(t, proxyAddr, "localhost:443"); code != 403 || reason != policy.ReasonDefaultDeny {
		t.Fatalf("before: %d %q", code, reason)
	}
	replace(t, policyPath, "version: 1\nrules:\n  - host: a.example.com\n  - host: localhost\n")
	start := time.Now()
	var reason string
	for time.Since(start) < 2*time.Second {
		if _, reason = connectReason(t, proxyAddr, "localhost:443"); reason != policy.ReasonDefaultDeny {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if reason != "blocked-address" {
		t.Fatalf("policy change not applied within 2s (last reason %q)", reason)
	}
	t.Logf("reload took %v", time.Since(start))

	// A bad edit is rejected and the last good policy keeps enforcing.
	replace(t, policyPath, "version: 1\nrules: [")
	time.Sleep(200 * time.Millisecond)
	if _, reason := connectReason(t, proxyAddr, "localhost:443"); reason != "blocked-address" {
		t.Errorf("bad reload changed enforcement: %q", reason)
	}
	if _, reason := connectReason(t, proxyAddr, "other.example.com:443"); reason != policy.ReasonDefaultDeny {
		t.Errorf("bad reload opened the gate: %q", reason)
	}

	if err := stop(); err != nil {
		t.Fatalf("clean shutdown: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(auditDir, audit.FileName))
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	for _, want := range []string{`"event":"policy"`, `"action":"load"`, `"action":"reload"`, `"action":"reload-failed"`, `"reason":"default-deny"`, `"reason":"blocked-address"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %s", want)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("not JSON Lines: %q", line)
		}
	}
}

func TestAdminEndpoints(t *testing.T) {
	_, adminAddr, _, policyPath, _ := startGateway(t, "version: 1\nrules:\n  - {host: a.example.com, unsafe_allow_http: true}\n")
	resp, err := http.Get("http://" + adminAddr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"status": "ok"`) {
		t.Errorf("healthz: %d %s", resp.StatusCode, b)
	}
	resp, err = http.Get("http://" + adminAddr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Policy      Status `json:"policy"`
		Connections int    `json:"active_connections"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	resp.Body.Close()
	if len(st.Policy.PolicyHash) != 64 || st.Policy.Rules != 1 || len(st.Policy.Relaxations) != 1 {
		t.Errorf("status: %+v", st)
	}
	// Mutating verbs are not routed.
	req, _ := http.NewRequest("POST", "http://"+adminAddr+"/healthz", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Error("admin endpoint must be read-only")
		}
	}
	if err := Healthcheck(context.Background(), adminAddr); err != nil {
		t.Errorf("healthcheck: %v", err)
	}
	_ = policyPath
	if err := Healthcheck(context.Background(), "10.0.0.1:3129"); err == nil {
		t.Error("healthcheck must refuse non-loopback addresses")
	}
	if err := Healthcheck(context.Background(), "127.0.0.1:1"); err == nil {
		t.Error("healthcheck must fail when nothing is listening")
	}
}

func TestRunRefusesNonLoopbackAdminAndBadPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p := policyFile(t, polA)
	if err := Run(ctx, Options{PolicyPath: p, AuditDir: t.TempDir(), Admin: "0.0.0.0:3129", Logger: quiet()}); err == nil {
		t.Error("non-loopback admin address must be refused")
	}
	bad := policyFile(t, "nonsense")
	if err := Run(ctx, Options{PolicyPath: bad, AuditDir: t.TempDir(), Listen: "127.0.0.1:0", Admin: "127.0.0.1:0", Logger: quiet()}); err == nil {
		t.Error("a bad policy must prevent startup")
	}
	if err := Run(ctx, Options{AuditDir: t.TempDir()}); err == nil {
		t.Error("missing --policy must be an error")
	}
}

func TestFetchStatus(t *testing.T) {
	_, adminAddr, _, _, _ := startGateway(t, "version: 1\nrules:\n  - {host: a.example.com}\n")
	b, err := FetchStatus(context.Background(), adminAddr)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Policy Status `json:"policy"`
	}
	if err := json.Unmarshal(b, &st); err != nil || len(st.Policy.PolicyHash) != 64 {
		t.Fatalf("status = %s (%v)", b, err)
	}
	if _, err := FetchStatus(context.Background(), "0.0.0.0:9999"); err == nil {
		t.Error("a non-loopback admin address must be refused")
	}
}
