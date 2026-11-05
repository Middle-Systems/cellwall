package sandbox

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-systems/kennel/internal/policy"
	"github.com/middle-systems/kennel/internal/policyedit"
	"github.com/middle-systems/kennel/internal/scaffold"
)

// fakeEngine answers the docker commands Edit and Status make, reporting whatever policy is
// currently on disk as the gateway's active policy (as a healthy, fast-reloading gateway would).
type fakeEngine struct {
	root      string
	running   bool
	staleHash string // when set, the gateway keeps reporting this hash (a rejected reload)
	lastError string
	mu        sync.Mutex
	calls     []string
}

func (f *fakeEngine) diskHash() string {
	b, err := os.ReadFile(filepath.Join(f.root, ".kennel", "state", "policy", "policy.json"))
	if err != nil {
		return ""
	}
	p, err := policy.Parse("policy.json", b)
	if err != nil {
		return ""
	}
	c, err := policy.Compile(p, true)
	if err != nil {
		return ""
	}
	return c.Hash
}

func (f *fakeEngine) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	j := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, j)
	f.mu.Unlock()
	switch {
	case strings.Contains(j, "ps --status running -q gateway"):
		if f.running {
			return []byte("abc123\n"), nil
		}
		return nil, nil
	case strings.Contains(j, "gateway status"):
		h := f.diskHash()
		if f.staleHash != "" {
			h = f.staleHash
		}
		return []byte(`{"policy":{"policy_hash":"` + h + `","last_reload_error":"` + f.lastError + `"},"active_connections":0}`), nil
	}
	return nil, nil
}

func project(t *testing.T) (root, global string) {
	t.Helper()
	root, global = t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := scaffold.Build(scaffold.Options{Root: root, GlobalConfigDir: global})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plan.Apply(); err != nil {
		t.Fatal(err)
	}
	return root, global
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return ""
	}
	return string(b)
}

func allow(hosts ...string) EditOptions {
	return EditOptions{Edit: policyedit.Edit{Action: policy.ActionAllow, Hosts: hosts}, Wait: 2 * time.Second}
}

func TestAllowWithRunningGatewayWaitsForTheNewPolicy(t *testing.T) {
	root, global := project(t)
	f := &fakeEngine{root: root, running: true}
	res, err := Edit(context.Background(), Env{Runner: f, GlobalDir: global}, root, allow("registry.example.org"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.GatewayUp || !res.Applied || res.GatewayError != "" {
		t.Fatalf("result = %+v", res)
	}
	if !strings.Contains(readFile(t, root, ".kennel/state/policy/policy.json"), "registry.example.org") {
		t.Error("the effective policy does not contain the new host")
	}
	if strings.Contains(readFile(t, root, ".kennel/policy.yaml"), "registry.example.org") {
		t.Error("a session-only allow must not touch the committed policy")
	}
}

func TestAllowWithoutAGatewaySaysWhenItTakesEffect(t *testing.T) {
	root, global := project(t)
	res, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow("registry.example.org"))
	if err != nil {
		t.Fatal(err)
	}
	if res.GatewayUp || res.Applied {
		t.Errorf("no gateway is running, but result = %+v", res)
	}
}

func TestAllowReportsAGatewayThatRejectsTheChange(t *testing.T) {
	root, global := project(t)
	f := &fakeEngine{root: root, running: true, staleHash: "0000", lastError: "boom"}
	res, err := Edit(context.Background(), Env{Runner: f, GlobalDir: global}, root, EditOptions{
		Edit: policyedit.Edit{Action: policy.ActionAllow, Hosts: []string{"a.example.org"}}, Wait: 600 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || !strings.Contains(res.GatewayError, "boom") {
		t.Fatalf("a rejected reload must be reported, got %+v", res)
	}
}

func TestSaveWritesTheCommittedPolicyAndKeepsItsComments(t *testing.T) {
	root, global := project(t)
	opts := allow("api.example.org")
	opts.Save = true
	opts.Edit.Note = "partner api"
	if _, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, opts); err != nil {
		t.Fatal(err)
	}
	pol := readFile(t, root, ".kennel/policy.yaml")
	if !strings.Contains(pol, "api.example.org") || !strings.Contains(pol, "# kennel egress policy") {
		t.Errorf("committed policy:\n%s", pol)
	}
	if readFile(t, root, ".kennel/state/session-policy.yaml") != "" {
		t.Error("--save must not also create a session rule")
	}
	// Saving the same rule again says it was already there.
	res, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, opts)
	if err != nil || len(res.AlreadySaved) != 1 {
		t.Fatalf("second save: %+v %v", res, err)
	}
}

func TestAllowRefusedWhenADenyStillWinsAndNothingIsLeftBehind(t *testing.T) {
	root, global := project(t)
	deny := policyedit.Edit{Action: policy.ActionDeny, Hosts: []string{"tracker.example.org"}}
	if _, _, _, err := policyedit.Save(root, deny); err != nil {
		t.Fatal(err)
	}
	if _, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow("registry.example.org")); err != nil {
		t.Fatal(err)
	}
	beforePolicy := readFile(t, root, ".kennel/state/policy/policy.json")
	beforeSession := readFile(t, root, ".kennel/state/session-policy.yaml")
	beforeProject := readFile(t, root, ".kennel/policy.yaml")

	_, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow("tracker.example.org"))
	if err == nil || !strings.Contains(err.Error(), "still denied") || !strings.Contains(err.Error(), "next:") {
		t.Fatalf("want an actionable refusal, got %v", err)
	}
	if readFile(t, root, ".kennel/state/policy/policy.json") != beforePolicy ||
		readFile(t, root, ".kennel/state/session-policy.yaml") != beforeSession ||
		readFile(t, root, ".kennel/policy.yaml") != beforeProject {
		t.Error("a refused allow changed files")
	}
}

func TestDangerousWildcardIsRefusedAndRolledBack(t *testing.T) {
	root, global := project(t)
	for _, host := range []string{"*.github.io", "**.com"} {
		_, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow(host))
		if err == nil {
			t.Errorf("%s must be refused", host)
		}
		if readFile(t, root, ".kennel/state/session-policy.yaml") != "" {
			t.Errorf("%s: the refused rule was left in the session layer", host)
		}
	}
	// And the effective policy is still valid and loadable afterwards.
	if h := (&fakeEngine{root: root}).diskHash(); h == "" {
		t.Error("policy.json is missing or invalid after a refused edit")
	}
}

func TestPlainHTTPPortIsRefusedWithAnExplanation(t *testing.T) {
	root, global := project(t)
	opts := allow("plain.example.org")
	opts.Edit.Ports = []int{80}
	_, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, opts)
	if err == nil || !strings.Contains(err.Error(), "plain HTTP") || !strings.Contains(err.Error(), "unsafe_allow_http") {
		t.Fatalf("got %v", err)
	}
}

func TestBadHostsAreRefusedBeforeAnythingIsWritten(t *testing.T) {
	root, global := project(t)
	for _, h := range []string{"https://example.org", "1.2.3.4", "example.org:443", "bücher.de"} {
		if _, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow(h)); err == nil {
			t.Errorf("%q must be refused", h)
		}
	}
	if readFile(t, root, ".kennel/state/session-policy.yaml") != "" {
		t.Error("a refused host left a session file")
	}
}

func TestStatusWithoutADaemonStillReportsWhatItCan(t *testing.T) {
	root, global := project(t)
	if _, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow("a.example.org")); err != nil {
		t.Fatal(err)
	}
	rep, err := Status(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Policy.OnDisk == "" || rep.Policy.GatewayUp || len(rep.Containers) != 0 {
		t.Errorf("report = %+v", rep)
	}
	found := false
	for _, r := range rep.Relaxations {
		if strings.Contains(r, "session rule") && strings.Contains(r, "a.example.org") {
			found = true
		}
	}
	if !found {
		t.Errorf("a session rule must show up among the relaxations: %v", rep.Relaxations)
	}
}

func TestStatusDetectsADriftedGateway(t *testing.T) {
	root, global := project(t)
	if _, err := Edit(context.Background(), Env{Runner: &fakeEngine{root: root}, GlobalDir: global}, root, allow("a.example.org")); err != nil {
		t.Fatal(err)
	}
	f := &fakeEngine{root: root, running: true, staleHash: "ffff"}
	rep, err := Status(context.Background(), Env{Runner: f, GlobalDir: global}, root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Policy.InSync || len(rep.Warnings) == 0 {
		t.Errorf("a gateway enforcing another policy must be flagged: %+v", rep)
	}
}

func TestParsePSAcceptsBothComposeFormats(t *testing.T) {
	nd := []byte(`{"Service":"agent","State":"running","Image":"a"}` + "\n" + `{"Service":"gateway","State":"running","Health":"healthy","Image":"g"}` + "\n")
	arr := []byte(`[{"Service":"agent","State":"running","Image":"a"},{"Service":"gateway","State":"running","Health":"healthy","Image":"g"}]`)
	for name, in := range map[string][]byte{"ndjson": nd, "array": arr} {
		cs := parsePS(in)
		if len(cs) != 2 || cs[1].Service != "gateway" || cs[1].Health != "healthy" {
			t.Errorf("%s: %+v", name, cs)
		}
	}
	if len(parsePS(nil)) != 0 {
		t.Error("empty output means no containers")
	}
}

func listenLoopback(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}
