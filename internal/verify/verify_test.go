package verify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-systems/kennel/internal/audit"
	"github.com/middle-systems/kennel/internal/policy"
)

// world is a scriptable sandbox. The zero value is a healthy, correctly configured one; each test
// breaks one property and expects exactly that check to fail. This is how the suite itself is
// tested: a check that cannot fail is worth nothing.
type world struct {
	mu sync.Mutex

	directConnects  bool
	dnsLeak         bool
	publicResolves  bool
	noGateway       bool
	unlistedStatus  int // 0 = 403
	allowedStatus   int // 0 = 200
	ipLiteralStatus int // 0 = 403
	ipLiteralReason string
	loopbackStatus  int
	loopbackReason  string
	tlsConnect      int
	tlsControl      string
	sniMismatch     string
	ech             string
	noTLS           string
	plainStatus     int
	plainReason     string
	protectedBad    string // an extra line the protected-path probe prints
	protectedCode   int
	capEff          string
	noNewPrivs      string
	uid             string
	socket          bool
	hostDockerInt   bool
	reachable       []string
	noProxyControl  bool
	listeners       map[int]string
	hostGetErr      error
	forwarderServer string
	holdStart       string
	holdResult      string
	allowTook       time.Duration
	allowErr        error
	freshStatus     int
	missingAudit    map[string]bool
	pythonMissing   bool
	execErr         error
	auditRecords    []audit.Record
	protected       []string
	ports           []int
	policyRules     []policy.Rule
	undone          int
	tokenN          int
}

func (w *world) env(t *testing.T) *Env {
	t.Helper()
	if w.policyRules == nil {
		w.policyRules = []policy.Rule{{Host: "api.example.com"}}
	}
	pol, err := policy.Compile(&policy.Policy{Version: 1, Rules: w.policyRules}, false)
	if err != nil {
		t.Fatal(err)
	}
	if w.protected == nil {
		w.protected = []string{".kennel", ".devcontainer", ".git/hooks"}
	}
	if w.ports == nil {
		w.ports = []int{5173}
	}
	if w.listeners == nil {
		w.listeners = map[int]string{5173: "all-interfaces"}
	}
	e := &Env{
		Policy: pol, Protected: w.protected, Ports: w.ports, Mutate: true, AuditWait: 150 * time.Millisecond,
		Now:   time.Now,
		Token: func() string { w.mu.Lock(); defer w.mu.Unlock(); w.tokenN++; return fmt.Sprintf("t%d", w.tokenN) },
	}
	e.Exec = func(_ context.Context, argv ...string) (Out, error) { return w.exec(argv) }
	e.Hold = func(_ context.Context, argv ...string) (Held, error) { return w.hold(argv) }
	e.Audit = func() ([]audit.Record, error) { return w.audit(), nil }
	e.Listeners = func(context.Context) (map[int]string, error) { return w.listeners, nil }
	e.HostGet = func(context.Context, int) (string, error) {
		if w.hostGetErr != nil {
			return "", w.hostGetErr
		}
		return "HTTP/1.0 200 OK", nil
	}
	e.AllowTemp = func(_ context.Context, hosts []string) (func(), time.Duration, error) {
		if w.allowErr != nil {
			return nil, 0, w.allowErr
		}
		return func() { w.mu.Lock(); w.undone++; w.mu.Unlock() }, w.allowTook, nil
	}
	return e
}

func js(v any) Out { b, _ := json.Marshal(v); return Out{Stdout: string(b) + "\n"} }

func status(code int, def int) int {
	if code == 0 {
		return def
	}
	return code
}

func (w *world) exec(argv []string) (Out, error) {
	if w.execErr != nil {
		return Out{}, w.execErr
	}
	if len(argv) >= 3 && argv[0] == "python3" && w.pythonMissing {
		return Out{Code: 127, Stderr: "python3: not found"}, nil
	}
	script := ""
	if len(argv) >= 3 {
		script = argv[2]
	}
	switch {
	case argv[0] == "python3" && script == pyDirect:
		return js([]map[string]any{
			{"to": "1.1.1.1:443", "connected": w.directConnects, "err": "OSError"},
			{"to": "8.8.8.8:53", "connected": false, "err": "OSError"},
		}), nil
	case argv[0] == "python3" && script == pyDNS:
		leaks := []string{}
		if w.dnsLeak {
			leaks = []string{"1.1.1.1"}
		}
		return js(map[string]any{"resolv": []string{"127.0.0.11"}, "gateway_resolves": !w.noGateway, "public_resolves": w.publicResolves, "udp_leaks": leaks}), nil
	case argv[0] == "python3" && script == pyProxy:
		return w.proxy(argv[3]), nil
	case argv[0] == "python3" && script == pyTLS:
		sni := argv[4]
		w.mu.Lock()
		defer w.mu.Unlock()
		w.auditRecords = append(w.auditRecords, w.recordsFor(sni, argv[3])...)
		return js(map[string]any{"connect": status(w.tlsConnect, 200), "control": orDefault(w.tlsControl, "ok"),
			"sni_mismatch": orDefault(w.sniMismatch, "closed"), "ech": orDefault(w.ech, "closed"), "no_tls": orDefault(w.noTLS, "closed")}), nil
	case argv[0] == "python3" && script == pyHost:
		return js(map[string]any{"host_docker_internal": w.hostDockerInt, "default_routes": []string{}, "reachable": nonNil(w.reachable), "proxy_control": !w.noProxyControl}), nil
	case argv[0] == "sh" && strings.Contains(argv[2], "mountinfo") && strings.Contains(argv[2], "verify-moved"):
		var sb strings.Builder
		for _, p := range argv[4:] {
			fmt.Fprintf(&sb, "mount-ro:%s\nwrite-refused:%s\npinned:%s\n", p, p, p)
		}
		sb.WriteString(w.protectedBad)
		return Out{Stdout: sb.String(), Code: w.protectedCode}, nil
	case argv[0] == "sh" && strings.Contains(argv[2], "CapEff"):
		var sb strings.Builder
		fmt.Fprintf(&sb, "CapEff:\t%s\nCapBnd:\t0000000000000000\nNoNewPrivs:\t%s\nSeccomp:\t2\nuid=%s\n", orDefault(w.capEff, "0000000000000000"), orDefault(w.noNewPrivs, "1"), orDefault(w.uid, "1000"))
		if w.socket {
			sb.WriteString("SOCKET=/var/run/docker.sock\n")
		}
		sb.WriteString("done\n")
		return Out{Stdout: sb.String()}, nil
	case argv[0] == "python3" && strings.Contains(script, "GET http://1.1.1.1/"):
		return js([]map[string]any{{"server": orDefault(w.forwarderServer, "SimpleHTTP/0.6 Python/3.11")}}), nil
	}
	return Out{Code: 99, Stderr: "unexpected command: " + strings.Join(argv[:min(len(argv), 2)], " ")}, nil
}

func (w *world) proxy(arg string) Out {
	var raws []string
	_ = json.Unmarshal([]byte(arg), &raws)
	var out []proxied
	for _, raw := range raws {
		target := strings.Fields(raw)[1]
		host := strings.Split(strings.TrimPrefix(target, "http://"), ":")[0]
		host = strings.TrimSuffix(host, "/")
		isGet := strings.HasPrefix(raw, "GET ")
		p := proxied{Status: 403, Reason: "default-deny", Line: "HTTP/1.1 403 Forbidden", Body: "kennel: not in the allowlist.\nTo allow it for this session: kennel allow x"}
		switch {
		case strings.HasSuffix(host, ".invalid") && strings.HasPrefix(host, "reload-"):
			if w.freshStatus != 0 {
				p.Status, p.Reason = w.freshStatus, ""
			} else {
				p.Status, p.Reason = 502, ""
			}
		case strings.HasSuffix(host, ".invalid"):
			if !isGet {
				p.Status = status(w.unlistedStatus, 403)
			}
			w.mu.Lock()
			if !w.missingAudit["deny"] {
				w.auditRecords = append(w.auditRecords, audit.Record{TS: time.Now(), Event: "decision", Action: "deny", Host: host, Reason: "default-deny"})
			}
			w.mu.Unlock()
		case host == "api.example.com" && isGet:
			p.Status, p.Reason = status(w.plainStatus, 403), orDefault(w.plainReason, "http-not-allowed")
		case host == "api.example.com":
			p.Status, p.Reason = status(w.allowedStatus, 200), ""
		case host == "localhost":
			p.Status, p.Reason = status(w.loopbackStatus, 403), orDefault(w.loopbackReason, "blocked-address")
		default: // IP literals
			p.Status, p.Reason = status(w.ipLiteralStatus, 403), orDefault(w.ipLiteralReason, "ip-literal")
		}
		out = append(out, p)
	}
	return js(out)
}

// recordsFor fabricates the audit records the gateway would write for the TLS probe.
func (w *world) recordsFor(sni, host string) []audit.Record {
	var rs []audit.Record
	if !w.missingAudit["sni"] {
		rs = append(rs, audit.Record{TS: time.Now(), Event: "decision", Action: "deny", Host: host, SNI: sni, Reason: "sni-mismatch"})
	}
	if !w.missingAudit["ech"] {
		rs = append(rs, audit.Record{TS: time.Now(), Event: "decision", Action: "deny", Host: host, Reason: "ech"})
	}
	return rs
}

func (w *world) audit() []audit.Record {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]audit.Record(nil), w.auditRecords...)
}

type fakeHeld struct {
	lines []string
	sent  []string
}

func (h *fakeHeld) Send(l string) error { h.sent = append(h.sent, l); return nil }
func (h *fakeHeld) ReadLine(time.Duration) (string, error) {
	if len(h.lines) == 0 {
		return "", errors.New("EOF")
	}
	l := h.lines[0]
	h.lines = h.lines[1:]
	return l, nil
}
func (h *fakeHeld) Close() error { return nil }

func (w *world) hold(argv []string) (Held, error) {
	if strings.Contains(strings.Join(argv, " "), "http.server") {
		return &fakeHeld{}, nil
	}
	return &fakeHeld{lines: []string{orDefault(w.holdStart, "READY"), orDefault(w.holdResult, "ALIVE")}}, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func run(t *testing.T, w *world, only ...string) map[string]Result {
	t.Helper()
	rs := Run(context.Background(), w.env(t), only)
	m := map[string]Result{}
	for _, r := range rs {
		m[r.Name] = r
	}
	return m
}

func TestAHealthySandboxPassesEverything(t *testing.T) {
	rs := run(t, &world{})
	if len(rs) != 12 {
		t.Fatalf("want the 12 checks of the spec, got %d", len(rs))
	}
	for name, r := range rs {
		if r.Status != Pass {
			t.Errorf("%s: %s: %s", name, r.Status, r.Detail)
		}
	}
	if Failed(mapValues(rs), true) {
		t.Error("a clean run must not fail even with --strict")
	}
}

func mapValues(m map[string]Result) []Result {
	var out []Result
	for _, r := range m {
		out = append(out, r)
	}
	return out
}

// Every weakening below must be caught by the named check and by no other.
func TestEachWeaknessIsCaughtByItsCheck(t *testing.T) {
	cases := []struct {
		name  string
		check string
		w     *world
		want  string
	}{
		{"a route to the internet", "direct-egress", &world{directConnects: true}, "route"},
		{"DNS leaking to a public resolver", "dns-leak", &world{dnsLeak: true}, "public resolvers"},
		{"public names resolving", "dns-leak", &world{publicResolves: true}, "resolved example.com"},
		{"an unusable gateway name", "dns-leak", &world{noGateway: true}, "proves nothing"},
		{"an unlisted host let through", "proxy-policy", &world{unlistedStatus: 200}, "not refused"},
		{"a listed host refused", "proxy-policy", &world{allowedStatus: 403}, "was refused"},
		{"no audit record for a denial", "proxy-policy", &world{missingAudit: map[string]bool{"deny": true}}, "audit"},
		{"an IP literal let through", "ip-literal", &world{ipLiteralStatus: 200}, "not refused"},
		{"an IP literal refused for the wrong reason", "ip-literal", &world{ipLiteralReason: "default-deny"}, "not ip-literal"},
		{"loopback reachable", "internal-addresses", &world{loopbackStatus: 200}, "loopback"},
		{"loopback refused for the wrong reason", "internal-addresses", &world{loopbackReason: "default-deny"}, "blocked-address"},
		{"SNI mismatch let through", "tls-sni-ech", &world{sniMismatch: "open"}, "SNI differs"},
		{"ECH let through", "tls-sni-ech", &world{ech: "open"}, "encrypted_client_hello"},
		{"non-TLS let through", "tls-sni-ech", &world{noTLS: "open"}, "non-TLS"},
		{"a closed handshake that is not logged", "tls-sni-ech", &world{missingAudit: map[string]bool{"sni": true}}, "sni-mismatch"},
		{"plain HTTP let through", "plain-http", &world{plainStatus: 200}, "not refused"},
		{"plain HTTP refused for the wrong reason", "plain-http", &world{plainReason: "default-deny"}, "http-not-allowed"},
		{"a writable protected path", "protected-paths", &world{protectedBad: "WRITABLE:.git/hooks\n", protectedCode: 1}, "WRITABLE"},
		{"a renamable parent", "protected-paths", &world{protectedBad: "RENAMABLE:.git\n"}, "RENAMABLE"},
		{"visible gateway state", "protected-paths", &world{protectedBad: "STATE-VISIBLE\n"}, "STATE-VISIBLE"},
		{"capabilities", "hardening", &world{capEff: "00000000a80425fb"}, "CapEff"},
		{"privilege escalation allowed", "hardening", &world{noNewPrivs: "0"}, "NoNewPrivs"},
		{"running as root", "hardening", &world{uid: "0"}, "uid"},
		{"a Docker socket", "hardening", &world{socket: true}, "docker.sock"},
		{"host.docker.internal", "host-isolation", &world{hostDockerInt: true}, "host.docker.internal"},
		{"a reachable host service", "host-isolation", &world{reachable: []string{"172.17.0.1:2375"}}, "172.17.0.1:2375"},
		{"a reachable admin port", "host-isolation", &world{reachable: []string{"gateway:3129"}}, "gateway:3129"},
		{"a dev server on localhost only", "preview-inbound", &world{listeners: map[int]string{5173: "loopback-only"}}, "localhost"},
		{"a published port that does not reach the agent", "preview-inbound", &world{hostGetErr: errors.New("connection reset")}, "does not reach"},
		{"a dropped connection on reload", "hot-reload", &world{holdResult: "DROPPED SSLEOFError"}, "dropped"},
		{"a slow reload", "hot-reload", &world{allowTook: 3 * time.Second}, "limit 2s"},
		{"a rule the gateway reports but does not enforce", "hot-reload", &world{freshStatus: 403}, "still refuses"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := run(t, c.w)
			got := rs[c.check]
			if got.Status != Fail || !strings.Contains(got.Detail, c.want) {
				t.Fatalf("%s should FAIL mentioning %q, got %s: %s", c.check, c.want, got.Status, got.Detail)
			}
			for name, r := range rs {
				if name != c.check && r.Status == Fail {
					t.Errorf("%s also failed (a weakness should be caught where it belongs): %s", name, r.Detail)
				}
			}
		})
	}
}

func TestChecksThatNeedOutboundSkipRatherThanPass(t *testing.T) {
	rs := run(t, &world{tlsConnect: 502, holdStart: "NOTUNNEL 502"})
	for _, name := range []string{"tls-sni-ech", "hot-reload"} {
		if rs[name].Status != Skip || !strings.Contains(rs[name].Detail, "outbound") {
			t.Errorf("%s = %s: %s", name, rs[name].Status, rs[name].Detail)
		}
	}
	if Failed(mapValues(rs), false) {
		t.Error("skips alone must not fail a normal run")
	}
	if !Failed(mapValues(rs), true) {
		t.Error("--strict must fail on skips: CI uses it so a silent skip cannot hide a regression")
	}
}

func TestAControlThatFailsMeansNoVerdict(t *testing.T) {
	rs := run(t, &world{tlsControl: "fail:SSLError"})
	if rs["tls-sni-ech"].Status != Skip {
		t.Errorf("if a correct handshake fails, refusals prove nothing: %s %s", rs["tls-sni-ech"].Status, rs["tls-sni-ech"].Detail)
	}
	rs = run(t, &world{noProxyControl: true})
	if rs["host-isolation"].Status != Fail {
		t.Errorf("unreachable results without a working positive control must fail: %s", rs["host-isolation"].Status)
	}
}

func TestReadOnlyModeSkipsTheChecksThatEditPolicy(t *testing.T) {
	w := &world{}
	e := w.env(t)
	e.Mutate = false
	for _, r := range Run(context.Background(), e, nil) {
		if (r.Name == "internal-addresses" || r.Name == "hot-reload") != (r.Status == Skip) {
			t.Errorf("%s: %s", r.Name, r.Status)
		}
	}
	if w.undone != 0 {
		t.Error("nothing was added, so nothing should be removed")
	}
}

func TestTemporaryRulesAreAlwaysRemoved(t *testing.T) {
	w := &world{loopbackStatus: 200, holdResult: "DROPPED"}
	_ = run(t, w, "internal-addresses", "hot-reload")
	if w.undone != 2 {
		t.Errorf("both temporary session rules must be removed even when the checks fail (removed %d)", w.undone)
	}
}

func TestAPythonFreeImageFailsLoudly(t *testing.T) {
	rs := run(t, &world{pythonMissing: true}, "direct-egress")
	if rs["direct-egress"].Status != Fail || !strings.Contains(rs["direct-egress"].Detail, "python3") {
		t.Errorf("%+v", rs["direct-egress"])
	}
}

func TestACrashingCheckIsAFailureNotAPass(t *testing.T) {
	w := &world{}
	e := w.env(t)
	e.Exec = func(context.Context, ...string) (Out, error) { panic("boom") }
	rs := Run(context.Background(), e, []string{"direct-egress"})
	if len(rs) != 1 || rs[0].Status != Fail || !strings.Contains(rs[0].Detail, "crashed") {
		t.Errorf("%+v", rs)
	}
}

func TestEngineErrorsAreFailures(t *testing.T) {
	rs := run(t, &world{execErr: errors.New("container is not running")}, "direct-egress", "hardening")
	for name, r := range rs {
		if r.Status != Fail {
			t.Errorf("%s = %s", name, r.Status)
		}
	}
}

func TestSelectingChecksByNameAndNumber(t *testing.T) {
	rs := Run(context.Background(), (&world{}).env(t), []string{"4", "hardening"})
	if len(rs) != 2 || rs[0].ID != 4 || rs[1].Name != "hardening" {
		t.Errorf("%+v", rs)
	}
}

func TestNoAllowedHostMeansHonestSkips(t *testing.T) {
	w := &world{policyRules: []policy.Rule{{Host: "*.example.com"}}}
	rs := run(t, w, "tls-sni-ech", "hot-reload")
	for name, r := range rs {
		if r.Status != Skip {
			t.Errorf("%s = %s", name, r.Status)
		}
	}
}

func TestAllowedHostSelection(t *testing.T) {
	mk := func(rules ...policy.Rule) *policy.Compiled {
		c, err := policy.Compile(&policy.Policy{Version: 1, Rules: rules}, false)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if got := allowedHost(mk(policy.Rule{Host: "*.example.com"}, policy.Rule{Host: "deny.example.org", Action: "deny"}, policy.Rule{Host: "http.example.org", UnsafeAllowHTTP: true}, policy.Rule{Host: "ports.example.org", Ports: []int{8443}}, policy.Rule{Host: "good.example.org"})); got != "good.example.org" {
		t.Errorf("picked %q", got)
	}
	if allowedHost(nil) != "" || allowedHost(mk()) != "" {
		t.Error("no policy, no host")
	}
}

// ---- volume mode ----

func volumeEnv(t *testing.T, w *world, hostSeesAgentFile, agentSeesHostFile bool) (*Env, *[]string) {
	t.Helper()
	e := w.env(t)
	e.VolumeMode = true
	var created []string
	e.HostMarker = func(name string) (func(), error) {
		created = append(created, name)
		return func() {}, nil
	}
	e.HostHas = func(name string) bool { return hostSeesAgentFile && strings.HasSuffix(name, "-agent") }
	inner := e.Exec
	e.Exec = func(ctx context.Context, argv ...string) (Out, error) {
		if len(argv) >= 3 && argv[0] == "sh" && strings.Contains(argv[2], "agent-wrote") {
			out := "agent-wrote\n"
			code := 0
			if agentSeesHostFile {
				out, code = "HOST-FILE-VISIBLE\nagent-wrote\n", 1
			}
			return Out{Stdout: out, Code: code}, nil
		}
		if len(argv) >= 2 && argv[0] == "rm" {
			return Out{}, nil
		}
		return inner(ctx, argv...)
	}
	return e, &created
}

func TestVolumeModeChecksIsolationInsteadOfReadOnlyMounts(t *testing.T) {
	w := &world{}
	e, created := volumeEnv(t, w, false, false)
	rs := Run(context.Background(), e, []string{"protected-paths"})
	if rs[0].Status != Pass || !strings.Contains(rs[0].Detail, "kennel fetch") {
		t.Fatalf("%+v", rs[0])
	}
	if len(*created) != 1 || !strings.HasSuffix((*created)[0], "-host") {
		t.Errorf("the host marker was not created: %v", *created)
	}
}

func TestVolumeModeCatchesASharedWorkspace(t *testing.T) {
	w := &world{}
	for name, c := range map[string][2]bool{
		"the agent's file shows up on the host": {true, false},
		"the host's file shows up in the agent": {false, true},
	} {
		e, _ := volumeEnv(t, w, c[0], c[1])
		rs := Run(context.Background(), e, []string{"protected-paths"})
		if rs[0].Status != Fail {
			t.Errorf("%s must FAIL: %+v", name, rs[0])
		}
	}
}
