package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/middle-systems/kennel/internal/audit"
	"github.com/middle-systems/kennel/internal/policy"
	"github.com/middle-systems/kennel/internal/proxy/proxytest"
)

// memAudit is an in-memory Auditor.
type memAudit struct {
	mu   sync.Mutex
	recs []audit.Record
	fail atomic.Bool
}

func (m *memAudit) Log(r audit.Record) error {
	if m.fail.Load() {
		return errors.New("disk full")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, r)
	return nil
}

func (m *memAudit) snapshot() []audit.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]audit.Record(nil), m.recs...)
}

func (m *memAudit) find(pred func(audit.Record) bool) (audit.Record, bool) {
	for _, r := range m.snapshot() {
		if pred(r) {
			return r, true
		}
	}
	return audit.Record{}, false
}

// wait polls for a record, since close records are written after the tunnel ends.
func (m *memAudit) wait(t *testing.T, pred func(audit.Record) bool) audit.Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := m.find(pred); ok {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no matching audit record; have: %+v", m.snapshot())
	return audit.Record{}
}

// env is a proxy under test wired to fakes: names resolve to public-looking addresses and every
// dial is redirected to a local upstream, so the production dial/guard code paths run unchanged
// apart from the final socket connect.
type env struct {
	t        *testing.T
	srv      *Server
	addr     string
	audit    *memAudit
	resolver *fakeResolver
	pol      atomic.Pointer[policy.Compiled]

	upstream    net.Listener
	upstreamIn  chan []byte // first bytes each upstream connection received
	dials       atomic.Int64
	upstreamMu  sync.Mutex
	upstreamFn  func(net.Conn) // behaviour of the fake upstream; default: echo
	dialAllowed atomic.Value   // last allowPrivate value seen
}

func newEnv(t *testing.T, policySrc string) *env {
	t.Helper()
	e := &env{t: t, audit: &memAudit{}, upstreamIn: make(chan []byte, 16)}
	e.resolver = &fakeResolver{answers: map[string][]netip.Addr{}}
	e.setPolicy(policySrc)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	e.upstream = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.serveUpstream(c)
		}
	}()

	e.srv = New(Config{
		Policy:   func() *policy.Compiled { return e.pol.Load() },
		Audit:    e.audit,
		Resolver: e,
		NewDial: func(allowPrivate bool) DialFunc {
			e.dialAllowed.Store(allowPrivate)
			return func(ctx context.Context, _, _ string) (net.Conn, error) {
				e.dials.Add(1)
				return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
			}
		},
		Logger: slog.New(slog.DiscardHandler),
	})
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	e.addr = pl.Addr().String()
	go func() { _ = e.srv.Serve(pl) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = e.srv.Shutdown(ctx)
	})
	return e
}

// LookupNetIP makes env the Resolver: unknown names get a public address.
func (e *env) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	name := strings.TrimSuffix(host, ".")
	e.resolver.mu.Lock()
	ans, ok := e.resolver.answers[name]
	e.resolver.mu.Unlock()
	if ok {
		return ans, nil
	}
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

func (e *env) resolve(name string, addrs ...string) {
	e.resolver.mu.Lock()
	defer e.resolver.mu.Unlock()
	e.resolver.answers[name] = nil
	for _, a := range addrs {
		e.resolver.answers[name] = append(e.resolver.answers[name], netip.MustParseAddr(a))
	}
}

func (e *env) setPolicy(src string) {
	p, err := policy.Parse("test", []byte(src))
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := policy.Compile(p, false)
	if err != nil {
		e.t.Fatal(err)
	}
	e.pol.Store(c)
}

func (e *env) setUpstream(fn func(net.Conn)) {
	e.upstreamMu.Lock()
	e.upstreamFn = fn
	e.upstreamMu.Unlock()
}

func (e *env) serveUpstream(c net.Conn) {
	defer c.Close()
	e.upstreamMu.Lock()
	fn := e.upstreamFn
	e.upstreamMu.Unlock()
	if fn != nil {
		fn(c)
		return
	}
	buf := make([]byte, 64<<10)
	first := true
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if first {
				e.upstreamIn <- append([]byte(nil), buf[:n]...)
				first = false
			}
			_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
		}
		if err != nil {
			return
		}
	}
}

// connect sends a CONNECT and returns the connection, the parsed response and a reader positioned
// after the response head.
func (e *env) connect(target string, extra ...[]byte) (net.Conn, *http.Response, *bufio.Reader) {
	e.t.Helper()
	c, err := net.DialTimeout("tcp", e.addr, 2*time.Second)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	out := []byte(req)
	for _, x := range extra {
		out = append(out, x...)
	}
	if _, err := c.Write(out); err != nil {
		e.t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		e.t.Fatalf("reading response to CONNECT %s: %v", target, err)
	}
	return c, resp, br
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	return string(b)
}

const basePolicy = `
version: 1
rules:
  - host: registry.example.com
  - host: ports.example.com
    ports: [443, 8443]
  - host: skip.example.com
    unsafe_skip_tls_check: true
  - host: ech.example.com
    unsafe_allow_ech: true
  - host: plain.example.com
    unsafe_allow_http: true
  - host: private.example.com
    unsafe_allow_private: true
  - host: "*.wild.example.com"
`

func hello(sni string) []byte { return proxytest.Records(proxytest.HelloOpts{SNI: sni}) }

func isDecision(action, host string) func(audit.Record) bool {
	return func(r audit.Record) bool {
		return r.Event == audit.EventDecision && r.Action == action && r.Host == host
	}
}

func isClose(host string) func(audit.Record) bool {
	return func(r audit.Record) bool { return r.Event == audit.EventClose && r.Host == host }
}

func TestConnectAllowedTunnelsAndForwardsHelloVerbatim(t *testing.T) {
	e := newEnv(t, basePolicy)
	h := hello("registry.example.com")
	c, resp, br := e.connect("registry.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body(t, resp))
	}
	if _, err := c.Write(h); err != nil {
		t.Fatal(err)
	}
	got := <-e.upstreamIn
	if string(got) != string(h) {
		t.Errorf("upstream must receive the ClientHello byte-for-byte\n got %x\nwant %x", got, h)
	}
	// Bidirectional data after the hello.
	reply := make([]byte, 5+len(h))
	if _, err := io.ReadFull(br, reply); err != nil || !strings.HasPrefix(string(reply), "echo:") {
		t.Fatalf("no reply through tunnel: %v %q", err, reply)
	}
	if _, err := c.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 9)
	if _, err := io.ReadFull(br, pong); err != nil || string(pong) != "echo:PING" {
		t.Fatalf("second exchange: %v %q", err, pong)
	}
	c.Close()

	dec := e.audit.wait(t, isDecision("allow", "registry.example.com"))
	if dec.Port != 443 || dec.Rule == "" || dec.Policy == "" || dec.ID == "" || dec.Proto != "connect" || dec.Src != "127.0.0.1" {
		t.Errorf("decision record incomplete: %+v", dec)
	}
	cl := e.audit.wait(t, isClose("registry.example.com"))
	if cl.ID != dec.ID || cl.SNI != "registry.example.com" || cl.BytesUp == nil || *cl.BytesUp < int64(len(h)) || cl.BytesDown == nil || *cl.BytesDown == 0 || cl.DurationMS == nil {
		t.Errorf("close record wrong: %+v", cl)
	}
}

func TestPipelinedHelloIsNotLost(t *testing.T) {
	// A client that sends the ClientHello in the same write as the CONNECT must still work: the
	// bytes sit in the server's buffered reader and must be read from there.
	e := newEnv(t, basePolicy)
	c, resp, br := e.connect("registry.example.com:443", hello("registry.example.com"))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	select {
	case <-e.upstreamIn:
	case <-time.After(3 * time.Second):
		t.Fatal("pipelined ClientHello never reached the upstream")
	}
	_ = c
	_ = br
}

func TestDeniedHostGetsActionableMessage(t *testing.T) {
	e := newEnv(t, basePolicy)
	_, resp, _ := e.connect("evil.example.org:443")
	b := body(t, resp)
	if resp.StatusCode != 403 || resp.Header.Get("X-Kennel-Reason") != policy.ReasonDefaultDeny {
		t.Fatalf("status %d reason %q", resp.StatusCode, resp.Header.Get("X-Kennel-Reason"))
	}
	for _, want := range []string{"evil.example.org:443", "not in the allowlist", "kennel allow evil.example.org", "--save"} {
		if !strings.Contains(b, want) {
			t.Errorf("message missing %q:\n%s", want, b)
		}
	}
	rec := e.audit.wait(t, isDecision("deny", "evil.example.org"))
	if rec.Reason != policy.ReasonDefaultDeny || rec.Port != 443 {
		t.Errorf("%+v", rec)
	}
	if e.dials.Load() != 0 || len(e.resolver.calls) != 0 {
		t.Error("a denied host must never be resolved or dialed")
	}
}

func TestPolicyIsCheckedBeforeResolution(t *testing.T) {
	// Denied names must not even reach the resolver: a lookup is itself a way to leak data.
	e := newEnv(t, basePolicy)
	e.resolver.calls = nil
	e.connect("aGVsbG8tZXhmaWw.attacker.example.net:443")
	e.connect("registry.example.com:22") // right host, wrong port
	time.Sleep(50 * time.Millisecond)
	e.resolver.mu.Lock()
	defer e.resolver.mu.Unlock()
	if len(e.resolver.calls) != 0 {
		t.Errorf("resolver was consulted for denied requests: %v", e.resolver.calls)
	}
}

func TestPortNotAllowed(t *testing.T) {
	e := newEnv(t, basePolicy)
	_, resp, _ := e.connect("registry.example.com:22")
	b := body(t, resp)
	if resp.StatusCode != 403 || !strings.Contains(b, "--port 22") {
		t.Fatalf("status %d: %s", resp.StatusCode, b)
	}
	c, resp, _ := e.connect("ports.example.com:8443")
	if resp.StatusCode != 200 {
		t.Fatalf("allowed extra port refused: %d", resp.StatusCode)
	}
	_ = c
}

func TestIPLiteralTargetsDenied(t *testing.T) {
	e := newEnv(t, basePolicy)
	for _, target := range []string{"93.184.216.34:443", "[2606:2800:220:1::1]:443", "127.0.0.1:443", "2130706433:443", "0x7f.1:443", "10.0.0.1:443", "[::ffff:10.0.0.1]:443"} {
		_, resp, _ := e.connect(target)
		if resp.StatusCode != 403 || resp.Header.Get("X-Kennel-Reason") != ReasonIPLiteral {
			t.Errorf("%s: status %d reason %q", target, resp.StatusCode, resp.Header.Get("X-Kennel-Reason"))
		}
	}
	if e.dials.Load() != 0 {
		t.Error("IP literals must never be dialed")
	}
}

func TestBlockedResolutionsDenied(t *testing.T) {
	e := newEnv(t, basePolicy)
	cases := map[string][]string{
		"registry.example.com": {"127.0.0.1"},
	}
	for _, c := range []struct {
		name  string
		addrs []string
		want  string
	}{
		{"registry.example.com", []string{"127.0.0.1"}, "loopback"},
		{"registry.example.com", []string{"10.1.2.3"}, "private"},
		{"registry.example.com", []string{"169.254.169.254"}, "cloud-metadata"},
		{"registry.example.com", []string{"::1"}, "loopback"},
		{"registry.example.com", []string{"::ffff:192.168.0.1"}, "private"},
		{"registry.example.com", []string{"fd00::1"}, "private"},
		{"registry.example.com", []string{"93.184.216.34", "10.0.0.9"}, "private"}, // one bad address among good
		{"registry.example.com", []string{"64:ff9b::a00:1"}, "embedded-private"},
		{"registry.example.com", []string{"0.0.0.0"}, "unspecified"},
	} {
		_ = cases
		e.resolve(c.name, c.addrs...)
		_, resp, _ := e.connect(c.name + ":443")
		b := body(t, resp)
		if resp.StatusCode != 403 || resp.Header.Get("X-Kennel-Reason") != ReasonBlockedAddress || !strings.Contains(b, c.want) {
			t.Errorf("%v: status %d reason %q body %q", c.addrs, resp.StatusCode, resp.Header.Get("X-Kennel-Reason"), b)
		}
	}
	if e.dials.Load() != 0 {
		t.Errorf("blocked resolutions must never be dialed (dials=%d)", e.dials.Load())
	}
	rec := e.audit.wait(t, func(r audit.Record) bool { return r.Reason == ReasonBlockedAddress })
	if rec.Action != audit.ActionDeny {
		t.Errorf("%+v", rec)
	}
}

func TestUnsafeAllowPrivateRelaxesOnlyPrivate(t *testing.T) {
	e := newEnv(t, basePolicy)
	e.resolve("private.example.com", "10.0.0.7")
	c, resp, _ := e.connect("private.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatalf("unsafe_allow_private host refused: %d %s", resp.StatusCode, body(t, resp))
	}
	_ = c
	if v, _ := e.dialAllowed.Load().(bool); !v {
		t.Error("dialer must be told private addresses are allowed for this rule")
	}
	// Loopback and metadata stay blocked even for that rule.
	for _, a := range []string{"127.0.0.1", "169.254.169.254", "0.0.0.0"} {
		e.resolve("private.example.com", a)
		_, resp, _ := e.connect("private.example.com:443")
		if resp.StatusCode != 403 {
			t.Errorf("%s must stay blocked with unsafe_allow_private, got %d", a, resp.StatusCode)
		}
	}
}

func TestSNIMismatchClosedAndLogged(t *testing.T) {
	e := newEnv(t, basePolicy)
	c, resp, br := e.connect("registry.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	_, _ = c.Write(hello("evil.example.org")) // CONNECT to the allowed host, hello for another
	if _, err := br.ReadByte(); err == nil {
		t.Error("connection must be closed")
	}
	cl := e.audit.wait(t, isClose("registry.example.com"))
	if cl.Reason != ReasonSNIMismatch || cl.Action != audit.ActionDeny || cl.SNI != "evil.example.org" {
		t.Errorf("%+v", cl)
	}
	select {
	case got := <-e.upstreamIn:
		t.Errorf("a mismatching hello must never reach the upstream, got %x", got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSNICaseAndTrailingDotAreNormalized(t *testing.T) {
	e := newEnv(t, basePolicy)
	c, _, _ := e.connect("Registry.Example.COM.:443")
	_, _ = c.Write(hello("REGISTRY.example.com."))
	select {
	case <-e.upstreamIn:
	case <-time.After(3 * time.Second):
		t.Fatal("equivalent names must be treated as equal")
	}
}

func TestMissingSNIAndNonTLSAndECH(t *testing.T) {
	e := newEnv(t, basePolicy)
	for _, tc := range []struct {
		name, target string
		payload      []byte
		reason       string
	}{
		{"no sni", "registry.example.com:443", proxytest.Records(proxytest.HelloOpts{}), ReasonNoSNI},
		{"ech", "registry.example.com:443", proxytest.Records(proxytest.HelloOpts{SNI: "registry.example.com", ECH: 0xfe0d}), ReasonECH},
		{"not tls", "registry.example.com:443", []byte("SSH-2.0-evil\r\n"), "tls-" + HelloNotTLS},
		{"http over 443", "registry.example.com:443", []byte("GET / HTTP/1.1\r\nHost: registry.example.com\r\n\r\n"), "tls-" + HelloNotTLS},
		{"two server names", "registry.example.com:443", proxytest.Records(proxytest.HelloOpts{SNI: "registry.example.com", ExtraSNI: []string{"evil.example.org"}}), "tls-" + HelloMultiSNI},
	} {
		before := len(e.audit.snapshot())
		c, resp, br := e.connect(tc.target)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", tc.name, resp.StatusCode)
		}
		_, _ = c.Write(tc.payload)
		if _, err := br.ReadByte(); err == nil {
			t.Errorf("%s: connection must be closed", tc.name)
		}
		deadline := time.Now().Add(2 * time.Second)
		var found bool
		for time.Now().Before(deadline) && !found {
			for _, r := range e.audit.snapshot()[before:] {
				if r.Event == audit.EventClose && r.Reason == tc.reason && r.Action == audit.ActionDeny {
					found = true
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !found {
			t.Errorf("%s: no close record with reason %q: %+v", tc.name, tc.reason, e.audit.snapshot()[before:])
		}
	}
	select {
	case got := <-e.upstreamIn:
		t.Errorf("rejected first flights must never reach the upstream: %q", got)
	default:
	}
	// The explicit relaxations work and are per-rule.
	c, _, _ := e.connect("ech.example.com:443")
	_, _ = c.Write(proxytest.Records(proxytest.HelloOpts{SNI: "ech.example.com", ECH: 0xfe0d}))
	select {
	case <-e.upstreamIn:
	case <-time.After(3 * time.Second):
		t.Error("unsafe_allow_ech rule should pass an ECH hello")
	}
	c, _, _ = e.connect("skip.example.com:443")
	_, _ = c.Write([]byte("SSH-2.0-OpenSSH\r\n"))
	select {
	case got := <-e.upstreamIn:
		if !strings.HasPrefix(string(got), "SSH-2.0") {
			t.Errorf("got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Error("unsafe_skip_tls_check rule should pass non-TLS bytes")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	e := newEnv(t, "version: 1\nrules:\n  - host: registry.example.com\nlimits: {handshake_timeout: 200ms}\n")
	c, resp, br := e.connect("registry.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	_ = c // send nothing
	if _, err := br.ReadByte(); err == nil {
		t.Error("a client that never sends a hello must be dropped")
	}
	cl := e.audit.wait(t, isClose("registry.example.com"))
	if cl.Reason != ReasonHandshakeTimeout || cl.Action != audit.ActionError {
		t.Errorf("%+v", cl)
	}
}

func TestMalformedConnectTargets(t *testing.T) {
	e := newEnv(t, basePolicy)
	for _, target := range []string{"registry.example.com", "registry.example.com:0", "registry.example.com:99999", "registry.example.com:abc",
		"user@registry.example.com:443", ":443", "registry.example.com:443/x", "regis try.example.com:443", "reg_istry.example.com:443"} {
		c, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: x\r\n\r\n", target)
		resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "CONNECT"})
		c.Close()
		if err != nil {
			continue // the HTTP server itself rejected it before our handler: also fine
		}
		if resp.StatusCode == 200 {
			t.Errorf("%q must not produce a tunnel", target)
		}
	}
	if e.dials.Load() != 0 {
		t.Error("malformed targets must never be dialed")
	}
}

func TestWildcardRule(t *testing.T) {
	e := newEnv(t, basePolicy)
	c, resp, _ := e.connect("a.wild.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	_ = c
	for _, h := range []string{"wild.example.com", "a.b.wild.example.com"} {
		if _, resp, _ := e.connect(h + ":443"); resp.StatusCode != 403 {
			t.Errorf("%s: %d", h, resp.StatusCode)
		}
	}
}

func TestHostnameHygiene(t *testing.T) {
	e := newEnv(t, "version: 1\nrules:\n  - host: '**.wild.example.com'\nlimits: {max_label_len: 30}\n")
	long := strings.Repeat("a", 31)
	if _, resp, _ := e.connect(long + ".wild.example.com:443"); resp.StatusCode != 400 {
		t.Errorf("over-long label: %d", resp.StatusCode)
	}
	rec := e.audit.wait(t, func(r audit.Record) bool { return r.Reason == policy.HostLabelTooLong })
	if rec.Action != audit.ActionDeny {
		t.Errorf("%+v", rec)
	}
	if _, resp, _ := e.connect("bücher.wild.example.com:443"); resp.StatusCode == 200 {
		t.Error("non-ASCII hostnames must be refused")
	}

	// High-entropy labels are flagged in the audit log but still allowed by default...
	data := "nbswy3dpeb3w64tmmqqhg2lun5ts" // 28 chars of base32-looking payload
	if !Suspicious(data + ".wild.example.com") {
		t.Fatal("test label should look like encoded data")
	}
	c, resp, _ := e.connect(data + ".wild.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatalf("suspicious host should be allowed by default: %d", resp.StatusCode)
	}
	_ = c
	if r := e.audit.wait(t, isDecision("allow", data+".wild.example.com")); !r.Suspicious {
		t.Errorf("not flagged suspicious: %+v", r)
	}
	// ...and refused when deny_suspicious is on.
	e.setPolicy("version: 1\nrules:\n  - host: '**.wild.example.com'\nlimits: {deny_suspicious: true}\n")
	if _, resp, _ := e.connect(data + ".wild.example.com:443"); resp.StatusCode != 403 {
		t.Errorf("deny_suspicious: %d", resp.StatusCode)
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	e := newEnv(t, basePolicy)
	e.audit.fail.Store(true)
	_, resp, _ := e.connect("registry.example.com:443")
	if resp.StatusCode != 503 || resp.Header.Get("X-Kennel-Reason") != ReasonAuditUnavailable {
		t.Fatalf("an allow that cannot be audited must be refused: %d", resp.StatusCode)
	}
	if e.dials.Load() != 0 {
		t.Error("no connection may be made when the allow cannot be recorded")
	}
	// Denials still deny while the log is broken.
	if _, resp, _ := e.connect("evil.example.org:443"); resp.StatusCode != 403 {
		t.Errorf("%d", resp.StatusCode)
	}
}

func TestAuditFailureFailOpenIsOptIn(t *testing.T) {
	e := newEnv(t, basePolicy)
	e.srv.cfg.FailOpenOnAuditError = true
	e.audit.fail.Store(true)
	c, resp, _ := e.connect("registry.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatalf("fail-open should proceed: %d", resp.StatusCode)
	}
	_ = c
}

func TestMaxConnsAndRateLimit(t *testing.T) {
	e := newEnv(t, "version: 1\nrules:\n  - host: registry.example.com\nlimits: {max_conns: 2, max_new_conns_per_host_per_min: 3}\n")
	e.setUpstream(func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }) // hold tunnels open
	var open []net.Conn
	for i := 0; i < 2; i++ {
		c, resp, _ := e.connect("registry.example.com:443")
		if resp.StatusCode != 200 {
			t.Fatalf("conn %d: %d", i, resp.StatusCode)
		}
		_, _ = c.Write(hello("registry.example.com"))
		open = append(open, c)
	}
	_, resp, _ := e.connect("registry.example.com:443")
	if resp.StatusCode != 503 || resp.Header.Get("X-Kennel-Reason") != ReasonAtCapacity {
		t.Errorf("third connection: %d", resp.StatusCode)
	}
	for _, c := range open {
		c.Close()
	}
	e.audit.wait(t, func(r audit.Record) bool { return r.Event == audit.EventClose })
	time.Sleep(50 * time.Millisecond)
	// 3 tokens per minute and the over-capacity attempt consumed none after the first three.
	var limited bool
	for i := 0; i < 6 && !limited; i++ {
		_, resp, _ := e.connect("registry.example.com:443")
		limited = resp.StatusCode == 429
	}
	if !limited {
		t.Error("per-host rate limit never engaged")
	}
}

func TestIdleTimeoutAndByteLimit(t *testing.T) {
	e := newEnv(t, "version: 1\nrules:\n  - host: registry.example.com\nlimits: {idle_timeout: 300ms, max_bytes_per_conn: 20000}\n")
	c, _, br := e.connect("registry.example.com:443")
	_, _ = c.Write(hello("registry.example.com"))
	if _, err := br.ReadByte(); err != nil { // the echo of the hello
		t.Fatal(err)
	}
	// Idle: say nothing; the gateway must drop the tunnel.
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, br)
	cl := e.audit.wait(t, isClose("registry.example.com"))
	if cl.Reason != "idle-timeout" {
		t.Errorf("reason = %q", cl.Reason)
	}

	// Byte cap: push more than the limit.
	c, _, br = e.connect("registry.example.com:443")
	_, _ = c.Write(hello("registry.example.com"))
	go func() { _, _ = io.Copy(io.Discard, br) }()
	chunk := make([]byte, 8000)
	for i := 0; i < 20; i++ {
		if _, err := c.Write(chunk); err != nil {
			break
		}
	}
	e.audit.wait(t, func(r audit.Record) bool { return r.Event == audit.EventClose && r.Reason == "max-bytes" })
}

func TestReloadAppliesToNewRequestsOnly(t *testing.T) {
	e := newEnv(t, basePolicy)
	e.setUpstream(func(c net.Conn) { _, _ = io.Copy(c, c) })
	c, resp, br := e.connect("registry.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	_, _ = c.Write(hello("registry.example.com"))
	first := make([]byte, len(hello("registry.example.com")))
	if _, err := io.ReadFull(br, first); err != nil {
		t.Fatal(err)
	}

	// Swap to a policy that no longer allows the host.
	e.setPolicy("version: 1\nrules:\n  - host: other.example.com\n")
	if _, resp, _ := e.connect("registry.example.com:443"); resp.StatusCode != 403 {
		t.Errorf("new request after reload must be denied: %d", resp.StatusCode)
	}
	// The in-flight tunnel is untouched.
	if _, err := c.Write([]byte("STILL-ALIVE")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("STILL-ALIVE"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "STILL-ALIVE" {
		t.Errorf("in-flight connection was disturbed by reload: %v %q", err, got)
	}
}

func TestShutdownRecordsInFlightTunnels(t *testing.T) {
	e := newEnv(t, basePolicy)
	e.setUpstream(func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	c, _, _ := e.connect("registry.example.com:443")
	_, _ = c.Write(hello("registry.example.com"))
	e.audit.wait(t, isDecision("allow", "registry.example.com"))
	time.Sleep(50 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = e.srv.Shutdown(ctx)
	cl := e.audit.wait(t, isClose("registry.example.com"))
	if cl.Reason != "shutdown" {
		t.Errorf("reason = %q", cl.Reason)
	}
}

func TestOriginFormRequestIsNotAProxyRequest(t *testing.T) {
	e := newEnv(t, basePolicy)
	resp, err := http.Get("http://" + e.addr + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 || resp.Header.Get("X-Kennel-Reason") != ReasonNotProxy {
		t.Errorf("%d", resp.StatusCode)
	}
}

// ---- plain HTTP ----

func (e *env) proxyClient() *http.Client {
	return &http.Client{
		Timeout:       5 * time.Second,
		Transport:     &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse("http://" + e.addr) }, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestPlainHTTPDeniedByDefault(t *testing.T) {
	e := newEnv(t, basePolicy)
	resp, err := e.proxyClient().Get("http://registry.example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 || resp.Header.Get("X-Kennel-Reason") != policy.ReasonHTTPNotAllow {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("X-Kennel-Reason"))
	}
	if e.dials.Load() != 0 {
		t.Error("denied plain HTTP must not dial")
	}
}

func TestPlainHTTPForwardedWhenAllowed(t *testing.T) {
	e := newEnv(t, basePolicy)
	var mu sync.Mutex
	var seen http.Header
	var seenHost string
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen, seenHost = r.Header.Clone(), r.Host
		mu.Unlock()
		w.Header().Set("X-Real", "kept")
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	up.Listener.Close()
	up.Listener = e.upstream
	e.upstream.Close() // replace the echo upstream with the HTTP one on the same address
	ln, err := net.Listen("tcp", e.upstream.Addr().String())
	if err != nil {
		t.Skip(err)
	}
	e.upstream = ln
	up.Listener = ln
	up.Start()
	defer up.Close()

	// Raw bytes, because Go's own client would copy a Host override into the request line.
	// Absolute-form request for plain.example.com, with a conflicting Host header and
	// proxy/hop-by-hop headers that must not be forwarded.
	raw := "GET http://plain.example.com/path?q=1 HTTP/1.1\r\n" +
		"Host: evil.example.org\r\n" +
		"Proxy-Authorization: Basic c2VjcmV0\r\n" +
		"X-Custom: v\r\n" +
		"Connection: X-Hop-Only, close\r\n" +
		"X-Hop-Only: secret\r\n\r\n"
	resp := rawHTTP(t, e.addr, raw)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "hello from upstream" {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenHost != "plain.example.com" {
		t.Errorf("upstream saw Host %q; the URL host must win over a conflicting Host header", seenHost)
	}
	for _, h := range []string{"Proxy-Authorization", "X-Hop-Only"} {
		if seen.Get(h) != "" {
			t.Errorf("hop-by-hop / proxy header %s was forwarded", h)
		}
	}
	if seen.Get("X-Custom") != "v" {
		t.Error("end-to-end headers must be forwarded")
	}
	if resp.Header.Get("X-Real") != "kept" {
		t.Errorf("end-to-end response headers must be forwarded: %v", resp.Header)
	}
	e.audit.wait(t, isDecision("allow", "plain.example.com"))
	cl := e.audit.wait(t, isClose("plain.example.com"))
	if cl.Proto != "http" || cl.BytesDown == nil || *cl.BytesDown != int64(len("hello from upstream")) {
		t.Errorf("%+v", cl)
	}
}

// rawHTTP sends literal request bytes and parses the response.
func rawHTTP(t *testing.T, addr, raw string) *http.Response {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, raw)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	return resp
}

func TestPlainHTTPRejectsUpgradeIPLiteralAndBadScheme(t *testing.T) {
	e := newEnv(t, basePolicy)
	do := func(raw string) *http.Response { return rawHTTP(t, e.addr, raw) }
	if r := do("GET http://plain.example.com/ HTTP/1.1\r\nHost: plain.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); r.StatusCode != 403 {
		t.Errorf("upgrade: %d", r.StatusCode)
	}
	if r := do("GET http://93.184.216.34/ HTTP/1.1\r\nHost: x\r\n\r\n"); r.StatusCode != 403 {
		t.Errorf("ip literal: %d", r.StatusCode)
	}
	if r := do("GET http://[::1]/ HTTP/1.1\r\nHost: x\r\n\r\n"); r.StatusCode != 403 {
		t.Errorf("ipv6 literal: %d", r.StatusCode)
	}
	if r := do("GET ftp://plain.example.com/ HTTP/1.1\r\nHost: x\r\n\r\n"); r.StatusCode != 400 {
		t.Errorf("ftp scheme: %d", r.StatusCode)
	}
	if r := do("GET http://user:pw@plain.example.com/ HTTP/1.1\r\nHost: x\r\n\r\n"); r.StatusCode != 400 {
		t.Errorf("userinfo: %d", r.StatusCode)
	}
	if e.dials.Load() != 0 {
		t.Error("none of these may be dialed")
	}
}

// A real TLS handshake and HTTP request through the proxy, end to end.
func TestRealTLSThroughProxy(t *testing.T) {
	e := newEnv(t, basePolicy)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "secure hello "+r.Host)
	}))
	e.upstream.Close()
	ln, err := net.Listen("tcp", e.upstream.Addr().String())
	if err != nil {
		t.Skip(err)
	}
	e.upstream = ln
	up.Listener = ln
	up.StartTLS()
	defer up.Close()

	c, resp, br := e.connect("registry.example.com:443")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	conn := &bufConn{Conn: c, r: br}
	tc := tls.Client(conn, &tls.Config{ServerName: "registry.example.com", InsecureSkipVerify: true}) // #nosec G402 -- test server
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake through the proxy failed: %v", err)
	}
	fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: registry.example.com\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(tc)
	if !strings.Contains(string(b), "secure hello registry.example.com") {
		t.Errorf("response: %q", b)
	}
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestStripHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Hop-One, keep-alive")
	h.Add("Connection", "X-Hop-Two")
	for _, k := range []string{"X-Hop-One", "X-Hop-Two", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Set(k, "x")
	}
	h.Set("X-End-To-End", "kept")
	h.Set("Content-Type", "text/plain")
	stripHopByHop(h)
	for k := range h {
		if k != "X-End-To-End" && k != "Content-Type" {
			t.Errorf("header %s survived stripping", k)
		}
	}
	if h.Get("X-End-To-End") != "kept" || h.Get("Content-Type") != "text/plain" {
		t.Errorf("end-to-end headers were removed: %v", h)
	}
}
