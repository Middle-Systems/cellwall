package proxy

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseConnectTarget(t *testing.T) {
	ok := map[string][2]any{
		"example.com:443":          {"example.com", 443},
		"a.b.c.example.com:8443":   {"a.b.c.example.com", 8443},
		"[2606:4700::1111]:443":    {"2606:4700::1111", 443},
		"EXAMPLE.com:1":            {"EXAMPLE.com", 1},
		"127.0.0.1:65535":          {"127.0.0.1", 65535},
		"registry-1.docker.io:443": {"registry-1.docker.io", 443},
	}
	for in, want := range ok {
		h, p, err := ParseConnectTarget(in)
		if err != nil || h != want[0] || p != want[1] {
			t.Errorf("%q -> %q,%d,%v", in, h, p, err)
		}
	}
	for _, in := range []string{
		"", "example.com", "example.com:", ":443", "example.com:0", "example.com:65536", "example.com:-1", "example.com:+443",
		"example.com:4 43", "example.com:0x1bb", "example.com:443:80", "http://example.com:443", "example.com:443/path",
		"user@example.com:443", "example.com:443?x", "example.com:443#x", "exa mple.com:443", "example.com\r\n:443",
		"example.com\x00:443", "bücher.example:443", "example.com:44３", "example.com\\:443", strings.Repeat("a", 400) + ":443",
		"[::1:443", "::1:443",
	} {
		if h, p, err := ParseConnectTarget(in); err == nil {
			t.Errorf("%q should be rejected, got %q,%d", in, h, p)
		}
	}
}

func TestSuspicious(t *testing.T) {
	yes := []string{
		"d41d8cd98f00b204e9800998ecf8427e.example.com",   // md5 hex
		"mfrggzdfmztwq2lknnwg23tpobyxe43u.example.com",   // base32
		"agvsbg8gd29ybgqgzxhmawx0cmf0aw9u.example.com",   // base64-ish (hosts are lowercased before this runs)
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8.evil.test", // long hex
	}
	for _, h := range yes {
		if !Suspicious(h) {
			t.Errorf("%s should be flagged", h)
		}
	}
	no := []string{
		"registry.npmjs.org", "files.pythonhosted.org", "registry-1.docker.io", "production.cloudflare.docker.com",
		"api.anthropic.com", "index.crates.io", "a.b.c.d.e.f.example.com", "downloads.claude.ai",
		"http-intake.logs.us5.datadoghq.com", "browser-intake-us5-datadoghq.com", "raw.githubusercontent.com",
		"xn--bcher-kva.example", "my-very-long-but-ordinary-service-name.internal.example.com",
		"internationalization-services.example.com", "kubernetes-dashboard-metrics-scraper.example.com",
		"ec2-203-0-113-25.compute-1.amazonaws.com", "d111111abcdef8.cloudfront.net",
	}
	for _, h := range no {
		if Suspicious(h) {
			t.Errorf("%s must not be flagged (false positives are noise)", h)
		}
	}
}

func TestPrintableNeutralisesControlCharacters(t *testing.T) {
	got := printable("evil\r\nX-Injected: 1\x1b[31m\u202e.com")
	if strings.ContainsAny(got, "\r\n\x1b") || strings.Contains(got, "\u202e") || strings.Contains(got, " ") {
		t.Errorf("%q", got)
	}
	if long := printable(strings.Repeat("a", 500)); len(long) > 110 {
		t.Errorf("not truncated: %d", len(long))
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRateLimiter(func() time.Time { return now })
	for i := 0; i < 6; i++ {
		if !r.Allow("a.com", 6) {
			t.Fatalf("burst of 6 should pass (%d)", i)
		}
	}
	if r.Allow("a.com", 6) {
		t.Error("7th in a burst must be refused")
	}
	if !r.Allow("b.com", 6) {
		t.Error("buckets are per host")
	}
	now = now.Add(10 * time.Second) // 6/min = 1 token per 10s
	if !r.Allow("a.com", 6) {
		t.Error("a token should have refilled")
	}
	if r.Allow("a.com", 6) {
		t.Error("only one token refilled")
	}
	now = now.Add(time.Hour)
	for i := 0; i < 6; i++ {
		if !r.Allow("a.com", 6) {
			t.Errorf("full refill expected (%d)", i)
		}
	}
	if r.Allow("a.com", 6) {
		t.Error("refill must cap at the burst size")
	}
	for i := 0; i < 1000; i++ {
		if !r.Allow("anything", 0) || !r.Allow("anything", -1) {
			t.Fatal("limit <= 0 means unlimited")
		}
	}
}

func TestRateLimiterSweepsIdleBuckets(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRateLimiter(func() time.Time { return now })
	for i := 0; i < pruneAfter+10; i++ {
		r.Allow(strings.Repeat("x", 3)+string(rune('a'+i%26))+itoa(i), 10)
	}
	now = now.Add(10 * time.Minute)
	r.Allow("trigger.example.com", 10)
	r.mu.Lock()
	n := len(r.m)
	r.mu.Unlock()
	if n > 10 {
		t.Errorf("idle buckets were not swept: %d remain", n)
	}
}

func tcpPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b = <-ch
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestSpliceCopiesBothWaysAndHalfCloses(t *testing.T) {
	clientFar, clientNear := tcpPair(t) // clientFar is the "agent"
	upNear, upFar := tcpPair(t)         // upFar is the "internet"
	done := make(chan SpliceResult, 1)
	go func() {
		done <- Splice(context.Background(), clientNear, clientNear, upNear, SpliceOptions{Idle: 2 * time.Second})
	}()

	_, _ = clientFar.Write([]byte("request-bytes"))
	buf := make([]byte, 13)
	if _, err := io.ReadFull(upFar, buf); err != nil || string(buf) != "request-bytes" {
		t.Fatalf("up: %v %q", err, buf)
	}
	_, _ = upFar.Write([]byte("response!"))
	buf = make([]byte, 9)
	if _, err := io.ReadFull(clientFar, buf); err != nil || string(buf) != "response!" {
		t.Fatalf("down: %v %q", err, buf)
	}
	// Client finishes sending; the upstream sees EOF but can still reply (half-close).
	_ = clientFar.(*net.TCPConn).CloseWrite()
	if n, _ := upFar.Read(make([]byte, 1)); n != 0 {
		t.Error("upstream should see EOF")
	}
	_, _ = upFar.Write([]byte("late"))
	late := make([]byte, 4)
	if _, err := io.ReadFull(clientFar, late); err != nil || string(late) != "late" {
		t.Fatalf("half-close lost data: %v %q", err, late)
	}
	_ = upFar.Close()
	res := <-done
	if res.Up != 13 || res.Down != 13 || res.Reason != "closed" {
		t.Errorf("%+v", res)
	}
}

func TestSpliceIdleCountsBothDirections(t *testing.T) {
	clientFar, clientNear := tcpPair(t)
	upNear, upFar := tcpPair(t)
	done := make(chan SpliceResult, 1)
	go func() {
		done <- Splice(context.Background(), clientNear, clientNear, upNear, SpliceOptions{Idle: 300 * time.Millisecond})
	}()
	// Keep only the DOWN direction busy for longer than the idle timeout: not idle overall.
	go func() {
		for i := 0; i < 8; i++ {
			_, _ = upFar.Write([]byte("tick"))
			time.Sleep(100 * time.Millisecond)
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, clientFar) }()
	select {
	case res := <-done:
		if res.Reason == "idle-timeout" && res.Down < 24 {
			t.Fatalf("a busy tunnel was cut for idleness: %+v", res)
		}
	case <-time.After(700 * time.Millisecond):
	}
	// Then go quiet: it must be cut.
	select {
	case res := <-done:
		if res.Reason != "idle-timeout" {
			t.Errorf("reason %q", res.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("idle tunnel was never closed")
	}
}

func TestSpliceTotalTimeoutAndMaxBytesAndCancel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opt    SpliceOptions
		reason string
		drive  func(clientFar, upFar net.Conn)
		cancel bool
	}{
		{"total", SpliceOptions{Total: 200 * time.Millisecond}, "total-timeout", func(c, u net.Conn) {}, false},
		{"bytes", SpliceOptions{MaxBytes: 100}, "max-bytes", func(c, u net.Conn) { _, _ = c.Write(make([]byte, 500)) }, false},
		{"cancel", SpliceOptions{}, "shutdown", func(c, u net.Conn) {}, true},
	} {
		clientFar, clientNear := tcpPair(t)
		upNear, upFar := tcpPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan SpliceResult, 1)
		go func() { done <- Splice(ctx, clientNear, clientNear, upNear, tc.opt) }()
		go func() { _, _ = io.Copy(io.Discard, upFar) }()
		tc.drive(clientFar, upFar)
		if tc.cancel {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}
		select {
		case res := <-done:
			if res.Reason != tc.reason {
				t.Errorf("%s: reason %q, want %q", tc.name, res.Reason, tc.reason)
			}
			if tc.name == "bytes" && res.Up > 100 {
				t.Errorf("forwarded %d bytes past the 100 byte cap", res.Up)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: never ended", tc.name)
		}
		cancel()
	}
}
