package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

var agentAddr = []netip.Addr{netip.MustParseAddr("10.20.0.2")}

func lookupAgent(context.Context, string) ([]netip.Addr, error) { return agentAddr, nil }

// echoServer greets, then echoes; it records the addresses it was dialled at via the forwarder.
func echoServer(t *testing.T, greeting string) *net.TCPAddr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(greeting))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// running starts a forwarder on an ephemeral loopback port whose vetted dial is redirected to up.
// dialed collects the addresses the forwarder tried to reach (what it believed was the agent).
func running(t *testing.T, up *net.TCPAddr, lookup func(context.Context, string) ([]netip.Addr, error), maxConns int) (addr string, f *Forwarder, dialed func() []string) {
	t.Helper()
	f, err := New(Config{Ports: []int{0}, Target: "agent", Bind: "127.0.0.1", Lookup: lookup, MaxConns: maxConns})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []string
	f.dial = func(ctx context.Context, a string) (net.Conn, error) {
		mu.Lock()
		got = append(got, a)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.String())
	}
	ready := make(chan net.Addr, 1)
	f.cfg.OnListening = func(_ int, a net.Addr) { ready <- a }
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- f.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancellation")
		}
	})
	select {
	case a := <-ready:
		return a.String(), f, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), got...) }
	case err := <-errc:
		t.Fatalf("forwarder failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder did not start")
	}
	return "", nil, nil
}

func TestValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no target": {Ports: []int{8080}},
		"no ports":  {Target: "agent"},
		"dup ports": {Ports: []int{8080, 8080}, Target: "agent"},
		"bad port":  {Ports: []int{70000}, Target: "agent"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestPrivateAddressClassification(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "172.18.0.5", "192.168.1.1", "100.64.0.9", "fd00::1"} {
		if !private(netip.MustParseAddr(s)) {
			t.Errorf("%s should be accepted as a Docker network address", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "127.0.0.1", "::1", "169.254.169.254", "2606:4700::1111", "0.0.0.0"} {
		if private(netip.MustParseAddr(s)) {
			t.Errorf("%s must not be accepted: forwarding there would be an outbound or local path", s)
		}
	}
	if private(netip.MustParseAddr("::ffff:8.8.8.8").Unmap()) {
		t.Error("an IPv4-mapped public address was accepted")
	}
}

func TestRelayCarriesBytesBothWaysAndHalfClose(t *testing.T) {
	up := echoServer(t, "hello\n")
	addr, _, dialed := running(t, up, lookupAgent, 0)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello\n" {
		t.Fatalf("greeting = %q, %v", buf, err)
	}
	_, _ = conn.Write([]byte("ping"))
	_ = conn.(*net.TCPConn).CloseWrite() // the client is done sending; the reply must still arrive
	rest, err := io.ReadAll(conn)
	if err != nil || string(rest) != "ping" {
		t.Fatalf("echo = %q, %v", rest, err)
	}
	// The forwarder dialled the vetted address of the fixed target, not anything from the stream.
	if d := dialed(); len(d) != 1 || !strings.HasPrefix(d[0], "10.20.0.2:") {
		t.Errorf("dialled %v", d)
	}
}

func TestWhatTheClientSendsCannotChooseTheUpstream(t *testing.T) {
	up := echoServer(t, "")
	addr, _, dialed := running(t, up, lookupAgent, 0)
	for _, payload := range []string{
		"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n",
		"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
		"\x16\x03\x01\x00\x05hello",
	} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte(payload))
		_ = c.(*net.TCPConn).CloseWrite()
		_, _ = io.ReadAll(c)
		_ = c.Close()
	}
	for _, d := range dialed() {
		if !strings.HasPrefix(d, "10.20.0.2:") {
			t.Errorf("the forwarder dialled %s because of client bytes", d)
		}
	}
	if len(dialed()) != 3 {
		t.Errorf("dialled %v", dialed())
	}
}

func TestPublicUpstreamIsRefusedAndNeverDialled(t *testing.T) {
	up := echoServer(t, "should-not-be-reached")
	addr, _, dialed := running(t, up, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("93.184.216.34")}, nil // split-horizon style
	}, 0)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	if len(b) != 0 {
		t.Errorf("data came back from a refused upstream: %q", b)
	}
	if len(dialed()) != 0 {
		t.Errorf("the forwarder dialled %v", dialed())
	}
}

func TestResolutionFailureClosesTheClient(t *testing.T) {
	up := echoServer(t, "x")
	addr, _, dialed := running(t, up, func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("nxdomain") }, 0)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if b, _ := io.ReadAll(c); len(b) != 0 || len(dialed()) != 0 {
		t.Errorf("got %q, dialled %v", b, dialed())
	}
}

func TestCapacityLimit(t *testing.T) {
	up := echoServer(t, "hi")
	addr, f, _ := running(t, up, lookupAgent, 1)

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	b := make([]byte, 2)
	_ = first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(first, b); err != nil {
		t.Fatalf("first connection: %v", err)
	}
	if f.Active() != 1 {
		t.Errorf("active = %d", f.Active())
	}

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	if got, _ := io.ReadAll(second); len(got) != 0 {
		t.Errorf("a connection over capacity was served: %q", got)
	}
}

func TestRunReportsAPortThatCannotBeBound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	port := ln.Addr().(*net.TCPAddr).Port
	f, _ := New(Config{Ports: []int{port}, Target: "agent", Bind: "127.0.0.1", Lookup: lookupAgent})
	if err := f.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("got %v", err)
	}
}
