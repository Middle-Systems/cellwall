package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	err     error
	calls   []string
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, host)
	if f.err != nil {
		return nil, f.err
	}
	return f.answers[strings.TrimSuffix(host, ".")], nil
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestResolveAllowsPublic(t *testing.T) {
	r := &fakeResolver{answers: map[string][]netip.Addr{"ok.example": addrs("93.184.216.34", "2606:2800:220:1::1", "93.184.216.34")}}
	got, err := Resolve(context.Background(), r, "ok.example", false)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v, %v (duplicates must be removed)", got, err)
	}
	if len(r.calls) != 1 || r.calls[0] != "ok.example." {
		t.Errorf("must look up once, fully qualified: %v", r.calls)
	}
}

func TestResolveBlocksAnyBadAddress(t *testing.T) {
	// One internal address hidden among public ones must sink the whole connection.
	r := &fakeResolver{answers: map[string][]netip.Addr{
		"mixed.example":    addrs("93.184.216.34", "10.0.0.5"),
		"meta.example":     addrs("169.254.169.254"),
		"loop.example":     addrs("127.0.0.1"),
		"loop6.example":    addrs("::1"),
		"mapped.example":   addrs("::ffff:127.0.0.1"),
		"nat64.example":    addrs("64:ff9b::a00:1"),
		"zero.example":     addrs("0.0.0.0"),
		"rebind.example":   addrs("1.2.3.4", "192.168.1.1"),
		"ula.example":      addrs("fd00::1"),
		"linklocal.123456": addrs("fe80::1"),
	}}
	for name := range r.answers {
		_, err := Resolve(context.Background(), r, name, false)
		var be *BlockedError
		if !errors.As(err, &be) {
			t.Errorf("%s: want BlockedError, got %v", name, err)
		}
	}
}

func TestResolveAllowPrivateOnlyRelaxesPrivate(t *testing.T) {
	r := &fakeResolver{answers: map[string][]netip.Addr{
		"internal.example": addrs("10.1.2.3"),
		"cgnat.example":    addrs("100.64.1.1"),
		"loop.example":     addrs("127.0.0.1"),
		"meta.example":     addrs("169.254.169.254"),
		"zero.example":     addrs("0.0.0.0"),
		"mcast.example":    addrs("224.0.0.1"),
	}}
	for _, name := range []string{"internal.example", "cgnat.example"} {
		if _, err := Resolve(context.Background(), r, name, true); err != nil {
			t.Errorf("%s should pass with allowPrivate: %v", name, err)
		}
	}
	for _, name := range []string{"loop.example", "meta.example", "zero.example", "mcast.example"} {
		if _, err := Resolve(context.Background(), r, name, true); err == nil {
			t.Errorf("%s must stay blocked even with allowPrivate", name)
		}
	}
}

func TestResolveFailures(t *testing.T) {
	r := &fakeResolver{err: errors.New("nxdomain")}
	_, err := Resolve(context.Background(), r, "nope.example", false)
	var re *ResolveError
	if !errors.As(err, &re) {
		t.Fatalf("got %v", err)
	}
	r = &fakeResolver{answers: map[string][]netip.Addr{}}
	if _, err := Resolve(context.Background(), r, "empty.example", false); err == nil {
		t.Fatal("empty answer must fail")
	}
}

func TestResolveCapsAddressCount(t *testing.T) {
	var many []netip.Addr
	for i := 0; i < 100; i++ {
		many = append(many, netip.AddrFrom4([4]byte{93, 184, byte(i), 1}))
	}
	// A blocked address beyond the cap is never examined or dialed.
	many = append(many, netip.MustParseAddr("10.0.0.1"))
	r := &fakeResolver{answers: map[string][]netip.Addr{"big.example": many}}
	got, err := Resolve(context.Background(), r, "big.example", false)
	if err != nil || len(got) != maxAddrs {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
}

func TestNewDialFuncRefusesBlockedAtConnectTime(t *testing.T) {
	// Independent of Resolve: the kernel-level hook refuses blocked literals.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener")
	}
	defer ln.Close()
	_, err = NewDialFunc(false)(context.Background(), "tcp", ln.Addr().String())
	if err == nil || !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("loopback must be refused by Control: %v", err)
	}
	_, err = NewDialFunc(true)(context.Background(), "tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("loopback must be refused even with allowPrivate")
	}
	// Hostnames are never accepted: the dial path must not do its own lookup.
	if _, err := NewDialFunc(false)(context.Background(), "tcp", "localhost:80"); err == nil {
		t.Fatal("hostname dial must fail")
	}
}

func TestDialAddrsFallsThroughAndReportsFirstError(t *testing.T) {
	var tried []string
	dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
		tried = append(tried, address)
		if strings.HasPrefix(address, "1.1.1.1") {
			return nil, errors.New("first failed")
		}
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	c, got, err := DialAddrs(context.Background(), dial, addrs("1.1.1.1", "8.8.8.8"), 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got.String() != "8.8.8.8" || strings.Join(tried, ",") != "1.1.1.1:443,8.8.8.8:443" {
		t.Errorf("got %v tried %v", got, tried)
	}
	// IPv6 literals are bracketed.
	tried = nil
	_, _, _ = DialAddrs(context.Background(), func(_ context.Context, _, a string) (net.Conn, error) {
		tried = append(tried, a)
		return nil, errors.New("x")
	}, addrs("2606:4700::1111"), 443)
	if len(tried) != 1 || tried[0] != "[2606:4700::1111]:443" {
		t.Errorf("tried %v", tried)
	}
	_, _, err = DialAddrs(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("boom")
	}, addrs("1.1.1.1"), 443)
	if err == nil || err.Error() != "boom" {
		t.Errorf("err = %v", err)
	}
}

func TestDialAddrsStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	n := 0
	_, _, err := DialAddrs(ctx, func(ctx context.Context, _, _ string) (net.Conn, error) {
		n++
		<-ctx.Done()
		return nil, ctx.Err()
	}, addrs("1.1.1.1", "8.8.8.8", "9.9.9.9"), 443)
	if err == nil || n != 1 {
		t.Errorf("err=%v attempts=%d; must stop after the context expires", err, n)
	}
}
