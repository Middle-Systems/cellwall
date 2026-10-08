package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/proxy/proxytest"
)

// The benchmarks measure what the gateway adds to a connection on loopback: the real server, the
// real policy engine, the real dial guard and the real audit logger writing to disk. Only the
// resolver (a fixed public-looking address) and the final socket connect (redirected to a local
// upstream) are substituted, as in the functional tests. Loopback has no network latency, so the
// numbers are the proxy's own cost and are an upper bound on relative overhead.

const benchPolicy = `
version: 1
rules:
  - host: bench.example.com
limits: {max_conns: 100000, max_new_conns_per_host_per_min: 100000000}
`

type fixedResolver struct{}

func (fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// benchRig is a proxy in front of a local upstream. The upstream, per connection, first reads
// the 'mode' byte: 'e' echoes until close, 's' discards everything, 'g' streams data to the client.
type benchRig struct {
	proxyAddr, upstreamAddr string
	stop                    func()
}

func newBenchRig(tb testing.TB) *benchRig {
	tb.Helper()
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Skip("no loopback")
	}
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go serveBenchUpstream(c)
		}
	}()

	pol, err := policy.Parse("bench", []byte(benchPolicy))
	if err != nil {
		tb.Fatal(err)
	}
	comp, err := policy.Compile(pol, false)
	if err != nil {
		tb.Fatal(err)
	}
	lg, err := audit.Open(audit.Options{Dir: tb.TempDir()})
	if err != nil {
		tb.Fatal(err)
	}
	srv := New(Config{
		Policy:   func() *policy.Compiled { return comp },
		Audit:    lg,
		Resolver: fixedResolver{},
		NewDial: func(bool) DialFunc {
			return func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", up.Addr().String())
			}
		},
		Logger: slog.New(slog.DiscardHandler),
	})
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	go func() { _ = srv.Serve(pl) }()
	return &benchRig{
		proxyAddr: pl.Addr().String(), upstreamAddr: up.Addr().String(),
		stop: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			_ = up.Close()
			_ = lg.Close()
		},
	}
}

func serveBenchUpstream(c net.Conn) {
	defer func() { _ = c.Close() }()
	// The client sends a TLS record (the ClientHello the proxy inspects) and then a mode byte.
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(hdr[3])<<8|int64(hdr[4])); err != nil {
		return
	}
	mode := make([]byte, 1)
	if _, err := io.ReadFull(c, mode); err != nil {
		return
	}
	switch mode[0] {
	case 'e':
		_, _ = io.Copy(c, c)
	case 's':
		_, _ = io.Copy(io.Discard, c)
	case 'g':
		buf := make([]byte, 64<<10)
		for {
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}
}

// openTunnel performs CONNECT through the proxy and returns the tunnel plus the time to the 200.
func (r *benchRig) openTunnel() (net.Conn, *bufio.Reader, time.Duration, error) {
	c, err := net.Dial("tcp", r.proxyAddr)
	if err != nil {
		return nil, nil, 0, err
	}
	start := time.Now()
	if _, err := fmt.Fprintf(c, "CONNECT bench.example.com:443 HTTP/1.1\r\nHost: bench.example.com:443\r\n\r\n"); err != nil {
		_ = c.Close()
		return nil, nil, 0, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	d := time.Since(start)
	if err != nil || resp.StatusCode != 200 {
		_ = c.Close()
		return nil, nil, 0, fmt.Errorf("CONNECT failed: %w (%v)", err, resp)
	}
	return c, br, d, nil
}

// tunnelFirstByte measures CONNECT + ClientHello + first echoed byte, the cost a client feels
// before its first byte of application data can flow.
func (r *benchRig) tunnelFirstByte() (time.Duration, error) {
	start := time.Now()
	c, br, _, err := r.openTunnel()
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(append(proxytest.Records(proxytest.HelloOpts{SNI: "bench.example.com"}), 'e', 'x')); err != nil {
		return 0, err
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(br, b); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func (r *benchRig) directFirstByte() (time.Duration, error) {
	start := time.Now()
	c, err := net.Dial("tcp", r.upstreamAddr)
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(append(proxytest.Records(proxytest.HelloOpts{SNI: "bench.example.com"}), 'e', 'x')); err != nil {
		return 0, err
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

func percentile(ds []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func sample(n int, f func() (time.Duration, error)) ([]time.Duration, error) {
	// Warm up: dial paths, goroutine stacks, the audit file.
	for i := 0; i < 50; i++ {
		if _, err := f(); err != nil {
			return nil, err
		}
	}
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		d, err := f()
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// BenchmarkConnectSetup reports p50/p99 time from sending CONNECT to receiving 200, and the
// time to the first byte through the tunnel, each next to the same measurement with no proxy.
func BenchmarkConnectSetup(b *testing.B) {
	r := newBenchRig(b)
	defer r.stop()
	setup, err := sample(b.N, func() (time.Duration, error) {
		c, _, d, err := r.openTunnel()
		if err == nil {
			_ = c.Close()
		}
		return d, err
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(percentile(setup, 0.5).Microseconds()), "p50-connect-µs")
	b.ReportMetric(float64(percentile(setup, 0.99).Microseconds()), "p99-connect-µs")
}

// BenchmarkFirstByte compares time to first echoed byte through the proxy and directly.
func BenchmarkFirstByte(b *testing.B) {
	r := newBenchRig(b)
	defer r.stop()
	via, err := sample(b.N, r.tunnelFirstByte)
	if err != nil {
		b.Fatal(err)
	}
	direct, err := sample(b.N, r.directFirstByte)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(percentile(via, 0.5).Microseconds()), "p50-proxied-µs")
	b.ReportMetric(float64(percentile(via, 0.99).Microseconds()), "p99-proxied-µs")
	b.ReportMetric(float64(percentile(direct, 0.5).Microseconds()), "p50-direct-µs")
	b.ReportMetric(float64(percentile(direct, 0.99).Microseconds()), "p99-direct-µs")
}

// transfer moves total bytes in one direction and returns bytes per second.
func (r *benchRig) transfer(viaProxy, download bool, total int64) (float64, error) {
	var c net.Conn
	var rd io.Reader
	var err error
	if viaProxy {
		var br *bufio.Reader
		c, br, _, err = r.openTunnel()
		rd = br
	} else {
		c, err = net.Dial("tcp", r.upstreamAddr)
		rd = c
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = c.Close() }()
	hello := proxytest.Records(proxytest.HelloOpts{SNI: "bench.example.com"})
	mode := byte('s')
	if download {
		mode = 'g'
	}
	start := time.Now()
	if _, err := c.Write(append(hello, mode)); err != nil {
		return 0, err
	}
	buf := make([]byte, 64<<10)
	if download {
		var got int64
		for got < total {
			n, err := rd.Read(buf)
			got += int64(n)
			if err != nil {
				return 0, err
			}
		}
	} else {
		var sent int64
		for sent < total {
			n, err := c.Write(buf)
			sent += int64(n)
			if err != nil {
				return 0, err
			}
		}
		// Half-close and wait for the far side so the bytes were really delivered.
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
			_, _ = io.Copy(io.Discard, rd)
		}
	}
	return float64(total) / time.Since(start).Seconds(), nil
}

func benchThroughput(b *testing.B, download bool) {
	r := newBenchRig(b)
	defer r.stop()
	const total = 256 << 20
	b.SetBytes(total)
	for i := 0; i < b.N; i++ {
		bps, err := r.transfer(true, download, total)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(bps/1e6, "MB/s")
	}
}

func BenchmarkThroughputUpload(b *testing.B)   { benchThroughput(b, false) }
func BenchmarkThroughputDownload(b *testing.B) { benchThroughput(b, true) }

// TestProxyOverheadBudget fails on large regressions. The limits are deliberately generous (an
// order of magnitude above what a loaded CI runner measures) so only a real regression trips them:
// an accidental O(n) per connection, a lock held across a dial, a copy loop with tiny buffers.
// It is skipped under the race detector, which slows everything several-fold; CI runs it in its own
// non-race step (`make bench-check`).
func TestProxyOverheadBudget(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("overhead budget needs a non-race, non-short run")
	}
	r := newBenchRig(t)
	defer r.stop()

	via, err := sample(400, r.tunnelFirstByte)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := sample(400, r.directFirstByte)
	if err != nil {
		t.Fatal(err)
	}
	p50, p99 := percentile(via, 0.5), percentile(via, 0.99)
	t.Logf("first byte through proxy: p50=%s p99=%s; direct: p50=%s p99=%s",
		p50, p99, percentile(direct, 0.5), percentile(direct, 0.99))
	if added := p50 - percentile(direct, 0.5); added > 20*time.Millisecond {
		t.Errorf("the proxy adds %s at p50 on loopback (budget 20ms)", added)
	}
	if p99 > 150*time.Millisecond {
		t.Errorf("p99 first byte through the proxy is %s (budget 150ms)", p99)
	}

	const total = 128 << 20
	for _, dir := range []struct {
		name     string
		download bool
	}{{"upload", false}, {"download", true}} {
		proxied, err := r.transfer(true, dir.download, total)
		if err != nil {
			t.Fatal(err)
		}
		base, err := r.transfer(false, dir.download, total)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: proxied %.0f MB/s, direct %.0f MB/s (%.0f%%)", dir.name, proxied/1e6, base/1e6, 100*proxied/base)
		if proxied/1e6 < 100 {
			t.Errorf("%s through the proxy: %.0f MB/s (floor 100)", dir.name, proxied/1e6)
		}
		if proxied < base*0.15 {
			t.Errorf("%s through the proxy is %.0f%% of direct (floor 15%%)", dir.name, 100*proxied/base)
		}
	}
}
