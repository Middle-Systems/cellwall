// Package forward is the gateway's inbound TCP forwarder for dev-server previews.
//
// Docker does not publish ports of containers that sit only on an internal network, so a preview
// is published on the gateway (127.0.0.1 on the host) and relayed here to the agent over the
// sandbox network (docs/spikes.md S3). The forwarder must never become an outbound path, so:
//
//   - the upstream HOST is fixed at start-up (the agent's service name) and nothing a client
//     sends can change it: this is a byte relay, it parses nothing;
//   - the upstream PORT is the listening port itself (a forwarded port maps to the same port);
//   - the name is resolved on every connection and every address must be private (RFC 1918, ULA,
//     CGNAT): if the name ever resolved to a public address the connection is refused.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults.
const (
	DefaultMaxConns    = 128
	DefaultDialTimeout = 5 * time.Second
)

// Config configures a Forwarder.
type Config struct {
	Ports  []int  // ports to listen on and forward to the same port upstream
	Target string // fixed upstream host name, e.g. "agent"
	// Bind is the address to listen on inside the gateway container ("" = all interfaces; the
	// host-side exposure is decided by how compose publishes the port).
	Bind        string
	MaxConns    int
	DialTimeout time.Duration
	Logger      *slog.Logger
	// Lookup resolves Target; nil uses the system resolver (Docker's embedded DNS in a container).
	Lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	// OnListening receives the bound address of each listener (tests use ephemeral ports).
	OnListening func(requested int, addr net.Addr)
}

// Forwarder relays connections.
type Forwarder struct {
	cfg    Config
	sem    chan struct{}
	active atomic.Int64
	// dial connects to a vetted address. It is a field only so in-package tests can redirect it to
	// loopback; nothing outside this package can set it.
	dial func(ctx context.Context, addr string) (net.Conn, error)
}

// New validates the configuration.
func New(cfg Config) (*Forwarder, error) {
	if cfg.Target == "" {
		return nil, errors.New("forward: a fixed upstream target is required")
	}
	if len(cfg.Ports) == 0 {
		return nil, errors.New("forward: no ports to forward")
	}
	seen := map[int]bool{}
	for _, p := range cfg.Ports {
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("forward: invalid port %d", p)
		}
		if p != 0 && seen[p] {
			return nil, fmt.Errorf("forward: port %d listed twice", p)
		}
		seen[p] = true
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Lookup == nil {
		cfg.Lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	f := &Forwarder{cfg: cfg, sem: make(chan struct{}, cfg.MaxConns)}
	f.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return f, nil
}

// Active reports the number of relayed connections right now.
func (f *Forwarder) Active() int { return int(f.active.Load()) }

// Run listens on every port and blocks until ctx is cancelled or a listener fails.
func (f *Forwarder) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var lc net.ListenConfig
	var lns []net.Listener
	for _, p := range f.cfg.Ports {
		ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(f.cfg.Bind, strconv.Itoa(p)))
		if err != nil {
			for _, l := range lns {
				_ = l.Close()
			}
			return fmt.Errorf("forward: listen on port %d: %w", p, err)
		}
		lns = append(lns, ln)
		if f.cfg.OnListening != nil {
			f.cfg.OnListening(p, ln.Addr())
		}
	}

	var wg sync.WaitGroup
	errc := make(chan error, len(lns))
	for i, ln := range lns {
		wg.Add(1)
		go func(ln net.Listener, port int) {
			defer wg.Done()
			errc <- f.serve(ctx, ln, port)
		}(ln, f.cfg.Ports[i])
	}
	go func() {
		<-ctx.Done()
		for _, ln := range lns {
			_ = ln.Close()
		}
	}()

	err := <-errc
	cancel()
	wg.Wait()
	if ctx.Err() != nil && (err == nil || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func (f *Forwarder) serve(ctx context.Context, ln net.Listener, port int) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil //nolint:nilerr // the listener was closed on purpose during shutdown
			}
			return fmt.Errorf("forward: accept on port %d: %w", port, err)
		}
		select {
		case f.sem <- struct{}{}:
		default:
			f.cfg.Logger.Warn("forward: at capacity, refusing connection", slog.Int("port", port))
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-f.sem }()
			f.relay(ctx, c, port)
		}()
	}
}

func (f *Forwarder) relay(ctx context.Context, client net.Conn, port int) {
	f.active.Add(1)
	defer f.active.Add(-1)
	defer func() { _ = client.Close() }()

	up, err := f.connect(ctx, port)
	if err != nil {
		f.cfg.Logger.Warn("forward: upstream unavailable", slog.Int("port", port), slog.Any("err", err))
		return
	}
	defer func() { _ = up.Close() }()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		// Pass the half-close on so a client that finished sending still gets the response.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, client)
	go pipe(client, up)
	select {
	case <-done:
		<-done
	case <-ctx.Done():
	}
}

// connect resolves the fixed target, refuses non-private addresses, and connects to the vetted IP.
func (f *Forwarder) connect(ctx context.Context, port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, f.cfg.DialTimeout)
	defer cancel()
	addrs, err := f.cfg.Lookup(ctx, f.cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", f.cfg.Target, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", f.cfg.Target)
	}
	for _, a := range addrs {
		if !private(a.Unmap()) {
			return nil, fmt.Errorf("%s resolves to %s, which is not a private address: refusing to forward", f.cfg.Target, a)
		}
	}
	var lastErr error
	for _, a := range addrs {
		c, err := f.dial(ctx, net.JoinHostPort(a.Unmap().String(), strconv.Itoa(port)))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// private reports whether a is an address a Docker network would use: RFC 1918, ULA or CGNAT.
// Loopback is deliberately not accepted: that would point the relay at the gateway itself.
func private(a netip.Addr) bool {
	return a.IsPrivate() || cgnat.Contains(a)
}
