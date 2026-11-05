package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Resolver looks up addresses for a hostname. net.DefaultResolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// maxAddrs bounds how many addresses of one name are considered, so a name with thousands of
// records cannot stall a connection or hide one bad address among many.
const maxAddrs = 16

// BlockedError means a hostname resolved to an address the guard refuses.
type BlockedError struct {
	Host   string
	Addr   netip.Addr
	Reason string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("%s resolves to %s, a non-public address (%s)", e.Host, e.Addr, e.Reason)
}

// ResolveError wraps a lookup failure.
type ResolveError struct {
	Host string
	Err  error
}

func (e *ResolveError) Error() string { return fmt.Sprintf("could not resolve %s: %v", e.Host, e.Err) }
func (e *ResolveError) Unwrap() error { return e.Err }

// Resolve looks the name up exactly once and validates EVERY address it returned. If any one is
// blocked the whole connection is refused (not just that address): a name that mixes public and
// internal addresses is either misconfigured or an attempt to exploit round-robin selection.
//
// Dotted names are looked up fully qualified (trailing dot): that bypasses the host's DNS search
// domains and /etc/hosts, so "registry.npmjs.org" can never be rewritten to
// "registry.npmjs.org.some.internal.corp" or pinned by a hosts entry. Go's resolver does not
// consult /etc/hosts for rooted names, which is the point.
//
// Single-label names ("upstream", "localhost") are looked up as written, because search domains,
// Docker service aliases and hosts entries are exactly how such names are meant to resolve. The
// address checks below apply either way.
func Resolve(ctx context.Context, r Resolver, host string, allowPrivate bool) ([]netip.Addr, error) {
	query := host
	if strings.Contains(host, ".") {
		query = host + "."
	}
	addrs, err := r.LookupNetIP(ctx, "ip", query)
	if err != nil {
		return nil, &ResolveError{Host: host, Err: err}
	}
	if len(addrs) == 0 {
		return nil, &ResolveError{Host: host, Err: errors.New("no addresses")}
	}
	if len(addrs) > maxAddrs {
		addrs = addrs[:maxAddrs]
	}
	out := make([]netip.Addr, 0, len(addrs))
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		a = a.WithZone("").Unmap()
		if v := Classify(a); v.Blocked(allowPrivate) {
			return nil, &BlockedError{Host: host, Addr: a, Reason: v.Reason}
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// DialFunc is how a connection is made to an IP literal. Tests replace it.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewDialFunc returns a dialer that re-validates the final socket address in the kernel's
// connect path (net.Dialer.Control). Resolve already vetted the addresses; this makes the guard
// hold even if a future code path hands the dialer an unvetted one.
func NewDialFunc(allowPrivate bool) DialFunc {
	d := &net.Dialer{
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("refusing to dial non-literal address %q", address)
			}
			if v := Classify(ap.Addr()); v.Blocked(allowPrivate) {
				return fmt.Errorf("refusing to dial %s (%s)", ap.Addr(), v.Reason)
			}
			return nil
		},
	}
	return d.DialContext
}

// DialAddrs connects to the first address that answers. Addresses are IP literals, so no further
// DNS lookup can happen between the policy check and the connection (no rebinding window).
func DialAddrs(ctx context.Context, dial DialFunc, addrs []netip.Addr, port int) (net.Conn, netip.Addr, error) {
	var firstErr error
	for _, a := range addrs {
		c, err := dial(ctx, "tcp", netip.AddrPortFrom(a, uint16(port)).String()) // #nosec G115 -- port validated 1-65535
		if err == nil {
			return c, a, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no addresses to dial")
	}
	return nil, netip.Addr{}, firstErr
}
