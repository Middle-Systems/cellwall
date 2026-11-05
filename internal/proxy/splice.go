package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// SpliceOptions bound one tunnel. Zero values disable the limit.
type SpliceOptions struct {
	Idle     time.Duration // no bytes in either direction for this long
	Total    time.Duration // wall-clock cap on the whole tunnel
	MaxBytes int64         // bytes read in both directions combined
}

// SpliceResult reports what moved and why the tunnel ended.
type SpliceResult struct {
	Up     int64  // client -> upstream bytes forwarded
	Down   int64  // upstream -> client bytes forwarded
	Reason string // "closed", "idle-timeout", "total-timeout", "max-bytes", "shutdown", or "<dir>-error"
}

// Splice copies bytes both ways between the client and the upstream until either side finishes
// or a limit trips. clientR is the reader to use for client data (the buffered reader returned by
// Hijack may hold bytes already read from the socket). Both connections are closed on return.
func Splice(ctx context.Context, client net.Conn, clientR io.Reader, upstream net.Conn, opt SpliceOptions) SpliceResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		up, down, total atomic.Int64
		lastActive      atomic.Int64
		reasonMu        sync.Mutex
		reason          string
	)
	lastActive.Store(time.Now().UnixNano())
	fail := func(r string) {
		reasonMu.Lock()
		if reason == "" {
			reason = r
		}
		reasonMu.Unlock()
		cancel()
	}
	if opt.Total > 0 {
		t := time.AfterFunc(opt.Total, func() { fail("total-timeout") })
		defer t.Stop()
	}
	// Closing both ends unblocks any pending Read/Write in the pumps.
	closed := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = upstream.Close()
		close(closed)
	}()

	pump := func(dst net.Conn, src io.Reader, srcConn net.Conn, counter *atomic.Int64, dir string) {
		buf := make([]byte, 32<<10)
		for {
			if opt.Idle > 0 {
				_ = srcConn.SetReadDeadline(time.Now().Add(opt.Idle))
			}
			n, err := src.Read(buf)
			if n > 0 {
				lastActive.Store(time.Now().UnixNano())
				if opt.MaxBytes > 0 && total.Add(int64(n)) > opt.MaxBytes {
					fail("max-bytes")
					return
				}
				if opt.Idle > 0 {
					_ = dst.SetWriteDeadline(time.Now().Add(opt.Idle))
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					fail(dir + "-error")
					return
				}
				counter.Add(int64(n))
			}
			if err == nil {
				continue
			}
			switch {
			case errors.Is(err, io.EOF):
				// This direction is finished; tell the peer, and let the other direction drain.
				if cw, ok := dst.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			case errors.Is(err, os.ErrDeadlineExceeded):
				// The other direction may still be busy: idle means BOTH are quiet.
				if time.Since(time.Unix(0, lastActive.Load())) < opt.Idle {
					continue
				}
				fail("idle-timeout")
			case ctx.Err() != nil:
				// closed by fail() or shutdown; reason already recorded
			default:
				fail(dir + "-error")
			}
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(upstream, clientR, client, &up, "client") }()
	go func() { defer wg.Done(); pump(client, upstream, upstream, &down, "upstream") }()
	wg.Wait()

	reasonMu.Lock()
	r := reason
	reasonMu.Unlock()
	if r == "" {
		if ctx.Err() != nil {
			r = "shutdown" // parent context cancelled
		} else {
			r = "closed"
		}
	}
	cancel()
	<-closed
	return SpliceResult{Up: up.Load(), Down: down.Load(), Reason: r}
}
