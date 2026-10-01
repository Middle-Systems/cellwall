package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/policy"
)

// dialInfo carries the addresses vetted for THIS request to the transport's dialer, so the
// connection is made to exactly the IPs the guard approved and never to a fresh lookup.
type dialInfo struct {
	addrs        []netip.Addr
	allowPrivate bool
}

type dialInfoKey struct{}

func newPlainTransport(s *Server) *http.Transport {
	return &http.Transport{
		Proxy: nil, // never chain through an environment proxy
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			di, ok := ctx.Value(dialInfoKey{}).(*dialInfo)
			if !ok {
				return nil, errors.New("refusing to dial without vetted addresses")
			}
			_, p, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			c, _, err := DialAddrs(ctx, s.cfg.NewDial(di.allowPrivate), di.addrs, port)
			return c, err
		},
		DisableCompression:     true, // forward Accept-Encoding untouched; do not rewrite bodies
		DisableKeepAlives:      true, // every request is resolved, vetted and dialed afresh
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// hopByHop headers are meaningful for a single connection only and must not be forwarded.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	// Headers named by Connection are hop-by-hop too.
	for _, v := range h["Connection"] {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// handlePlain forwards an absolute-form plain-HTTP request. It is denied unless a rule sets
// unsafe_allow_http, and otherwise follows the same pipeline as CONNECT.
func (s *Server) handlePlain(w http.ResponseWriter, r *http.Request) {
	rq := s.newRequest("http", r.RemoteAddr)
	lim := rq.cur.Limits

	if r.URL.Scheme != "http" {
		rq.rec.Host = printable(r.URL.Host)
		s.refuse(w, &rq.rec, messageFor("", 0, ReasonBadScheme, ""))
		return
	}
	rawHost := r.URL.Hostname()
	port := 80
	if p := r.URL.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			rq.rec.Host = printable(rawHost)
			s.refuse(w, &rq.rec, messageFor("", 0, ReasonBadTarget, "invalid port"))
			return
		}
		port = n
	}
	rq.rec.Host, rq.rec.Port = printable(rawHost), port
	if r.URL.User != nil {
		s.refuse(w, &rq.rec, messageFor("", 0, ReasonBadTarget, "userinfo is not allowed"))
		return
	}

	host, dr := normalizeTarget(rawHost, lim)
	if dr != nil {
		resp := messageFor(rawHost, port, dr.Code, dr.Detail)
		if dr.Code != ReasonIPLiteral {
			resp = messageFor(rawHost, port, ReasonBadTarget, dr.Detail)
			resp.Reason = dr.Code
		}
		s.refuse(w, &rq.rec, resp)
		return
	}
	rq.rec.Host = host
	if rq.rec.Suspicious = Suspicious(host); rq.rec.Suspicious && lim.DenySuspicious {
		s.refuse(w, &rq.rec, messageFor(host, port, ReasonSuspicious, ""))
		return
	}
	// Upgrades turn the request into an opaque tunnel the gateway cannot inspect.
	if r.Header.Get("Upgrade") != "" || headerHasToken(r.Header, "Connection", "upgrade") {
		s.refuse(w, &rq.rec, messageFor(host, port, ReasonUpgrade, ""))
		return
	}

	dec := rq.cur.Match(host, port, policy.ProtoHTTP)
	rq.rec.Rule = ruleLabel(dec.Rule)
	if !dec.Allowed {
		detail := ""
		if dec.Rule != nil {
			detail = ruleLabel(dec.Rule)
		}
		s.refuse(w, &rq.rec, messageFor(host, port, dec.Reason, detail))
		return
	}
	rule := dec.Rule.Rule

	if !s.rates.Allow(host, lim.MaxNewConnsPerHostPerMin) {
		s.refuse(w, &rq.rec, messageFor(host, port, ReasonRateLimited, ""))
		return
	}
	if n := s.active.Add(1); lim.MaxConns > 0 && n > int64(lim.MaxConns) {
		s.active.Add(-1)
		s.refuse(w, &rq.rec, messageFor(host, port, ReasonAtCapacity, ""))
		return
	}
	defer s.active.Add(-1)
	s.tunnels.Add(1)
	defer s.tunnels.Done()

	ctx, cancel := contextWithTimeout(r.Context(), lim.TotalTimeout)
	defer cancel()
	rctx, rcancel := contextWithTimeout(ctx, lim.DialTimeout)
	addrs, err := Resolve(rctx, s.cfg.Resolver, host, rule.UnsafeAllowPrivate)
	rcancel()
	if err != nil {
		var be *BlockedError
		if errors.As(err, &be) {
			s.refuse(w, &rq.rec, messageFor(host, port, ReasonBlockedAddress, be.Reason+" "+be.Addr.String()))
			return
		}
		s.errorOut(w, rq, host, port, ReasonResolveFailed, err)
		return
	}
	if !s.auditAllow(rq.rec) {
		writeDeny(w, messageFor(host, port, ReasonAuditUnavailable, ""))
		return
	}

	body := &countingReader{r: r.Body}
	out := r.Clone(context.WithValue(ctx, dialInfoKey{}, &dialInfo{addrs: addrs, allowPrivate: rule.UnsafeAllowPrivate}))
	out.RequestURI = ""
	out.Host = r.URL.Host // the URL decides the destination; a conflicting Host header is discarded
	out.Body = body
	out.Header = r.Header.Clone()
	stripHopByHop(out.Header)

	rt := s.plain.Clone()
	rt.ResponseHeaderTimeout = lim.IdleTimeout
	resp, err := rt.RoundTrip(out)
	if err != nil {
		s.cfg.Logger.Warn("plain http upstream failed", slog.String("host", host), slog.Any("err", err))
		s.closeRecord(rq, audit.ActionError, ReasonDialFailed, body.n.Load(), 0)
		writeDeny(w, messageFor(host, port, ReasonDialFailed, ""))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	stripHopByHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	var down int64
	reason := "closed"
	limit := lim.MaxBytesPerConn
	if limit > 0 {
		limit -= body.n.Load()
		if limit < 0 {
			limit = 0
		}
	}
	var src io.Reader = resp.Body
	if lim.MaxBytesPerConn > 0 {
		src = io.LimitReader(resp.Body, limit+1)
	}
	n, cerr := io.Copy(w, src)
	down = n
	switch {
	case lim.MaxBytesPerConn > 0 && n > limit:
		down = limit
		reason = "max-bytes"
	case cerr != nil:
		reason = "downstream-error"
	}
	s.closeRecord(rq, audit.ActionAllow, reason, body.n.Load(), down)
}

type countingReader struct {
	r io.ReadCloser
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.r == nil {
		return 0, io.EOF
	}
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingReader) Close() error {
	if c.r == nil {
		return nil
	}
	return c.r.Close()
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h[http.CanonicalHeaderKey(name)] {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

var _ = time.Second // keep time imported for future per-request deadlines
