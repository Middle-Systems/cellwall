package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/policy"
)

// Auditor records decisions. *audit.Logger satisfies it.
type Auditor interface {
	Log(audit.Record) error
}

// Config wires a Server to its collaborators.
type Config struct {
	// Policy returns the current compiled policy. It is called once per request, so a reload
	// swaps policy for new requests without disturbing connections already in flight.
	Policy   func() *policy.Compiled
	Audit    Auditor
	Resolver Resolver // default net.DefaultResolver
	// NewDial builds the dialer for a connection; default NewDialFunc. Tests substitute it.
	NewDial func(allowPrivate bool) DialFunc
	// FailOpenOnAuditError lets connections proceed when the audit log cannot be written. Off by
	// default (ADR 0005): there is no such thing as an unaudited allow unless this is set.
	FailOpenOnAuditError bool
	Logger               *slog.Logger
	Now                  func() time.Time
}

// Server is the egress proxy.
type Server struct {
	cfg     Config
	http    *http.Server
	rates   *rateLimiter
	active  atomic.Int64
	tunnels sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	plain   *http.Transport
}

// New builds a Server. Call Serve with a listener.
func New(cfg Config) *Server {
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.NewDial == nil {
		cfg.NewDial = NewDialFunc
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{cfg: cfg, rates: newRateLimiter(cfg.Now)}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.plain = newPlainTransport(s)
	s.http = &http.Server{
		Handler:           http.HandlerFunc(s.serveHTTP),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
		ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
	}
	return s
}

// Serve accepts connections on l until Shutdown or Close.
func (s *Server) Serve(l net.Listener) error {
	err := s.http.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Active returns the number of tunnels and plain requests currently in flight.
func (s *Server) Active() int { return int(s.active.Load()) }

// Shutdown stops accepting, waits for in-flight tunnels until ctx expires, then cuts the rest.
// Cut tunnels still get their close records (reason "shutdown").
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	done := make(chan struct{})
	go func() { s.tunnels.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		s.cancel()
		<-done
	}
	s.cancel()
	return err
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		s.handleConnect(w, r)
	case r.URL != nil && r.URL.IsAbs():
		s.handlePlain(w, r)
	default:
		s.refuse(w, &audit.Record{ID: newID(), Proto: "http", Src: remoteIP(r.RemoteAddr), Policy: s.policyID(s.cfg.Policy())},
			messageFor("", 0, ReasonNotProxy, ""))
	}
}

// request carries the per-request state shared by the CONNECT and plain-HTTP paths.
type request struct {
	start time.Time
	cur   *policy.Compiled
	rec   audit.Record
}

func (s *Server) newRequest(proto, remote string) *request {
	cur := s.cfg.Policy()
	return &request{
		start: s.cfg.Now(),
		cur:   cur,
		rec:   audit.Record{ID: newID(), Proto: proto, Src: remoteIP(remote), Policy: s.policyID(cur)},
	}
}

func (s *Server) policyID(c *policy.Compiled) string {
	if c == nil || len(c.Hash) < 12 {
		return ""
	}
	return c.Hash[:12]
}

// refuse writes a decision=deny record and the client-visible refusal.
func (s *Server) refuse(w http.ResponseWriter, rec *audit.Record, resp denyResponse) {
	rec.Event, rec.Action, rec.Reason = audit.EventDecision, audit.ActionDeny, resp.Reason
	s.logAudit(*rec)
	writeDeny(w, resp)
}

func writeDeny(w http.ResponseWriter, resp denyResponse) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Cellwall-Reason", resp.Reason)
	h.Set("Connection", "close")
	w.WriteHeader(resp.Status)
	_, _ = w.Write([]byte(resp.Body))
}

// logAudit writes a record whose loss does not change the outcome (denials, closes).
func (s *Server) logAudit(rec audit.Record) {
	if err := s.cfg.Audit.Log(rec); err != nil {
		s.cfg.Logger.Error("audit write failed", slog.Any("err", err), slog.String("event", rec.Event), slog.String("action", rec.Action), slog.String("host", rec.Host))
	}
}

// auditAllow records an allow decision and reports whether the connection may proceed. If the
// record cannot be written the connection is refused: no unaudited egress (ADR 0005).
func (s *Server) auditAllow(rec audit.Record) bool {
	rec.Event, rec.Action = audit.EventDecision, audit.ActionAllow
	if err := s.cfg.Audit.Log(rec); err != nil {
		s.cfg.Logger.Error("audit write failed", slog.Any("err", err), slog.String("host", rec.Host), slog.Bool("fail_open", s.cfg.FailOpenOnAuditError))
		return s.cfg.FailOpenOnAuditError
	}
	return true
}

// closeRecord ends a connection's audit trail.
func (s *Server) closeRecord(rq *request, action, reason string, up, down int64) {
	rec := rq.rec
	rec.Event, rec.Action, rec.Reason = audit.EventClose, action, reason
	rec.BytesUp, rec.BytesDown = audit.Int64(up), audit.Int64(down)
	rec.DurationMS = audit.Int64(s.cfg.Now().Sub(rq.start).Milliseconds())
	s.logAudit(rec)
}

// normalizeTarget turns a client-supplied host into a policy host, or says why it cannot.
func normalizeTarget(raw string, lim policy.EffectiveLimits) (string, *denyReason) {
	if policy.LooksLikeIP(raw) {
		return "", &denyReason{ReasonIPLiteral, ""}
	}
	host, err := policy.NormalizeHost(raw, lim.MaxHostLen, lim.MaxLabelLen)
	if err != nil {
		var he *policy.HostError
		if errors.As(err, &he) {
			return "", &denyReason{he.Code, he.Msg}
		}
		return "", &denyReason{ReasonBadTarget, err.Error()}
	}
	return host, nil
}

type denyReason struct{ Code, Detail string }

func ruleLabel(r *policy.CompiledRule) string {
	if r == nil {
		return ""
	}
	return "rules[" + itoa(r.Index) + "] " + r.Rule.Host + " (" + r.Rule.Source + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func contextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, d)
}

func remoteIP(addr string) string {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().String()
	}
	return printable(addr)
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
