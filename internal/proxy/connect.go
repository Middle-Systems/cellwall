package proxy

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/middle-systems/kennel/internal/audit"
	"github.com/middle-systems/kennel/internal/policy"
)

const connectEstablished = "HTTP/1.1 200 Connection Established\r\n\r\n"

// handleConnect serves an HTTP CONNECT tunnel. The order of operations is the security design:
//
//  1. parse and normalize the target, refuse IP literals and malformed names
//  2. consult policy using only the NAME — nothing is resolved or dialed yet
//  3. check rate and capacity limits
//  4. resolve once and vet every address (SSRF guard)
//  5. write the allow decision to the audit log (refuse if it cannot be written)
//  6. connect to a vetted IP literal (no second lookup: no rebinding window)
//  7. send 200, then check the client's TLS ClientHello against the CONNECT host
//  8. splice with idle/total/byte limits, then write the close record
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	rq := s.newRequest("connect", r.RemoteAddr)
	lim := rq.cur.Limits

	rawHost, port, err := ParseConnectTarget(r.RequestURI)
	if err != nil {
		rq.rec.Host = printable(r.RequestURI)
		s.refuse(w, &rq.rec, messageFor("", 0, ReasonBadTarget, err.Error()))
		return
	}
	rq.rec.Host, rq.rec.Port = printable(rawHost), port

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

	dec := rq.cur.Match(host, port, policy.ProtoTunnel)
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

	ctx, cancel := contextWithTimeout(r.Context(), lim.DialTimeout)
	defer cancel()
	addrs, err := Resolve(ctx, s.cfg.Resolver, host, rule.UnsafeAllowPrivate)
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

	upstream, _, err := DialAddrs(ctx, s.cfg.NewDial(rule.UnsafeAllowPrivate), addrs, port)
	if err != nil {
		s.errorOut(w, rq, host, port, ReasonDialFailed, err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		s.closeRecord(rq, audit.ActionError, "no-hijack", 0, 0)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	client, brw, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		s.closeRecord(rq, audit.ActionError, "hijack-failed", 0, 0)
		return
	}
	_ = client.SetDeadline(time.Time{})

	_ = client.SetWriteDeadline(time.Now().Add(lim.HandshakeTimeout))
	if _, err := client.Write([]byte(connectEstablished)); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		s.closeRecord(rq, audit.ActionError, "client-write-error", 0, 0)
		return
	}
	_ = client.SetWriteDeadline(time.Time{})

	var firstFlight []byte
	if !rule.UnsafeSkipTLSCheck {
		fl, action, reason := s.inspectHello(client, brw.Reader, host, rule, lim, rq)
		if reason != "" {
			_ = client.Close()
			_ = upstream.Close()
			s.closeRecord(rq, action, reason, 0, 0)
			return
		}
		firstFlight = fl
	}
	if len(firstFlight) > 0 {
		_ = upstream.SetWriteDeadline(time.Now().Add(lim.HandshakeTimeout))
		if _, err := upstream.Write(firstFlight); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			s.closeRecord(rq, audit.ActionError, "upstream-write-error", 0, 0)
			return
		}
		_ = upstream.SetWriteDeadline(time.Time{})
	}

	res := Splice(s.ctx, client, brw.Reader, upstream, SpliceOptions{
		Idle: lim.IdleTimeout, Total: lim.TotalTimeout, MaxBytes: lim.MaxBytesPerConn,
	})
	action := audit.ActionAllow
	if res.Reason == "max-bytes" || res.Reason == "total-timeout" || res.Reason == "idle-timeout" {
		action = audit.ActionAllow // a limit ending a legitimate tunnel is not a policy denial
	}
	s.closeRecord(rq, action, res.Reason, res.Up+int64(len(firstFlight)), res.Down)
}

// inspectHello reads and checks the client's first TLS flight. It returns the bytes to forward
// upstream, or a non-empty reason (with the audit action) when the tunnel must be closed.
func (s *Server) inspectHello(client net.Conn, r interface {
	Read([]byte) (int, error)
}, host string, rule policy.Rule, lim policy.EffectiveLimits, rq *request) ([]byte, string, string) {
	_ = client.SetReadDeadline(time.Now().Add(lim.HandshakeTimeout))
	info, raw, err := ReadClientHello(r)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		var he *HelloError
		if errors.As(err, &he) {
			return nil, audit.ActionDeny, "tls-" + he.Code
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, audit.ActionError, ReasonHandshakeTimeout
		}
		return nil, audit.ActionError, "client-read-error"
	}
	if info.HasSNI {
		rq.rec.SNI = printable(info.SNI)
	}
	if info.ECH && !rule.UnsafeAllowECH {
		return nil, audit.ActionDeny, ReasonECH
	}
	if !info.HasSNI {
		return nil, audit.ActionDeny, ReasonNoSNI
	}
	sni, err := policy.NormalizeHost(info.SNI, lim.MaxHostLen, lim.MaxLabelLen)
	if err != nil || sni != host {
		return nil, audit.ActionDeny, ReasonSNIMismatch
	}
	return raw, "", ""
}

// errorOut reports a failure that is neither a policy denial nor a success: the destination was
// allowed but could not be reached.
func (s *Server) errorOut(w http.ResponseWriter, rq *request, host string, port int, reason string, cause error) {
	s.cfg.Logger.Warn("connection failed", slog.String("host", host), slog.Int("port", port), slog.String("reason", reason), slog.Any("err", cause))
	rec := rq.rec
	rec.Event, rec.Action, rec.Reason = audit.EventDecision, audit.ActionError, reason
	s.logAudit(rec)
	writeDeny(w, messageFor(host, port, reason, ""))
}
