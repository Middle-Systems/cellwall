package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/proxy"
)

// Defaults for the gateway process.
const (
	DefaultListen         = ":3128"
	DefaultAdmin          = "127.0.0.1:3129"
	DefaultReloadInterval = 500 * time.Millisecond
	DefaultShutdownGrace  = 10 * time.Second
)

// Options configures Run.
type Options struct {
	PolicyPath string // required: the effective policy file (JSON or YAML)
	Listen     string // proxy listen address
	// Admin is the health/status listen address. It MUST be a loopback address: the agent shares
	// the gateway's network but not its loopback interface, and the control surface is never
	// exposed to it. There is deliberately no way to configure otherwise.
	Admin          string
	AuditDir       string
	AuditMaxSize   int64
	AuditMaxFiles  int
	FailOpenAudit  bool
	ReloadInterval time.Duration
	ShutdownGrace  time.Duration
	Logger         *slog.Logger

	// OnListening is called once both listeners are bound (used by tests to learn ephemeral ports).
	OnListening func(proxyAddr, adminAddr net.Addr)
}

func (o *Options) defaults() {
	if o.Listen == "" {
		o.Listen = DefaultListen
	}
	if o.Admin == "" {
		o.Admin = DefaultAdmin
	}
	if o.ReloadInterval <= 0 {
		o.ReloadInterval = DefaultReloadInterval
	}
	if o.ShutdownGrace <= 0 {
		o.ShutdownGrace = DefaultShutdownGrace
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// ValidateAdminAddr refuses anything but a literal loopback address.
func ValidateAdminAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("admin address %q: %w", addr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("admin address %q must be a loopback IP literal (e.g. 127.0.0.1:3129): the control surface is never exposed on a network the agent can reach", addr)
	}
	return nil
}

// Run starts the gateway and blocks until ctx is cancelled, then shuts down gracefully.
func Run(ctx context.Context, o Options) error {
	o.defaults()
	log := o.Logger
	if o.PolicyPath == "" {
		return errors.New("gateway: --policy is required")
	}
	if o.AuditDir == "" {
		return errors.New("gateway: --audit-dir is required")
	}
	if err := ValidateAdminAddr(o.Admin); err != nil {
		return err
	}

	state, err := NewState(o.PolicyPath, log)
	if err != nil {
		return fmt.Errorf("gateway: cannot start without a valid policy: %w", err)
	}
	aud, err := audit.Open(audit.Options{Dir: o.AuditDir, MaxSize: o.AuditMaxSize, MaxFiles: o.AuditMaxFiles})
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	defer func() { _ = aud.Close() }()

	logPolicy(log, "policy loaded", state.Current())
	_ = aud.Log(audit.Record{Event: audit.EventPolicy, Action: "load", Policy: short(state.Current().Hash)})
	if o.FailOpenAudit {
		log.Warn("RELAXATION: audit failures will NOT block connections (--audit-fail-open)")
	}

	srv := proxy.New(proxy.Config{
		Policy:               state.Current,
		Audit:                aud,
		FailOpenOnAuditError: o.FailOpenAudit,
		Logger:               log,
	})

	var lc net.ListenConfig
	proxyLn, err := lc.Listen(ctx, "tcp", o.Listen)
	if err != nil {
		return fmt.Errorf("gateway: listen on %s: %w", o.Listen, err)
	}
	adminLn, err := lc.Listen(ctx, "tcp", o.Admin)
	if err != nil {
		_ = proxyLn.Close()
		return fmt.Errorf("gateway: listen on %s: %w", o.Admin, err)
	}
	admin := &http.Server{Handler: adminMux(state, srv), ReadHeaderTimeout: 5 * time.Second}
	log.Info("gateway listening", slog.String("proxy", proxyLn.Addr().String()), slog.String("admin", adminLn.Addr().String()))
	if o.OnListening != nil {
		o.OnListening(proxyLn.Addr(), adminLn.Addr())
	}

	errc := make(chan error, 2)
	go func() { errc <- srv.Serve(proxyLn) }()
	go func() {
		if err := admin.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	go watch(ctx, state, aud, o.ReloadInterval, log)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down", slog.Duration("grace", o.ShutdownGrace))
	case runErr = <-errc:
		log.Error("server stopped unexpectedly", slog.Any("err", runErr))
	}
	sctx, cancel := context.WithTimeout(context.Background(), o.ShutdownGrace)
	defer cancel()
	_ = admin.Shutdown(sctx)
	if err := srv.Shutdown(sctx); err != nil && runErr == nil && !errors.Is(err, context.DeadlineExceeded) {
		runErr = err
	}
	return runErr
}

// watch polls the policy file until ctx ends.
func watch(ctx context.Context, state *State, aud *audit.Logger, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			handleReload(state.Poll(), aud, log)
		}
	}
}

func handleReload(r Reload, aud *audit.Logger, log *slog.Logger) {
	switch {
	case r.Failed:
		// Loud on purpose: the previous policy is still enforced, but someone expects the new one.
		log.Error("POLICY RELOAD FAILED: keeping the previous policy", slog.Any("err", r.Err),
			slog.String("active_policy", short(r.Old.Hash)))
		_ = aud.Log(audit.Record{Event: audit.EventPolicy, Action: "reload-failed", Reason: r.Err.Error(), Policy: short(r.Old.Hash)})
	case r.Changed:
		logPolicy(log, "policy reloaded", r.New)
		_ = aud.Log(audit.Record{Event: audit.EventPolicy, Action: "reload", Policy: short(r.New.Hash), Reason: "from " + short(r.Old.Hash)})
	}
}

func logPolicy(log *slog.Logger, msg string, c *policy.Compiled) {
	log.Info(msg, slog.String("policy", short(c.Hash)), slog.Int("rules", len(c.Policy.Rules)))
	// ADR 0003: every deliberately weakened control is printed whenever the policy changes.
	for _, line := range policy.Relaxations(c.Findings) {
		log.Warn("RELAXATION: " + line)
	}
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

func adminMux(state *State, srv *proxy.Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		c := state.Current()
		if c == nil {
			http.Error(w, "no policy", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "policy": short(c.Hash)})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"policy": state.Status(), "active_connections": srv.Active()})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Healthcheck contacts the admin endpoint and returns nil if the gateway reports healthy. The
// scratch gateway image has no shell or curl, so Docker's HEALTHCHECK runs `cellwall gateway
// healthcheck`.
func Healthcheck(ctx context.Context, admin string) error {
	if err := ValidateAdminAddr(admin); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+admin+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway unhealthy: %s", resp.Status)
	}
	return nil
}

// FetchStatus returns the admin endpoint's /status document (the active policy hash and reload
// history). The host CLI runs `cellwall gateway status` inside the gateway container to read it,
// so nothing is published on a host port and the agent has no path to it.
func FetchStatus(ctx context.Context, admin string) ([]byte, error) {
	if err := ValidateAdminAddr(admin); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+admin+"/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway status: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
