package cli

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/gateway"
)

// newGatewayCmd is the process that runs inside the gateway container. It is hidden: users never
// start it by hand, the generated compose file does.
func newGatewayCmd(g *globalFlags) *cobra.Command {
	var (
		o        gateway.Options
		maxMB    int64
		level    string
		logFmt   string
		adminHC  string
		failOpen bool
	)
	cmd := &cobra.Command{
		Use:    "gateway",
		Short:  "Run the egress gateway (used inside the gateway container)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lg, err := newLogger(cmd, level, logFmt, g.Verbose)
			if err != nil {
				return err
			}
			o.Logger = lg
			o.AuditMaxSize = maxMB << 20
			o.FailOpenAudit = failOpen
			return gateway.Run(cmd.Context(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.PolicyPath, "policy", "", "effective policy file (mount its DIRECTORY, not the file, so reloads are seen)")
	f.StringVar(&o.Listen, "listen", gateway.DefaultListen, "proxy listen address")
	f.StringVar(&o.Admin, "admin", gateway.DefaultAdmin, "admin/health listen address (must be loopback)")
	f.StringVar(&o.AuditDir, "audit-dir", "", "directory for the audit log")
	f.Int64Var(&maxMB, "audit-max-size-mb", 50, "rotate the audit log after this many MiB")
	f.IntVar(&o.AuditMaxFiles, "audit-max-files", 5, "rotated audit files to keep")
	f.BoolVar(&failOpen, "audit-fail-open", false, "UNSAFE: keep allowing connections when the audit log cannot be written")
	f.IntSliceVar(&o.Forward, "forward-port", nil, "preview port to relay to --forward-target on the same port (repeatable)")
	f.StringVar(&o.ForwardTarget, "forward-target", "agent", "fixed upstream host for forwarded ports")
	f.DurationVar(&o.ReloadInterval, "reload-interval", gateway.DefaultReloadInterval, "how often to check the policy file")
	f.DurationVar(&o.ShutdownGrace, "shutdown-grace", gateway.DefaultShutdownGrace, "how long to let tunnels drain on shutdown")
	f.StringVar(&level, "log-level", "info", "log level: debug, info, warn, error")
	f.StringVar(&logFmt, "log-format", "json", "log format: json or text")

	hc := &cobra.Command{
		Use:   "healthcheck",
		Short: "Exit 0 if the local gateway reports healthy (for Docker HEALTHCHECK)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := gateway.Healthcheck(cmd.Context(), adminHC); err != nil {
				return err
			}
			return nil
		},
	}
	hc.Flags().StringVar(&adminHC, "admin", gateway.DefaultAdmin, "admin address of the gateway to check")
	st := &cobra.Command{
		Use:   "status",
		Short: "Print the local gateway's status as JSON (run by the host CLI via docker exec)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := gateway.FetchStatus(cmd.Context(), adminHC)
			if err != nil {
				return err
			}
			_, _ = cmd.OutOrStdout().Write(b)
			return nil
		},
	}
	st.Flags().StringVar(&adminHC, "admin", gateway.DefaultAdmin, "admin address of the gateway")
	cmd.AddCommand(hc, st)
	return cmd
}

func newLogger(cmd *cobra.Command, level, format string, verbose bool) (*slog.Logger, error) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "info", "":
		lv = slog.LevelInfo
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid --log-level %q (use debug, info, warn or error)", level)
	}
	if verbose {
		lv = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch strings.ToLower(format) {
	case "json", "":
		return slog.New(slog.NewJSONHandler(cmd.ErrOrStderr(), opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), opts)), nil
	}
	return nil, fmt.Errorf("invalid --log-format %q (use json or text)", format)
}
