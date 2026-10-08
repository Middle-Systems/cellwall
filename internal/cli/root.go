// Package cli wires cobra commands to the packages that do the work. It contains no business logic.
package cli

import (
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
)

// ExitError asks main to exit with Code without printing an additional error line.
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

// globalFlags are shared by every command.
type globalFlags struct {
	ProjectDir string
	Verbose    bool
	JSON       bool
}

// NewRootCmd builds the command tree. Output streams are injected so tests can capture them.
func NewRootCmd(stdout, stderr io.Writer) *cobra.Command {
	var g globalFlags

	root := &cobra.Command{
		Use:   "cellwall",
		Short: "Run coding agents in a sandbox with policy-enforced egress",
		Long: "cellwall generates and runs a hardened dev-container setup in which a coding agent has\n" +
			"no direct network path to the internet. All egress goes through a policy-enforcing proxy\n" +
			"in a separate container the agent cannot modify.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			level := slog.LevelWarn
			if g.Verbose {
				level = slog.LevelDebug
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level})))
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)

	pf := root.PersistentFlags()
	pf.StringVar(&g.ProjectDir, "project-dir", ".", "project directory (default: current directory)")
	pf.BoolVarP(&g.Verbose, "verbose", "v", false, "enable debug logging on stderr")
	pf.BoolVar(&g.JSON, "json", false, "machine-readable JSON output where supported")

	root.AddCommand(newVersionCmd(&g), newDoctorCmd(&g), newInitCmd(&g), newPrepareCmd(&g), newGatewayCmd(&g),
		newUpCmd(&g), newRunCmd(&g), newShellCmd(&g), newDownCmd(&g), newStatusCmd(&g), newLogsCmd(&g), newAllowCmd(&g), newDenyCmd(&g), newPortsCmd(&g), newPolicyCmd(&g), newVerifyCmd(&g), newFetchCmd(&g))
	return root
}

func writef(w io.Writer, format string, args ...any) {
	// Output to a closed pipe is not actionable for a CLI; the exit code carries the result.
	_, _ = fmt.Fprintf(w, format, args...)
}
