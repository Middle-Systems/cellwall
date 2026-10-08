package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/compose"
	"github.com/middle-systems/cellwall/internal/engine"
	"github.com/middle-systems/cellwall/internal/prepare"
	"github.com/middle-systems/cellwall/internal/sandbox"
)

// shellArgv starts bash when the image has it and sh otherwise.
var shellArgv = []string{"sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi"}

// hostEnv builds the sandbox environment from the command's streams. The attached streams are the
// command's own, so an interactive session gets the real terminal file descriptors.
func hostEnv(cmd *cobra.Command, noTTY bool) sandbox.Env {
	in := cmd.InOrStdin()
	out := cmd.OutOrStdout()
	tty := false
	if fin, ok := in.(*os.File); ok {
		if fout, ok := out.(*os.File); ok {
			tty = !noTTY && compose.IsTerminal(fin) && compose.IsTerminal(fout)
		}
	}
	return sandbox.Env{
		Runner:    engine.ExecRunner{},
		Streams:   compose.Streams{In: in, Out: out, Err: cmd.ErrOrStderr()},
		Log:       cmd.ErrOrStderr(),
		GlobalDir: globalConfigDir(),
		TTY:       tty,
	}
}

type upFlags struct {
	rebuild      bool
	gatewayImage string
	detach       bool
}

func (f *upFlags) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&f.rebuild, "rebuild", false, "rebuild the agent image")
	fl.StringVar(&f.gatewayImage, "gateway-image", "", "gateway image reference (default: the image built from this binary)")
}

func newUpCmd(g *globalFlags) *cobra.Command {
	var f upFlags
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Build if needed, start the gateway and the agent, and wait until they are healthy",
		Long: "Runs `cellwall prepare`, makes sure the gateway image exists (on Linux it is built from this very\n" +
			"binary, so the two can never disagree), then starts the gateway and the agent container and\n" +
			"waits for the gateway's health check. It always returns once the sandbox is up; use\n" +
			"`cellwall run` or `cellwall shell` to get inside.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e := hostEnv(cmd, true)
			res, err := sandbox.Up(cmd.Context(), e, g.ProjectDir, sandbox.UpOptions{Rebuild: f.rebuild, GatewayImage: f.gatewayImage})
			if err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), map[string]any{
					"project": res.Project.Cfg.Project, "policy": res.Prepare.Policy.Hash, "rules": len(res.Prepare.Policy.Policy.Rules),
					"gateway_image": res.Prepare.GatewayImage, "relaxations": nz(res.Prepare.Relaxations), "warnings": nz(res.Prepare.Warnings),
				})
			}
			printUpSummary(cmd.OutOrStdout(), res)
			w := cmd.OutOrStdout()
			writef(w, "\nnext:\n  cellwall run             start the agent\n  cellwall shell           open a shell in the agent container\n"+
				"  cellwall logs --denied   see what the policy blocked, and how to allow it\n")
			return nil
		},
	}
	f.add(cmd)
	cmd.Flags().BoolVarP(&f.detach, "detach", "d", true, "accepted for familiarity; up always returns once the sandbox is healthy")
	return cmd
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func printUpSummary(w io.Writer, res *sandbox.UpResult) {
	pol := res.Prepare.Policy
	writef(w, "cellwall: sandbox %q is up (policy %s, %d rules)\n", res.Project.Cfg.Project, pol.Hash[:12], len(pol.Policy.Rules))
	printNotes(w, res.Prepare)
}

// printNotes shows what must never be silent: active relaxations and warnings.
func printNotes(w io.Writer, r *prepare.Result) {
	if len(r.Relaxations) > 0 {
		writef(w, "RELAXATIONS (each weakens the sandbox):\n")
		for _, x := range r.Relaxations {
			writef(w, "  ! %s\n", x)
		}
	}
	if len(r.Warnings) > 0 {
		writef(w, "warnings:\n")
		for _, x := range r.Warnings {
			writef(w, "  ! %s\n", x)
		}
	}
}

func newRunCmd(g *globalFlags) *cobra.Command {
	var f upFlags
	var noTTY bool
	cmd := &cobra.Command{
		Use:   "run [flags] [-- agent args...]",
		Short: "Start the sandbox if needed and run the agent in it, interactively",
		Long: "Does what `cellwall up` does, then runs the configured agent command (agent.command in\n" +
			".cellwall/config.yaml) in the agent container with your terminal attached. Everything after\n" +
			"`--` is appended to the agent command. Your terminal, signals and the agent's exit status are\n" +
			"passed through: `cellwall run` exits with exactly the agent's exit code.",
		Example: "  cellwall run\n  cellwall run -- --model sonnet\n  cellwall run -- -p \"fix the failing test\"",
		RunE: func(cmd *cobra.Command, args []string) error {
			e := hostEnv(cmd, noTTY)
			// Progress goes to stderr so stdout stays the agent's.
			res, err := sandbox.Up(cmd.Context(), e, g.ProjectDir, sandbox.UpOptions{Rebuild: f.rebuild, GatewayImage: f.gatewayImage})
			if err != nil {
				return err
			}
			writef(cmd.ErrOrStderr(), "cellwall: sandbox %q ready (policy %s, %d rules)\n", res.Project.Cfg.Project, res.Prepare.Policy.Hash[:12], len(res.Prepare.Policy.Policy.Rules))
			printNotes(cmd.ErrOrStderr(), res.Prepare)

			argv := append(append([]string{}, res.Project.Cfg.Agent.Command...), args...)
			if len(argv) == 0 {
				return fmt.Errorf("no agent command is configured (agent.command in .cellwall/config.yaml is empty)\n  next: set agent.command, run `cellwall run -- <command>`, or open a shell with `cellwall shell`")
			}
			code, err := sandbox.Exec(cmd.Context(), e, g.ProjectDir, argv)
			if err != nil {
				return err
			}
			return exitWith(code)
		},
	}
	f.add(cmd)
	cmd.Flags().BoolVar(&noTTY, "no-tty", false, "do not allocate a pseudo-terminal (for scripts and pipes)")
	return cmd
}

// exitWith turns a child's exit status into the process's.
func exitWith(code int) error {
	if code == 0 {
		return nil
	}
	return &ExitError{Code: code}
}

func newShellCmd(g *globalFlags) *cobra.Command {
	var noTTY bool
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Open an interactive shell in the agent container",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e := hostEnv(cmd, noTTY)
			code, err := sandbox.Exec(cmd.Context(), e, g.ProjectDir, shellArgv)
			if err != nil {
				return err
			}
			return exitWith(code)
		},
	}
	cmd.Flags().BoolVar(&noTTY, "no-tty", false, "do not allocate a pseudo-terminal")
	return cmd
}

func newDownCmd(g *globalFlags) *cobra.Command {
	var volumes, yes bool
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Stop and remove the containers",
		Long: "Stops and removes the gateway and agent containers and the sandbox networks. Your repository,\n" +
			".cellwall/ and the audit log are untouched. With --volumes the named volumes are deleted too:\n" +
			"the agent's home (its login and history) and the dependency caches.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if volumes && !yes {
				ok, err := confirm(cmd.InOrStdin(), cmd.ErrOrStderr(),
					"This deletes the agent's home volume (its login, history and settings) and the dependency caches.\nType 'yes' to continue: ")
				if err != nil {
					return err
				}
				if !ok {
					writef(cmd.ErrOrStderr(), "aborted: nothing was deleted\n")
					return &ExitError{Code: 1, Msg: "aborted"}
				}
			}
			e := hostEnv(cmd, true)
			if err := sandbox.Down(cmd.Context(), e, g.ProjectDir, sandbox.DownOptions{Volumes: volumes}); err != nil {
				return err
			}
			writef(cmd.OutOrStdout(), "cellwall: sandbox stopped%s.\n", map[bool]string{true: " and its volumes deleted", false: ""}[volumes])
			return nil
		},
	}
	cmd.Flags().BoolVar(&volumes, "volumes", false, "also delete the named volumes (agent home and dependency caches)")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

// confirm asks a yes/no question and requires an interactive answer: with no terminal it refuses
// rather than guessing, and says how to proceed.
func confirm(in io.Reader, out io.Writer, prompt string) (bool, error) {
	f, ok := in.(*os.File)
	if !ok || !compose.IsTerminal(f) {
		// main prints nothing for an ExitError, so say it here.
		writef(out, "error: this would delete data and there is no terminal to ask on\n  next: re-run with --yes if you are sure\n")
		return false, &ExitError{Code: 1, Msg: "no terminal to confirm on"}
	}
	writef(out, "%s", prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	return strings.EqualFold(strings.TrimSpace(line), "yes"), nil
}

func newStatusCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the containers, network isolation, active policy and warnings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e := hostEnv(cmd, true)
			rep, err := sandbox.Status(cmd.Context(), e, g.ProjectDir)
			if err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), rep)
			}
			printStatus(cmd.OutOrStdout(), rep)
			return nil
		},
	}
}

func printStatus(w io.Writer, r *sandbox.StatusReport) {
	writef(w, "project:   %s   (workspace: %s)\n", r.Project, r.WorkspaceMode)
	if len(r.Containers) == 0 {
		writef(w, "sandbox:   not running   (cellwall up)\n")
	}
	for _, c := range r.Containers {
		h := ""
		if c.Health != "" {
			h = " (" + c.Health + ")"
		}
		writef(w, "  %-8s %s%s\n", c.Service, c.State, h)
	}
	switch {
	case !r.Network.Found:
		writef(w, "network:   %s   not created\n", r.Network.Name)
	case r.Network.Internal && r.Network.Isolated:
		writef(w, "network:   %s   internal, host-isolated\n", r.Network.Name)
	default:
		writef(w, "network:   %s   NOT fully isolated (internal=%v, host-isolated=%v)\n", r.Network.Name, r.Network.Internal, r.Network.Isolated)
	}
	p := r.Policy
	switch {
	case p.OnDisk == "":
		writef(w, "policy:    not prepared\n")
	case p.Active == "" && !p.GatewayUp:
		writef(w, "policy:    %s (%d rules) on disk; gateway not running\n", p.OnDisk[:12], p.Rules)
	case p.Active == "":
		writef(w, "policy:    %s (%d rules) on disk; the gateway did not report its policy\n", p.OnDisk[:12], p.Rules)
	case p.InSync:
		writef(w, "policy:    %s (%d rules), loaded by the gateway (%d reloads)\n", p.OnDisk[:12], p.Rules, p.Reloads)
	default:
		writef(w, "policy:    on disk %s, gateway enforcing %s\n", p.OnDisk[:12], p.Active[:12])
	}
	if p.LastError != "" {
		writef(w, "           last reload error: %s\n", p.LastError)
	}
	if len(r.Ports) > 0 {
		writef(w, "previews:  ports %v are configured (forwarding arrives with `cellwall ports`)\n", r.Ports)
	}
	if len(r.Relaxations) > 0 {
		writef(w, "RELAXATIONS (each weakens the sandbox):\n")
		for _, x := range r.Relaxations {
			writef(w, "  ! %s\n", x)
		}
	} else {
		writef(w, "relaxations: none\n")
	}
	for _, x := range r.Warnings {
		writef(w, "warning: %s\n", x)
	}
}

// waitText formats a wait for humans.
func waitText(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
