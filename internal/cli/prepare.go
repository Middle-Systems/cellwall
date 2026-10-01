package cli

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/prepare"
)

func newPrepareCmd(g *globalFlags) *cobra.Command {
	var gatewayImage string
	cmd := &cobra.Command{
		Use:   "prepare",
		Short: "Write the gateway policy and per-session mounts",
		Long: "Compiles the project's policy (agent presets, your user-global policy, .cellwall/policy.yaml)\n" +
			"and writes the live state under .cellwall/state/: the effective policy the gateway hot-reloads,\n" +
			"the compose override with the read-only protected-path mounts and secrets, and compose.env.\n" +
			"It lists every active relaxation and any protected path created since the last run.\n" +
			"Running it again with nothing changed writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := prepare.Run(prepare.Options{Root: g.ProjectDir, GlobalConfigDir: globalConfigDir(), GatewayImage: gatewayImage, EngineCPUs: engineCPUs(cmd.Context())})
			if err != nil {
				return fmt.Errorf("%w\n  next: fix the problem above, then re-run `cellwall prepare`", err)
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), prepareJSON(res))
			}
			printPrepare(cmd.OutOrStdout(), res)
			return nil
		},
	}
	cmd.Flags().StringVar(&gatewayImage, "gateway-image", "", "gateway image reference (a digest reference in release builds; default: the locally built tag)")
	return cmd
}

type prepareReport struct {
	Project     string   `json:"project"`
	PolicyHash  string   `json:"policy_hash"`
	Rules       int      `json:"rules"`
	Presets     []string `json:"presets"`
	Mounted     []string `json:"protected_mounted"`
	Missing     []string `json:"protected_missing"`
	Symlinked   []string `json:"protected_symlinked,omitempty"`
	Appeared    []string `json:"protected_appeared,omitempty"`
	Written     []string `json:"written"`
	Relaxations []string `json:"relaxations"`
	Warnings    []string `json:"warnings"`
}

func prepareJSON(r *prepare.Result) prepareReport {
	nz := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return prepareReport{
		Project: r.Config.Project, PolicyHash: r.Policy.Hash, Rules: len(r.Policy.Policy.Rules), Presets: nz(r.Presets),
		Mounted: nz(r.Protected.Mounted), Missing: nz(r.Protected.Missing), Symlinked: r.Protected.Symlinked,
		Appeared: r.Appeared, Written: nz(r.Written), Relaxations: nz(r.Relaxations), Warnings: nz(r.Warnings),
	}
}

func printPrepare(w io.Writer, r *prepare.Result) {
	writef(w, "cellwall prepare: %s\n\n", r.Config.Project)
	writef(w, "policy %s: %d rules from presets [%s]\n", r.Policy.Hash[:12], len(r.Policy.Policy.Rules), strings.Join(r.Presets, ", "))
	if len(r.Written) == 0 {
		writef(w, "state is up to date (nothing written)\n")
	} else {
		for _, p := range r.Written {
			writef(w, "  wrote %s\n", p)
		}
	}
	if len(r.CachesMade) > 0 {
		writef(w, "created cache directories (so Docker does not create them as root): %s\n", strings.Join(r.CachesMade, ", "))
	}
	if len(r.Protected.Mounted) > 0 {
		writef(w, "\nread-only inside the sandbox: %s\n", strings.Join(r.Protected.Mounted, ", "))
	}
	if len(r.Protected.Missing) > 0 {
		writef(w, "protected but not present (not created; if the agent creates one, prepare reports it): %s\n", strings.Join(r.Protected.Missing, ", "))
	}
	if len(r.Relaxations) > 0 {
		writef(w, "\nRELAXATIONS (each weakens the sandbox):\n")
		for _, x := range r.Relaxations {
			writef(w, "  ! %s\n", x)
		}
	} else {
		writef(w, "\nno relaxations: the sandbox is at its strictest.\n")
	}
	if len(r.Warnings) > 0 {
		writef(w, "\nwarnings:\n")
		for _, x := range r.Warnings {
			writef(w, "  ! %s\n", x)
		}
	}
}

// engineCPUs asks the container engine how many CPUs it has; 0 if it cannot be reached (prepare
// works without a running engine, it just cannot clamp the CPU limit).
func engineCPUs(ctx context.Context) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.NCPU}}").Output()
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return n
}
