package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/middle-systems/kennel/internal/policy"
	"github.com/middle-systems/kennel/internal/policyedit"
	"github.com/middle-systems/kennel/internal/sandbox"
)

func newAllowCmd(g *globalFlags) *cobra.Command { return newEditCmd(g, policy.ActionAllow) }
func newDenyCmd(g *globalFlags) *cobra.Command  { return newEditCmd(g, policy.ActionDeny) }

func newEditCmd(g *globalFlags, action string) *cobra.Command {
	var ports []int
	var save bool
	var note string
	use, short := "allow <host>...", "Allow the agent to reach a host (takes effect live)"
	long := "Adds an allow rule for each exact hostname (or `*.example.com` pattern) and tells the running\n" +
		"gateway, which reloads without a restart. By default the rule lasts for this session only and is\n" +
		"kept in the local state directory; --save writes it into the committed .kennel/policy.yaml.\n\n" +
		"Hosts only, no URLs or IP addresses. Port 443 is assumed; use --port for others. A deny elsewhere\n" +
		"in the policy still wins, and kennel tells you if that stops the host from being reachable."
	if action == policy.ActionDeny {
		use, short = "deny <host>...", "Deny a host, overriding any allow"
		long = "Adds a deny rule for each host. Deny always beats allow, so this blocks a host that a preset or\n" +
			"another rule allows. By default for this session only; --save writes it into the committed\n" +
			".kennel/policy.yaml."
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e := hostEnv(cmd, true)
			res, err := sandbox.Edit(cmd.Context(), e, g.ProjectDir, sandbox.EditOptions{
				Edit: policyedit.Edit{Action: action, Hosts: args, Ports: ports, Note: note},
				Save: save,
			})
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), res)
			}
			printEdit(cmd, action, res)
			return nil
		},
	}
	cmd.Flags().IntSliceVar(&ports, "port", nil, "port(s) the rule applies to (default 443 for allow, every port for deny)")
	cmd.Flags().BoolVar(&save, "save", false, "write to the committed .kennel/policy.yaml instead of this session only")
	cmd.Flags().StringVar(&note, "note", "", "a short reason, stored with the rule")
	return cmd
}

func printEdit(cmd *cobra.Command, action string, r *sandbox.EditResult) {
	w := cmd.OutOrStdout()
	verb := map[string]string{policy.ActionAllow: "allowed", policy.ActionDeny: "denied"}[action]
	scope := "for this session only (add --save to put it in .kennel/policy.yaml)"
	if r.Saved {
		scope = "saved to .kennel/policy.yaml (commit it)"
	}
	for _, h := range r.Hosts {
		if contains(r.AlreadySaved, h) {
			writef(w, "%s was already in .kennel/policy.yaml\n", h)
			continue
		}
		writef(w, "%s %s %s\n", verb, h, scope)
	}
	for _, x := range r.Warnings {
		writef(w, "  ! %s\n", x)
	}
	switch {
	case !r.GatewayUp:
		writef(w, "the sandbox is not running; this takes effect at the next `kennel up`.\n")
	case r.Applied:
		writef(w, "the gateway is enforcing it now (policy %s, loaded in %s).\n", r.PolicyHash[:12], waitText(r.Waited))
	default:
		writef(w, "! the gateway has not confirmed the change: %s\n  next: run `kennel status` and `docker compose logs gateway`\n", r.GatewayError)
	}
	if !strings.Contains(scope, "saved") && action == policy.ActionAllow {
		writef(w, "undo with: kennel deny %s\n", strings.Join(r.Hosts, " "))
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
