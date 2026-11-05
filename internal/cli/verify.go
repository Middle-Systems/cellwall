package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/middle-systems/kennel/internal/sandbox"
	"github.com/middle-systems/kennel/internal/verify"
)

func newVerifyCmd(g *globalFlags) *cobra.Command {
	var strict, readOnly bool
	var only []string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Try to escape the running sandbox and report which protections hold",
		Long: "Runs the escape suite against the live sandbox: direct connections, DNS leaks, requests through\n" +
			"the proxy, IP-literal and loopback targets, SNI and ECH tricks, plain HTTP, writes to protected\n" +
			"paths, the container's privileges, reachability of the host and the gateway's control surface,\n" +
			"previews, and policy hot reload. The same checks run in CI.\n\n" +
			"Two checks briefly add (and always remove) a session rule to prove a guard; --read-only skips\n" +
			"them. A check that needs something the environment lacks (outbound network, a preview port) is\n" +
			"reported as SKIP, never as a pass; --strict makes skips fail. Exits non-zero if anything failed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e := hostEnv(cmd, true)
			ve, err := sandbox.VerifyEnv(cmd.Context(), e, g.ProjectDir, !readOnly)
			if err != nil {
				return err
			}
			if !g.JSON {
				writef(cmd.ErrOrStderr(), "kennel verify: attacking the running sandbox (about a minute)...\n")
			}
			results := verify.Run(cmd.Context(), ve, only)
			if len(results) == 0 {
				return fmt.Errorf("no check matches %v\n  next: names are %s", only, strings.Join(checkNames(), ", "))
			}
			failed := verify.Failed(results, strict)
			if g.JSON {
				if err := writeJSON(cmd.OutOrStdout(), map[string]any{"results": results, "failed": failed, "strict": strict}); err != nil {
					return err
				}
			} else {
				printVerify(cmd.OutOrStdout(), results, strict)
			}
			if failed {
				return &ExitError{Code: 1, Msg: "verify found problems"}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "treat skipped checks as failures (CI does)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false, "do not run the checks that briefly add a session rule")
	cmd.Flags().StringSliceVar(&only, "only", nil, "run only these checks, by number or name")
	return cmd
}

func checkNames() []string {
	var out []string
	for _, c := range verify.Checks() {
		out = append(out, c.Name)
	}
	return out
}

func printVerify(w io.Writer, rs []verify.Result, strict bool) {
	var pass, fail, skip int
	for _, r := range rs {
		label := map[verify.Status]string{verify.Pass: "PASS", verify.Fail: "FAIL", verify.Skip: "SKIP"}[r.Status]
		writef(w, "%2d  %s  %-19s %s\n", r.ID, label, r.Name, r.Title)
		if r.Detail != "" {
			writef(w, "          %s\n", r.Detail)
		}
		switch r.Status {
		case verify.Pass:
			pass++
		case verify.Fail:
			fail++
		case verify.Skip:
			skip++
		}
	}
	writef(w, "\n%d passed, %d failed, %d skipped", pass, fail, skip)
	if skip > 0 && !strict {
		writef(w, "  (a skip is not a pass: re-run with --strict to fail on it)")
	}
	writef(w, "\n")
	if fail > 0 {
		writef(w, "next: a FAIL means the sandbox does not hold that property. See docs/threat-model.md, fix the cause, run `kennel down && kennel up`, then `kennel verify` again.\n")
	}
}
