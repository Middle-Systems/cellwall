package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/config"
	"github.com/middle-systems/cellwall/internal/policy"
	"github.com/middle-systems/cellwall/internal/prepare"
)

func newPolicyCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Inspect the egress policy",
	}
	cmd.AddCommand(newPolicyLintCmd(g))
	return cmd
}

type lintReport struct {
	Source      string           `json:"source"`
	Rules       int              `json:"rules"`
	Findings    []policy.Finding `json:"findings"`
	Relaxations []string         `json:"relaxations"`
	Errors      int              `json:"errors"`
	Warnings    int              `json:"warnings"`
}

func newPolicyLintCmd(g *globalFlags) *cobra.Command {
	var strict bool
	cmd := &cobra.Command{
		Use:   "lint [file...]",
		Short: "Check the policy for dangerous wildcards, private-range allows and other weakened controls",
		Long: "Without arguments, lints the policy the sandbox would actually enforce: the agent's own hosts,\n" +
			"your user-global policy, .cellwall/policy.yaml and any session rules, after presets are expanded.\n" +
			"With file arguments, lints those policy files on their own.\n\n" +
			"Errors (wildcards over TLDs, public suffixes and user-content domains) stop the policy from\n" +
			"loading at all. Warnings are weakened controls you chose on purpose. Exits non-zero on any error,\n" +
			"and with --strict on any warning.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var reports []lintReport
			if len(args) == 0 {
				r, err := lintProject(g.ProjectDir)
				if err != nil {
					return err
				}
				reports = append(reports, r)
			}
			for _, f := range args {
				r, err := lintFile(f)
				if err != nil {
					return err
				}
				reports = append(reports, r)
			}
			failed := false
			for _, r := range reports {
				if r.Errors > 0 || (strict && r.Warnings > 0) {
					failed = true
				}
			}
			if g.JSON {
				if err := writeJSON(cmd.OutOrStdout(), reports); err != nil {
					return err
				}
			} else {
				for _, r := range reports {
					printLint(cmd.OutOrStdout(), r)
				}
			}
			if failed {
				return &ExitError{Code: 1, Msg: "policy lint found problems"}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "also fail on warnings")
	return cmd
}

func lintProject(dir string) (lintReport, error) {
	root, err := filepath.Abs(dir)
	if err != nil {
		return lintReport{}, err
	}
	loaded, err := config.Load(config.LoadOptions{ProjectDir: root, GlobalDir: globalConfigDir()})
	if err != nil {
		return lintReport{}, err
	}
	merged, warns, err := prepare.MergedPolicy(root, globalConfigDir(), loaded.Config)
	if err != nil {
		return lintReport{}, err
	}
	r, err := lintPolicy("effective policy for "+loaded.Config.Project, merged)
	if err != nil {
		return lintReport{}, err
	}
	r.Relaxations = append(r.Relaxations, loaded.Config.Relaxations()...)
	r.Relaxations = append(r.Relaxations, prepare.SessionRules(root)...)
	for _, w := range warns {
		r.Findings = append(r.Findings, policy.Finding{Level: policy.LevelWarn, Code: "setup", Message: w, Rule: -1})
		r.Warnings++
	}
	return r, nil
}

func lintFile(path string) (lintReport, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the file the user asked to lint
	if err != nil {
		return lintReport{}, fmt.Errorf("cannot read %s: %w\n  next: check the path", path, err)
	}
	p, err := policy.Parse(path, b)
	if err != nil {
		return lintReport{}, err
	}
	return lintPolicy(path, p)
}

func lintPolicy(label string, p *policy.Policy) (lintReport, error) {
	if err := p.Validate(false); err != nil {
		return lintReport{}, err
	}
	exp, err := policy.Expand(p)
	if err != nil {
		return lintReport{}, err
	}
	findings := policy.Lint(exp)
	r := lintReport{Source: label, Rules: len(exp.Rules), Findings: findings, Relaxations: policy.Relaxations(findings)}
	if r.Findings == nil {
		r.Findings = []policy.Finding{}
	}
	if r.Relaxations == nil {
		r.Relaxations = []string{}
	}
	for _, f := range findings {
		switch f.Level {
		case policy.LevelError:
			r.Errors++
		case policy.LevelWarn:
			r.Warnings++
		}
	}
	return r, nil
}

func printLint(w io.Writer, r lintReport) {
	writef(w, "%s: %d rules\n", r.Source, r.Rules)
	if len(r.Findings) == 0 {
		writef(w, "  no findings.\n")
	}
	for _, f := range r.Findings {
		writef(w, "  %s\n", f.String())
	}
	if len(r.Relaxations) > 0 {
		writef(w, "  relaxations (each weakens the sandbox):\n")
		for _, x := range r.Relaxations {
			writef(w, "    ! %s\n", x)
		}
	}
	writef(w, "  %d error(s), %d warning(s)\n", r.Errors, r.Warnings)
	if r.Errors > 0 {
		writef(w, "  next: errors stop the policy from loading. Replace wildcards over shared domains with the exact hostnames you need.\n")
	}
}
