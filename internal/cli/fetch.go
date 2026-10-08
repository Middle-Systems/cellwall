package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/sandbox"
	"github.com/middle-systems/cellwall/internal/volume"
)

func newFetchCmd(g *globalFlags) *cobra.Command {
	var apply, allowProtected bool
	var branch string
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Bring the agent's commits from the workspace volume into your repository (volume mode)",
		Long: "In workspace.mode=volume the agent works on its own copy of the repository. `fetch` copies the\n" +
			"commits it made into refs/cellwall/<branch> of your repository, after checking the objects with\n" +
			"git's integrity checks. It never touches your branches or working tree, and it tells you which\n" +
			"of the changed files run on your machine (protected_paths, .gitmodules, git hooks config, ...).\n\n" +
			"With --apply, the matching branch is fast-forwarded into your current branch. That stops and\n" +
			"shows the diff if any protected file changed, and asks you to type 'yes' (or pass\n" +
			"--allow-protected). Uncommitted work in the agent's copy is not fetched: ask it to commit.",
		Example: "  cellwall fetch\n  cellwall fetch --apply\n  cellwall fetch --apply --branch feature",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			e := hostEnv(cmd, true)
			res, cfg, err := sandbox.Fetch(cmd.Context(), e, g.ProjectDir)
			if err != nil {
				return err
			}
			if g.JSON && !apply {
				return writeJSON(cmd.OutOrStdout(), res)
			}
			if !g.JSON {
				printFetch(cmd.OutOrStdout(), res)
			}
			if !apply || res.Nothing {
				return nil
			}
			target, err := pickBranch(res, branch, g.ProjectDir)
			if err != nil {
				return err
			}
			protected := cfg.ProtectedSet()
			br, err := sandbox.ApplyFetched(cmd.Context(), e, g.ProjectDir, target, protected, allowProtected)
			var pe *volume.ProtectedError
			if errors.As(err, &pe) {
				if err := confirmProtected(cmd, g, target, pe); err != nil {
					return err
				}
				br, err = sandbox.ApplyFetched(cmd.Context(), e, g.ProjectDir, target, protected, true)
			}
			if err != nil {
				return err
			}
			writef(cmd.OutOrStdout(), "merged %d commit(s) from %s into your current branch (fast-forward).\n", br.Commits, br.Ref)
			return nil
		},
	}
	cmd.Flags().BoolVar(&apply, "apply", false, "fast-forward your current branch to the fetched branch")
	cmd.Flags().StringVar(&branch, "branch", "", "the agent's branch to apply (default: the one matching your current branch, or the only one)")
	cmd.Flags().BoolVar(&allowProtected, "allow-protected", false, "do not stop at changes to protected files (you have reviewed them)")
	return cmd
}

func printFetch(w io.Writer, r *volume.FetchResult) {
	if r.Nothing {
		writef(w, "nothing new: the agent has no commits your repository lacks.\n")
	}
	for _, b := range r.Branches {
		writef(w, "%s: %d commit(s), %d file(s) changed   -> %s\n", b.Branch, b.Commits, len(b.Changes), b.Ref)
		prot := b.Protected()
		for _, c := range b.Changes {
			mark := " "
			if c.Protected {
				mark = "!"
			}
			writef(w, "  %s %s  %s\n", mark, c.Status, c.Path)
		}
		if len(prot) > 0 {
			writef(w, "  ! %d of these run on your machine or in its tooling (protected paths, .gitmodules, hooks config).\n"+
				"    Review them before merging: git diff HEAD...%s -- <path>\n", len(prot), b.Ref)
		}
	}
	if r.AgentDirty > 0 {
		writef(w, "note: the agent has %d uncommitted file(s) that were not fetched. Ask it to commit, or look with `cellwall shell`.\n", r.AgentDirty)
	}
	if len(r.Branches) > 0 {
		writef(w, "\nnext: `cellwall fetch --apply` fast-forwards your branch, or merge it yourself: git merge %s\n", r.Branches[0].Ref)
	}
}

// pickBranch chooses which fetched branch --apply merges.
func pickBranch(r *volume.FetchResult, want, projectDir string) (string, error) {
	if want != "" {
		for _, b := range r.Branches {
			if b.Branch == want {
				return want, nil
			}
		}
		return "", fmt.Errorf("the agent has no new commits on branch %q\n  next: see the list above", want)
	}
	if len(r.Branches) == 1 {
		return r.Branches[0].Branch, nil
	}
	cur := currentBranch(projectDir)
	for _, b := range r.Branches {
		if b.Branch == cur {
			return cur, nil
		}
	}
	var names []string
	for _, b := range r.Branches {
		names = append(names, b.Branch)
	}
	return "", fmt.Errorf("several branches have new commits (%s) and none matches your current branch\n  next: choose one with --branch", strings.Join(names, ", "))
}

// confirmProtected shows what changed in protected files and asks for an explicit yes. With no
// terminal it refuses and says which flag to use once the changes have been reviewed.
func confirmProtected(cmd *cobra.Command, g *globalFlags, branch string, pe *volume.ProtectedError) error {
	var paths []string
	for _, c := range pe.Changes {
		paths = append(paths, c.Path)
	}
	diff, _ := sandbox.FetchedDiff(cmd.Context(), g.ProjectDir, branch, paths)
	out := cmd.ErrOrStderr()
	writef(out, "\nThe agent changed files that run on your machine:\n\n%s\n", diff)
	ok, err := confirm(cmd.InOrStdin(), out, "Type 'yes' to merge these changes anyway: ")
	if err != nil {
		writef(out, "(review the diff above, then re-run with --allow-protected)\n")
		return &ExitError{Code: 1, Msg: "protected files changed"}
	}
	if !ok {
		writef(out, "nothing was merged. The fetched branch is still at refs/cellwall/%s.\n", branch)
		return &ExitError{Code: 1, Msg: "not confirmed"}
	}
	return nil
}

// currentBranch returns the host checkout's branch name, or "".
func currentBranch(dir string) string {
	out, err := runGit(dir, "symbolic-ref", "--short", "-q", "HEAD")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
