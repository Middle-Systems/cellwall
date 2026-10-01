package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/scaffold"
)

// globalConfigDir is the user-global config directory: $CELLWALL_CONFIG_DIR, else
// $XDG_CONFIG_HOME/cellwall, else ~/.config/cellwall (the path the spec names, on every OS).
// The user-global layer can tune but never relax (config.LayerUserGlobal), so an environment
// variable choosing its location cannot weaken a project.
func globalConfigDir() string {
	if d := os.Getenv("CELLWALL_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "cellwall")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "cellwall")
	}
	return ""
}

type initFlags struct {
	stacks    []string
	workspace string
	agent     string
	force     bool
	merge     bool
	dryRun    bool
}

func newInitCmd(g *globalFlags) *cobra.Command {
	var f initFlags
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate the sandbox configuration for this project",
		Long: "Detects the project's stacks and writes .cellwall/ (config and policy, yours to edit) and the\n" +
			"container files under .devcontainer/ (generated; regenerate by re-running init).\n\n" +
			"init never overwrites a file that cellwall did not generate or that you edited, never writes\n" +
			"through a symlink, and writes nothing at all if any file is in conflict. Running it again\n" +
			"with nothing changed writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runInit(cmd, g, f) },
	}
	fl := cmd.Flags()
	fl.StringSliceVar(&f.stacks, "stack", nil, "stacks to use instead of detecting them: auto, or a list of node,python,go,rust,java,dotnet,ruby,php")
	fl.StringVar(&f.workspace, "workspace", "", "workspace mode: bind (default) or volume")
	fl.StringVar(&f.agent, "agent", "", "agent preset: claude (default) or none")
	fl.BoolVar(&f.force, "force", false, "overwrite generated container files even if edited or not from cellwall (never config.yaml or policy.yaml)")
	fl.BoolVar(&f.merge, "merge", false, "leave an existing devcontainer setup untouched; add cellwall under .devcontainer/cellwall/")
	fl.BoolVar(&f.dryRun, "dry-run", false, "show what would be written without writing anything")
	return cmd
}

type jsonAction struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

type initReport struct {
	Root      string       `json:"root"`
	Project   string       `json:"project"`
	Stacks    []string     `json:"stacks"`
	Actions   []jsonAction `json:"actions"`
	Warnings  []string     `json:"warnings,omitempty"`
	Notes     []string     `json:"notes,omitempty"`
	DryRun    bool         `json:"dry_run,omitempty"`
	Conflicts bool         `json:"conflicts,omitempty"`
}

func runInit(cmd *cobra.Command, g *globalFlags, f initFlags) error {
	out := cmd.OutOrStdout()
	opts := scaffold.Options{
		Root: g.ProjectDir, Stacks: f.stacks, WorkspaceMode: f.workspace, Agent: f.agent,
		Merge: f.merge, Force: f.force, GlobalConfigDir: globalConfigDir(),
	}
	plan, err := scaffold.Build(opts)
	if err != nil {
		return fmt.Errorf("%w\n  next: fix the problem above, then re-run `cellwall init`", err)
	}
	rep := initReport{Root: plan.Root, Project: plan.Config.Project, Stacks: plan.Detect.Names(), Warnings: plan.Warnings, Notes: plan.Notes, DryRun: f.dryRun}
	for _, a := range plan.Actions {
		rep.Actions = append(rep.Actions, jsonAction{Path: a.File.Path, Action: strings.ToLower(a.Kind.String()), Reason: a.Reason})
	}
	conflicts := plan.Conflicts()
	rep.Conflicts = len(conflicts) > 0

	if len(conflicts) > 0 {
		if g.JSON {
			_ = writeJSON(out, rep)
		} else {
			printConflicts(cmd.ErrOrStderr(), plan, conflicts, f)
		}
		return &ExitError{Code: 1, Msg: "init refused: existing files would be overwritten"}
	}
	if !f.dryRun {
		if _, err := plan.Apply(); err != nil {
			return fmt.Errorf("%w\n  next: nothing was fully written; fix the problem and re-run `cellwall init`", err)
		}
	}
	if g.JSON {
		return writeJSON(out, rep)
	}
	printInit(out, plan, f.dryRun)
	return nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printConflicts(w io.Writer, plan *scaffold.Plan, conflicts []scaffold.Action, f initFlags) {
	writef(w, "cellwall init: nothing was written.\n\nThese existing files would be overwritten, and they are not cellwall's to replace:\n\n")
	for _, c := range conflicts {
		writef(w, "  %s\n      %s\n", c.File.Path, c.Reason)
	}
	writef(w, "\nChoose one:\n")
	if !f.merge {
		writef(w, "  cellwall init --merge   keep your setup exactly as it is and add cellwall as a second\n"+
			"                          configuration under .devcontainer/cellwall/\n")
	}
	writef(w, "  cellwall init --force   replace the files listed above (nothing else is touched)\n")
	writef(w, "  (or move your own files aside and re-run `cellwall init`)\n")
}

func printInit(w io.Writer, plan *scaffold.Plan, dry bool) {
	verb := map[scaffold.ActionKind]string{
		scaffold.Create: "create", scaffold.Update: "update", scaffold.Overwrite: "overwrite",
		scaffold.Unchanged: "unchanged", scaffold.Keep: "kept",
	}
	if dry {
		verb = map[scaffold.ActionKind]string{
			scaffold.Create: "would create", scaffold.Update: "would update", scaffold.Overwrite: "would overwrite",
			scaffold.Unchanged: "unchanged", scaffold.Keep: "kept",
		}
		writef(w, "cellwall init --dry-run (nothing is written)\n")
	}
	writef(w, "cellwall init: %s (project %q)\n", plan.Root, plan.Config.Project)
	if names := plan.Detect.Names(); len(names) > 0 {
		var parts []string
		for _, s := range plan.Detect.Stacks {
			p := s.Name
			if s.Tool != "" {
				p += " (" + s.Tool + ")"
			}
			if s.Dir != "." {
				p += " in " + s.Dir
			}
			parts = append(parts, p)
		}
		writef(w, "detected: %s\n", strings.Join(parts, ", "))
	} else {
		writef(w, "detected: no known stack (the sandbox still works; add toolchains with `agent.apt_packages`)\n")
	}
	writef(w, "\n")
	changed := 0
	for _, a := range plan.Actions {
		line := fmt.Sprintf("  %-14s %s", verb[a.Kind], a.File.Path)
		if a.Reason != "" && (a.Kind == scaffold.Keep || a.Kind == scaffold.Overwrite) {
			line += "   (" + a.Reason + ")"
		}
		writef(w, "%s\n", line)
		if a.Kind == scaffold.Create || a.Kind == scaffold.Update || a.Kind == scaffold.Overwrite {
			changed++
		}
	}
	if changed == 0 {
		writef(w, "\nnothing to do: everything is up to date.\n")
	}
	if len(plan.Warnings) > 0 {
		writef(w, "\nwarnings:\n")
		for _, x := range plan.Warnings {
			writef(w, "  ! %s\n", x)
		}
	}
	if len(plan.Notes) > 0 {
		writef(w, "\nnotes:\n")
		for _, x := range plan.Notes {
			writef(w, "  - %s\n", x)
		}
	}
	if !dry && changed > 0 {
		writef(w, "\nnext:\n  1. review .cellwall/config.yaml and .cellwall/policy.yaml (both are yours to edit)\n"+
			"  2. cellwall prepare      writes the gateway policy and mounts (`cellwall up` will do this for you)\n"+
			"  3. commit .cellwall/ and %s/\n", plan.Config.Devcontainer.Dir)
		if plan.Config.Devcontainer.Dir != ".devcontainer" {
			writef(w, "\nyour existing devcontainer setup was left untouched. In VS Code, \"Dev Containers: Reopen in\n"+
				"Container\" now offers a second configuration named \"cellwall\".\n")
		}
	}
}
