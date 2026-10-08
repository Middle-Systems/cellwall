package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/audit"
	"github.com/middle-systems/cellwall/internal/auditlog"
	"github.com/middle-systems/cellwall/internal/gen"
)

func newLogsCmd(g *globalFlags) *cobra.Command {
	var follow, denied bool
	var since string
	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Read the gateway's audit log",
		Long: "Shows every decision the gateway made (allowed, denied, closed), from the audit log kept under\n" +
			".cellwall/state/audit/. With --denied, groups the refused destinations by host with counts and\n" +
			"the command that would allow each one (or why no rule can).",
		Example: "  cellwall logs --denied --since 1h\n  cellwall logs -f\n  cellwall logs --json | jq 'select(.action==\"deny\")'",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := filepath.Abs(g.ProjectDir)
			if err != nil {
				return err
			}
			dir := filepath.Join(root, filepath.FromSlash(gen.StateDirRel), "audit")
			from, err := auditlog.ParseSince(since, time.Now())
			if err != nil {
				return err
			}
			f := auditlog.Filter{Since: from, DeniedOnly: denied}
			out := cmd.OutOrStdout()

			if follow {
				enc := json.NewEncoder(out)
				return auditlog.Follow(cmd.Context(), dir, f, func(r audit.Record) {
					if g.JSON {
						_ = enc.Encode(r)
						return
					}
					writef(out, "%s\n", auditlog.Line(r))
				}, 0)
			}

			recs, skipped, err := auditlog.Read(dir, f)
			if err != nil {
				return fmt.Errorf("cannot read the audit log in %s: %w\n  next: run `cellwall up` once so the gateway creates it", dir, err)
			}
			if skipped > 0 {
				writef(cmd.ErrOrStderr(), "note: %d line(s) in the audit log were not valid records and were skipped\n", skipped)
			}
			if _, statErr := os.Stat(dir); errors.Is(statErr, fs.ErrNotExist) {
				writef(cmd.ErrOrStderr(), "no audit log yet: the sandbox has not been started (run `cellwall up`)\n")
				return nil
			}
			if denied {
				groups := auditlog.GroupDenied(recs)
				if g.JSON {
					if groups == nil {
						groups = []auditlog.Denied{}
					}
					return writeJSON(out, groups)
				}
				printDenied(cmd, groups, since)
				return nil
			}
			if g.JSON {
				enc := json.NewEncoder(out)
				for _, r := range recs {
					if err := enc.Encode(r); err != nil {
						return err
					}
				}
				return nil
			}
			for _, r := range recs {
				writef(out, "%s\n", auditlog.Line(r))
			}
			if len(recs) == 0 {
				writef(cmd.ErrOrStderr(), "no matching records\n")
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new records as they arrive")
	cmd.Flags().BoolVar(&denied, "denied", false, "only refused connections, grouped by host with the command to allow each")
	cmd.Flags().StringVar(&since, "since", "", "only records newer than this (30m, 2h, 1d)")
	return cmd
}

func printDenied(cmd *cobra.Command, groups []auditlog.Denied, since string) {
	w := cmd.OutOrStdout()
	if len(groups) == 0 {
		writef(w, "nothing was denied%s.\n", sinceText(since))
		return
	}
	writef(w, "denied%s: %d destination(s)\n\n", sinceText(since), len(groups))
	for _, d := range groups {
		writef(w, "%5d  %s:%d   %s   last %s\n", d.Count, d.Host, d.Port, d.Reason, d.LastSeen.Local().Format("15:04:05"))
		switch {
		case d.Suggest != "":
			writef(w, "       -> %s\n", d.Suggest)
		case d.Why != "":
			writef(w, "       (no rule can fix this: %s)\n", d.Why)
		}
	}
}

func sinceText(since string) string {
	if since == "" {
		return ""
	}
	return " in the last " + since
}
