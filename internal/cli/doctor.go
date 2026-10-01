package cli

import (
	"encoding/json"
	"io"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/doctor"
)

func newDoctorCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the host for everything cellwall needs",
		Long: "Checks the container engine, Compose, platform quirks and resources. Exits non-zero if any\n" +
			"check fails; warnings do not change the exit code.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep := doctor.Run(cmd.Context(), doctor.Options{})
			out := cmd.OutOrStdout()
			if g.JSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				printReport(out, rep)
			}
			if rep.Failed() {
				return &ExitError{Code: 1, Msg: "doctor found problems"}
			}
			return nil
		},
	}
}

var statusMark = map[doctor.Status]string{
	doctor.Pass: "ok  ",
	doctor.Warn: "warn",
	doctor.Fail: "FAIL",
	doctor.Skip: "skip",
}

func printReport(w io.Writer, rep doctor.Report) {
	for _, r := range rep.Results {
		writef(w, "[%s] %s", statusMark[r.Status], r.Title)
		if r.Detail != "" {
			writef(w, ": %s", r.Detail)
		}
		writef(w, "\n")
		if r.Fix != "" && r.Status != doctor.Pass {
			writef(w, "       -> %s\n", r.Fix)
		}
	}
}
