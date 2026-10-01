package cli

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/version"
)

func newVersionCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			if g.JSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			writef(cmd.OutOrStdout(), "cellwall %s (commit %s, built %s, %s %s/%s)\n",
				info.Version, info.Commit, info.Date, info.Go, info.OS, info.Arch)
			return nil
		},
	}
}
