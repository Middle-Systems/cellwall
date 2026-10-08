package cli

import (
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/middle-systems/cellwall/internal/sandbox"
)

func newPortsCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ports",
		Short: "Manage dev-server previews (ports published on 127.0.0.1 through the gateway)",
		Long: "The agent sits on an internal network and cannot publish ports. A preview is published by the\n" +
			"gateway on 127.0.0.1 of this machine and relayed to the same port in the agent container. The\n" +
			"dev server must listen on 0.0.0.0 inside the container, not localhost.",
	}
	cmd.AddCommand(newPortsLs(g), newPortsAdd(g), newPortsRm(g))
	return cmd
}

func newPortsLs(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List preview ports and whether the dev server behind each is reachable",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, err := sandbox.Ports(cmd.Context(), hostEnv(cmd, true), g.ProjectDir)
			if err != nil {
				return err
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), rep)
			}
			printPorts(cmd.OutOrStdout(), rep)
			return nil
		},
	}
}

func printPorts(w io.Writer, r *sandbox.PortsReport) {
	for _, p := range r.Ports {
		state := p.Listener
		switch {
		case !r.AgentRunning:
			state = "agent not running"
		case p.Listener == sandbox.ListenNone:
			state = "nothing listening yet"
		}
		pub := "not published"
		if p.Published {
			pub = "published"
		}
		writef(w, "%5d  %-26s %-22s %s\n", p.Port, p.URL, state, pub)
	}
	for _, x := range r.Warnings {
		writef(w, "! %s\n", x)
	}
}

func parsePorts(args []string) ([]int, error) {
	var out []int
	for _, a := range args {
		n, err := strconv.Atoi(a)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q is not a port number (1-65535)", a)
		}
		out = append(out, n)
	}
	return out, nil
}

func newPortsAdd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "add <port>...",
		Short: "Publish a dev-server port; recreates only the gateway",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ports, err := parsePorts(args)
			if err != nil {
				return err
			}
			return changePorts(cmd, g, ports, nil)
		},
	}
}

func newPortsRm(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <port>...",
		Short: "Stop publishing a dev-server port; recreates only the gateway",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ports, err := parsePorts(args)
			if err != nil {
				return err
			}
			return changePorts(cmd, g, nil, ports)
		},
	}
}

func changePorts(cmd *cobra.Command, g *globalFlags, add, rm []int) error {
	res, err := sandbox.ChangePorts(cmd.Context(), hostEnv(cmd, true), g.ProjectDir, add, rm)
	if err != nil {
		return err
	}
	if g.JSON {
		return writeJSON(cmd.OutOrStdout(), res)
	}
	w := cmd.OutOrStdout()
	switch {
	case len(res.Added) == 0 && len(res.Removed) == 0:
		writef(w, "nothing to change: ports are %v\n", res.Ports)
	default:
		if len(res.Added) > 0 {
			writef(w, "added %v\n", res.Added)
		}
		if len(res.Removed) > 0 {
			writef(w, "removed %v\n", res.Removed)
		}
		writef(w, "preview ports are now %v (config.yaml and the compose file were updated)\n", res.Ports)
		if res.GatewayReset {
			writef(w, "the gateway was recreated; in-flight proxy connections were dropped, the agent was not touched.\n")
		} else {
			writef(w, "the sandbox is not running; this takes effect at the next `cellwall up`.\n")
		}
	}
	for _, x := range res.Warnings {
		writef(w, "! %s\n", x)
	}
	return nil
}
