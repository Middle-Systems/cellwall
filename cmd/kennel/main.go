// Command kennel sets up and runs sandboxed coding-agent environments.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/middle-systems/kennel/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := cli.NewRootCmd(os.Stdout, os.Stderr).ExecuteContext(ctx)
	if err == nil {
		return
	}
	var ee *cli.ExitError
	if errors.As(err, &ee) {
		// The command already printed its own report; just propagate the exit code.
		os.Exit(ee.Code)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
