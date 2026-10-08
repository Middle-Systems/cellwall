package cli

import (
	"context"
	"os/exec"
)

func runGit(dir string, args ...string) (string, error) {
	out, err := exec.CommandContext(context.Background(), "git", append([]string{"-C", dir}, args...)...).Output() //nolint:gosec // argv only
	return string(out), err
}
