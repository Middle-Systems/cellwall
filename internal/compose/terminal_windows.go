//go:build windows

package compose

import (
	"os"
	"syscall"
)

// isTerminal asks the console API: a handle is a terminal only if GetConsoleMode accepts it, which
// is false for pipes, files and NUL (and for IDE terminals that are really pipes).
func isTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
