//go:build !windows

package compose

import "os"

func isTerminal(f *os.File) bool { return charDeviceTerminal(f) }
