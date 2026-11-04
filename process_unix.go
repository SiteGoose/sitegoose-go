//go:build unix

package sitegoose

import (
	"errors"
	"syscall"
)

// processAlive: a process with this ID exists (another's, when not ours to signal).
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
