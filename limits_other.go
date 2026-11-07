//go:build !linux

package sitegoose

// openFiles: off Linux there is no /proc/self/fd to count, so fds_used is
// left out rather than guessed.
func openFiles() (int64, bool) { return 0, false }
