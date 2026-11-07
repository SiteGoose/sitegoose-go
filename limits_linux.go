//go:build linux

package sitegoose

import "os"

// openFiles counts this process's open descriptors (/proc/self/fd's
// entries), less the one listing them takes.
func openFiles() (int64, bool) {
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return 0, false
	}
	n := int64(len(names)) - 1
	if n < 0 {
		n = 0
	}
	return n, true
}
