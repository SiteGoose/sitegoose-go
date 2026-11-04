//go:build linux

package sitegoose

import (
	"os"
	"strconv"
	"strings"
)

// rssMB is this process's resident memory in MB, from /proc/self/statm.
func rssMB() (int64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return (pages*int64(os.Getpagesize()) + 524288) / 1048576, true
}
