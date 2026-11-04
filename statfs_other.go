//go:build !linux && !darwin

package sitegoose

// statFS: no statfs in the standard library here, so no disks are reported.
func statFS(path string) (fsStat, bool) { return fsStat{}, false }
