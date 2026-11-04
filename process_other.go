//go:build !unix

package sitegoose

// processAlive: without a portable way to ask, an empty crash file is left alone.
func processAlive(pid int) bool { return true }
