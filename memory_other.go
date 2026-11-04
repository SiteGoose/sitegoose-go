//go:build !linux

package sitegoose

// rssMB: off Linux the standard library has no portable reading of resident
// memory, so the check-in leaves rss_mb out rather than guessing.
func rssMB() (int64, bool) { return 0, false }
