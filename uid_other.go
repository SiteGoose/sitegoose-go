//go:build !unix

package sitegoose

// userID: Windows has no uid 0; the check is left out rather than guessed.
func userID() (int, bool) { return 0, false }
