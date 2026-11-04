//go:build unix

package sitegoose

import "os"

func userID() (int, bool) { return os.Getuid(), true }
