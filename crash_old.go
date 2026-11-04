//go:build !go1.23

package sitegoose

import "time"

// watchCrashes: before Go 1.23 the runtime can't write a fatal panic
// anywhere but stderr, so only the crashes an earlier run on a newer Go left
// are sent. Recover still captures a goroutine's panic on its way up.
func (e *errorsModule) watchCrashes() { time.AfterFunc(5*time.Second, e.sendCrashes) }

func (e *errorsModule) stopCrashes() {}
