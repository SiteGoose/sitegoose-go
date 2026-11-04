//go:build go1.23

package sitegoose

import (
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"time"
)

// One crash file per process: runtime/debug.SetCrashOutput is the process's,
// so the first platform to ask owns it.
var (
	crashMu    sync.Mutex
	crashOwner *errorsModule
)

// watchCrashes has the runtime write a fatal panic to this process's crash
// file as well as to stderr (where it still goes), and sends the crashes
// earlier runs left, a few seconds after start.
func (e *errorsModule) watchCrashes() {
	crashMu.Lock()
	defer crashMu.Unlock()
	if crashOwner == nil {
		mine := e.crashFile + "-" + strconv.Itoa(os.Getpid()) + ".log"
		// An earlier process with our ID that crashed: its file is kept for sendCrashes.
		if info, err := os.Stat(mine); err == nil && info.Size() > 0 {
			earlier := e.crashFile + "-" + strconv.Itoa(os.Getpid()) + "-earlier.log"
			os.Rename(mine, earlier)
			os.Rename(sentMarker(mine), sentMarker(earlier))
		}
		os.Remove(sentMarker(mine))
		if f, err := os.OpenFile(mine, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err == nil {
			// SetCrashOutput keeps its own copy of the descriptor.
			if debug.SetCrashOutput(f, debug.CrashOptions{}) == nil {
				crashOwner = e
			}
			f.Close()
		} else {
			e.core.log("errors", "no crash file: %v", err)
		}
	}
	time.AfterFunc(5*time.Second, e.sendCrashes)
}

// stopCrashes: a clean shutdown leaves no crash file behind.
func (e *errorsModule) stopCrashes() {
	crashMu.Lock()
	defer crashMu.Unlock()
	if crashOwner != e {
		return
	}
	debug.SetCrashOutput(nil, debug.CrashOptions{})
	crashOwner = nil
	mine := e.crashFile + "-" + strconv.Itoa(os.Getpid()) + ".log"
	if info, err := os.Stat(mine); err == nil && info.Size() == 0 {
		os.Remove(mine)
	}
	os.Remove(sentMarker(mine))
}
