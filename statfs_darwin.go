//go:build darwin

package sitegoose

import "syscall"

func statFS(path string) (fsStat, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return fsStat{}, false
	}
	return fsStat{block: uint64(st.Bsize), blocks: uint64(st.Blocks), free: uint64(st.Bfree), avail: uint64(st.Bavail), files: uint64(st.Files), filesFree: uint64(st.Ffree)}, true
}
