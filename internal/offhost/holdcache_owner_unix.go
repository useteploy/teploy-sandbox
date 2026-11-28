//go:build unix

package offhost

import (
	"io/fs"
	"syscall"
)

// holdCacheOwnerOf is the file's owner, or -1 where the system has no owners.
func holdCacheOwnerOf(info fs.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
