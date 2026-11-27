//go:build unix

package hostsecret

import (
	"io/fs"
	"syscall"
)

// ownerOf is the file's owner, or -1 where the system has no owners.
func ownerOf(info fs.FileInfo) int {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(stat.Uid)
}
