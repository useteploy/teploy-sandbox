//go:build unix

package vm

import (
	"io/fs"
	"syscall"
)

// ownerAndLinks are the owning UID and the link count of a file's inode.
func ownerAndLinks(info fs.FileInfo) (uid uint32, links uint64) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Uid, uint64(stat.Nlink)
	}
	// A file whose inode cannot be read is nobody's and linked to
	// nothing: no check that wants an image's file accepts it.
	return ^uint32(0), 0
}
