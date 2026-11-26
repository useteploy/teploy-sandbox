//go:build !unix

package vm

import "io/fs"

func ownerAndLinks(fs.FileInfo) (uid uint32, links uint64) { return ^uint32(0), 0 }
