//go:build !unix

package hostsecret

import "io/fs"

func ownerOf(fs.FileInfo) int { return -1 }
