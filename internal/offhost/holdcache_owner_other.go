//go:build !unix

package offhost

import "io/fs"

func holdCacheOwnerOf(fs.FileInfo) int { return -1 }
