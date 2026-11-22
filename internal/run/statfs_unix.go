//go:build linux || darwin

package run

import "syscall"

// statfsUsage is the used and free bytes of the filesystem path is on:
// used is everything not free, free what an unprivileged writer may still
// use (f_bavail), so used+free can be less than the size by the root
// reserve.
func statfsUsage(path string) (used, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	size := int64(st.Bsize)
	return int64(st.Blocks-st.Bfree) * size, int64(st.Bavail) * size, nil
}
