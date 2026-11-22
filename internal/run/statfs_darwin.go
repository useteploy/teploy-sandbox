package run

import "syscall"

// statfsUsage: see statfs_linux.go. Darwin's counts are in f_bsize units
// (it has no f_frsize).
func statfsUsage(path string) (used, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	size := int64(st.Bsize)
	return int64(st.Blocks-st.Bfree) * size, int64(st.Bavail) * size, nil
}
