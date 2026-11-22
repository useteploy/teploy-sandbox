package run

import "syscall"

// statfsUsage is the used and free bytes of the filesystem path is on:
// used is everything not free, free what an unprivileged writer may still
// use (f_bavail), so used+free can be less than the size by the root
// reserve. Block counts are in fragment size units (f_frsize), which is
// what statfs(2) defines them in; f_bsize is only the preferred I/O size.
func statfsUsage(path string) (used, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	unit := st.Frsize
	if unit <= 0 {
		unit = st.Bsize
	}
	return int64(st.Blocks-st.Bfree) * int64(unit), int64(st.Bavail) * int64(unit), nil
}
