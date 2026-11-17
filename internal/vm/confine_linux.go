package vm

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

var socketDirOptions = fmt.Sprintf("mode=0700,size=%dk,nr_inodes=%d", SocketDirKB, SocketDirInodes)

const (
	mntDetach      = 2
	umountNoFollow = 8
)

// mountSocketDir mounts a VM's own tmpfs on its runtime dir.
func mountSocketDir(dir string) error {
	return syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, socketDirOptions)
}

// unmountSocketDir takes away whatever is mounted on dir, however often
// (a daemon that died between a mount and its record of it may have
// left more than one), and succeeds when nothing is. Detached rather
// than refused when busy: the VM's process is gone when this is called,
// and what the daemon itself may still hold open there (a connection it
// is about to close) must not keep the name.
func unmountSocketDir(dir string) error {
	for range 64 {
		err := syscall.Unmount(dir, mntDetach|umountNoFollow)
		switch {
		case err == nil:
			continue
		case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOENT):
			// Not a mount point, or not there.
			return nil
		}
		return &os.PathError{Op: "umount", Path: dir, Err: err}
	}
	return fmt.Errorf("%s is still a mount point after 64 unmounts", dir)
}

// probeSocketDir proves that the daemon can give a VM a filesystem for
// its sockets: it mounts one under dir and removes it again.
func probeSocketDir(dir string) error {
	probe := filepath.Join(dir, ".probe")
	if err := unmountSocketDir(probe); err != nil {
		return err
	}
	if err := os.Mkdir(probe, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	defer os.Remove(probe)
	if err := mountSocketDir(probe); err != nil {
		return fmt.Errorf("mount a tmpfs: %w", err)
	}
	return unmountSocketDir(probe)
}

// landlockABI asks the kernel which Landlock version it enforces:
// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION). The
// syscall has the same number on every architecture.
func landlockABI() (int, error) {
	const sysLandlockCreateRuleset, versionFlag = 444, 1
	version, _, errno := syscall.Syscall(sysLandlockCreateRuleset, 0, 0, versionFlag)
	if errno != 0 {
		return 0, errno
	}
	return int(version), nil
}

// socketOwner is the UID of the peer of a connected unix socket
// (SO_PEERCRED). For the connecting side that is whoever called listen:
// the kernel takes it from that process's credentials, and nothing the
// peer sends can change it.
func socketOwner(conn net.Conn) (uint32, error) {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("%T is not a unix socket", conn)
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}
