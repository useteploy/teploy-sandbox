package vm

import (
	"os"
	"syscall"
)

// realMountOps binds and unbinds with mount(8)'s own calls. An unbind
// is a plain unmount: the copy of the mount in the VM's jail (a slave of
// the outbox) goes with it, so the VM has no path left to its image
// once the snapshot is written (measured on Linux 6.12:
// TestJailOutboxReceivesWhatTheHostMountsAndSendsNothingBack). Plain
// and not lazy because the daemon holds nothing below the outbox
// itself: a busy answer would mean something unexpected does, and is
// reported rather than left as a dangling reference.
func realMountOps() mountOps {
	return mountOps{
		bind: func(source, target string) error {
			if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
				return &os.PathError{Op: "bind", Path: target, Err: err}
			}
			return nil
		},
		unbind: func(target string) error {
			if err := syscall.Unmount(target, 0); err != nil {
				return &os.PathError{Op: "umount", Path: target, Err: err}
			}
			return nil
		},
	}
}

// mountSharedDir makes dir a mount of its own, shared. A VM's outbox is
// one: the VM's jail binds it as a slave (jailPath.Slave), and so
// receives everything the daemon mounts below it while the VM runs, and
// sends it nothing. A bind of the directory to itself is what gives it
// a mount to share.
func mountSharedDir(dir string) error {
	if err := syscall.Mount(dir, dir, "", syscall.MS_BIND, ""); err != nil {
		return &os.PathError{Op: "bind", Path: dir, Err: err}
	}
	if err := syscall.Mount("", dir, "", syscall.MS_SHARED, ""); err != nil {
		_ = syscall.Unmount(dir, mntDetach)
		return &os.PathError{Op: "make-shared", Path: dir, Err: err}
	}
	return nil
}
