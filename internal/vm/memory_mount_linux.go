package vm

import (
	"os"
	"syscall"
)

// realMountOps binds and unbinds with mount(8)'s own calls. An unbind
// is detached: the mount leaves the namespace at once, and with it the
// copy of it in the VM's jail (a slave of the outbox), which is the
// point; whatever still holds it, keeps it only until it lets go.
func realMountOps() mountOps {
	return mountOps{
		bind: func(source, target string) error {
			if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
				return &os.PathError{Op: "bind", Path: target, Err: err}
			}
			return nil
		},
		unbind: func(target string) error {
			if err := syscall.Unmount(target, mntDetach); err != nil {
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
