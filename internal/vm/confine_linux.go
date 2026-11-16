package vm

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// confinedProcAttr starts a process as an unprivileged user, directly in
// its cgroup and in empty network and IPC namespaces: it is never, not
// for an instant, outside its limits or root. Changing to a non-zero UID drops every capability; nothing is
// kept and none is ambient.
func confinedProcAttr(uid, gid uint32, groups []uint32, cgroup *os.File) (*syscall.SysProcAttr, error) {
	if uid == 0 || gid == 0 {
		return nil, errors.New("refusing to start a hypervisor as root")
	}
	if cgroup == nil {
		return nil, errors.New("refusing to start a hypervisor outside a cgroup")
	}
	return &syscall.SysProcAttr{
		// Its own session: a signal aimed at the daemon's process group
		// (a terminal's ^C) must not take every run with it.
		Setsid:     true,
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups},
		// Network and IPC namespaces of its own, both empty: a VM has no
		// network device in this slice, so its hypervisor needs no
		// network, and gets not even the host's loopback. The daemon
		// reaches it through unix sockets, which are files. The kernel
		// makes the namespaces as the process is created; nothing runs
		// as root in them.
		Cloneflags:  syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC,
		UseCgroupFD: true,
		CgroupFD:    int(cgroup.Fd()),
	}, nil
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
