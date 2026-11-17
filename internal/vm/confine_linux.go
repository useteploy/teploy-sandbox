package vm

import (
	"fmt"
	"net"
	"syscall"
)

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
