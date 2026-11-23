package access

import (
	"fmt"
	"net"
	"syscall"
)

const peerCredentialsSupported = true

// peerCredentials is the uid and gid of a unix socket's peer, from the
// kernel (SO_PEERCRED): what the peer was when it connected, not anything
// it says.
func peerCredentials(conn net.Conn) (uid, gid int, err error) {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("%T is not a unix socket", conn)
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return int(cred.Uid), int(cred.Gid), nil
}
