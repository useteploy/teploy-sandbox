package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// AF_VSOCK through raw syscalls: the standard library has no vsock
// support and this module has no dependencies.
const (
	afVsock      = 40
	vmaddrCIDAny = 0xFFFFFFFF
)

// sockaddrVM is struct sockaddr_vm from <linux/vm_sockets.h>.
type sockaddrVM struct {
	family    uint16
	reserved1 uint16
	port      uint32
	cid       uint32
	flags     uint8
	zero      [3]uint8
}

// listenVsock binds the port on every CID the guest has and returns an
// accept function. Sockets are non-blocking and handed to the runtime
// poller (os.NewFile), so reads, writes and Close behave like a net.Conn:
// closing a connection unblocks a read on it.
func listenVsock(port uint32) (func() (io.ReadWriteCloser, error), error) {
	fd, err := vsockSocket()
	if err != nil {
		return nil, err
	}
	addr := sockaddrVM{family: afVsock, port: port, cid: vmaddrCIDAny}
	if _, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr)); errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind vsock port %d: %w", port, errno)
	}
	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("listen on vsock port %d: %w", port, err)
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	listener := os.NewFile(uintptr(fd), "vsock-listener")
	raw, err := listener.SyscallConn()
	if err != nil {
		listener.Close()
		return nil, err
	}
	return func() (io.ReadWriteCloser, error) {
		for {
			var conn int
			var acceptErr error
			err := raw.Read(func(fd uintptr) bool {
				r, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4, fd, 0, 0, syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0, 0)
				if errno == syscall.EAGAIN {
					return false // wait until the listener is readable
				}
				if errno != 0 {
					acceptErr = errno
				}
				conn = int(r)
				return true
			})
			if err != nil {
				return nil, err
			}
			switch acceptErr {
			case nil:
				return os.NewFile(uintptr(conn), "vsock-conn"), nil
			case syscall.EINTR, syscall.ECONNABORTED:
				continue
			default:
				return nil, acceptErr
			}
		}
	}, nil
}

// vsockSocket opens an AF_VSOCK stream socket. The virtio transport is
// what carries connections from the host; the socket family alone can be
// present without it, so it is loaded here (best effort: it may be built
// in, or already loaded by modules-load.d). Early in boot the family may
// not be there yet either, which is answered with a short wait.
func vsockSocket() (int, error) {
	_ = exec.Command("modprobe", "vmw_vsock_virtio_transport").Run()
	deadline := time.Now().Add(30 * time.Second)
	for {
		fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err == nil {
			return fd, nil
		}
		if err != syscall.EAFNOSUPPORT || time.Now().After(deadline) {
			return -1, fmt.Errorf("open vsock socket (is vmw_vsock_virtio_transport loaded?): %w", err)
		}
		_ = exec.Command("modprobe", "vmw_vsock_virtio_transport").Run()
		time.Sleep(200 * time.Millisecond)
	}
}
