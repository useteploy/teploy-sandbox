package vm

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// sysSetns is the number of setns(2) on this architecture, or 0 where
// this driver does not know it. Not syscall.SYS_SETNS: the syscall
// package's tables were frozen before the call existed on some
// architectures, amd64 among them, and a daemon that names the constant
// does not compile there at all (the Docker driver included).
var sysSetns = setnsNumbers[runtime.GOARCH]

var setnsNumbers = map[string]uintptr{
	"amd64": 308,
	// The table every newer architecture shares.
	"arm64": 268, "riscv64": 268, "loong64": 268,
}

// inNamespace runs fn on a thread that is in the named network
// namespace: a socket or a device made there, and a process started
// there, belong to that namespace. The empty name is the namespace the
// daemon is in, and fn simply runs.
//
// The thread is not given back: it ends with the goroutine, so no other
// goroutine ever finds itself in a guest's namespace.
func inNamespace(name string, fn func() error) error {
	if name == "" {
		return fn()
	}
	if name != filepath.Base(name) {
		return fmt.Errorf("%q is not the name of a network namespace", name)
	}
	if sysSetns == 0 {
		return fmt.Errorf("entering a network namespace is not supported on %s", runtime.GOARCH)
	}
	target, err := os.Open(filepath.Join(netnsDir, name))
	if err != nil {
		return err
	}
	defer target.Close()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if _, _, errno := syscall.RawSyscall(sysSetns, target.Fd(), syscall.CLONE_NEWNET, 0); errno != 0 {
			done <- fmt.Errorf("enter the network namespace %s: %w", name, errno)
			return
		}
		done <- fn()
	}()
	return <-done
}

const tunDevice = "/dev/net/tun"

// openTap creates a tap device in the network namespace of the calling
// thread and returns it open. The device is down and not persistent: it is gone when
// the last descriptor for it is closed, which after the hand-over is the
// hypervisor's. Frames carry a virtio-net header, as the hypervisor
// expects of a tap it is handed.
func openTap(name string) (*os.File, error) {
	if len(name) >= syscall.IFNAMSIZ {
		return nil, fmt.Errorf("interface name %q is too long", name)
	}
	fd, err := syscall.Open(tunDevice, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: tunDevice, Err: err}
	}
	// struct ifreq: the name, then a union whose first member here is the
	// flags.
	var request [40]byte
	copy(request[:syscall.IFNAMSIZ-1], name)
	binary.NativeEndian.PutUint16(request[syscall.IFNAMSIZ:], syscall.IFF_TAP|syscall.IFF_NO_PI|syscall.IFF_VNET_HDR)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&request[0]))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, errno)
	}
	return os.NewFile(uintptr(fd), "tap:"+name), nil
}

// tunAvailable reports whether the daemon can create tap devices.
func tunAvailable() error {
	file, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return file.Close()
}
