package vm

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const tunDevice = "/dev/net/tun"

// openTap creates a tap device in the daemon's network namespace and
// returns it open. The device is down and not persistent: it is gone when
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
