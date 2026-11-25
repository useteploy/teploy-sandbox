package guest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// What a restored VM's guest needs from its kernel: setting the wall
// clock and reseeding the random generator. The ioctl numbers are the
// kernel's own and the same on every architecture.

const (
	// rndAddEntropy is RNDADDENTROPY: mix a buffer into the random pool
	// and credit it with a number of bits of real entropy.
	rndAddEntropy = 0x40085203
	// rndReseedCrng is RNDRESEEDCRNG (Linux 4.19 or newer): reseed the
	// generator now, from what the pool holds.
	rndReseedCrng = 0x5207
	// The bits of entropy credited for each byte the daemon sends: its
	// bytes come from the host's own generator.
	entropyBitsPerByte = 8
	// clockRealtime is CLOCK_REALTIME, the same number on every
	// architecture the agent runs on.
	clockRealtime = 0
)

var errEntropyWords = errors.New("the entropy buffer is not a whole number of 32-bit words")

// platformSetClock steps the wall clock (clock_settime(2); the standard
// package only wraps the read).
func platformSetClock(nowNs int64) error {
	ts := syscall.Timespec{Sec: nowNs / 1e9, Nsec: nowNs % 1e9}
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_SETTIME, clockRealtime, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return errno
	}
	return nil
}

// platformAddEntropy writes the bytes to the random pool through
// RNDADDENTROPY (which credits them, unlike a plain write to
// /dev/urandom), then asks for a reseed with RNDRESEEDCRNG. A kernel
// without the reseed request, or one that refuses it (ENOTTY or EINVAL),
// is not an error: the bytes are in the pool either way, and reseeded
// says whether the request went through.
func platformAddEntropy(entropy []byte) (reseeded bool, err error) {
	if len(entropy) == 0 || len(entropy)%4 != 0 {
		return false, errEntropyWords
	}
	// struct rand_pool_info: the bits of entropy, then the buffer's
	// size in 32-bit words, then the words themselves.
	info := make([]byte, 8+len(entropy))
	binary.LittleEndian.PutUint32(info[0:], uint32(len(entropy)*entropyBitsPerByte))
	binary.LittleEndian.PutUint32(info[4:], uint32(len(entropy)/4))
	copy(info[8:], entropy)
	device, err := os.OpenFile("/dev/urandom", os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	defer device.Close()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), rndAddEntropy, uintptr(unsafe.Pointer(&info[0]))); errno != 0 {
		return false, errno
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, device.Fd(), rndReseedCrng, 0)
	switch errno {
	case 0:
		return true, nil
	case syscall.ENOTTY, syscall.EINVAL:
		return false, nil
	}
	return false, errno
}

// platformVMGenIDSeen reports whether the kernel's VM Generation ID
// driver is bound to the device the hypervisor presents: the ACPI device
// VMGENCTR, with a driver. The device is in the tables whether or not the
// kernel has the driver (CONFIG_VMGENID); the driver is what reseeds.
func platformVMGenIDSeen() bool {
	devices, err := os.ReadDir("/sys/bus/acpi/devices")
	if err != nil {
		return false
	}
	for _, device := range devices {
		name := device.Name()
		if !bytes.HasPrefix([]byte(name), []byte("VMGENCTR")) {
			continue
		}
		if _, err := os.Stat("/sys/bus/acpi/devices/" + name + "/driver"); err == nil {
			return true
		}
	}
	return false
}
