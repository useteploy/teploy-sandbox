package vm

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	prSetSeccomp      = 22
	seccompModeFilter = 2
	// seccomp(2)'s operation that asks whether the kernel knows an
	// answer a filter may give.
	seccompGetActionAvail = 2
)

// sysSeccomp is the number of seccomp(2) on this architecture, or 0
// where this driver does not know it.
var sysSeccomp = map[string]uintptr{"amd64": 317, "arm64": 277}[runtime.GOARCH]

// installSeccomp puts the daemon's filter on the calling thread, for
// good: it stays across the execve that follows and on everything the
// program then starts. The thread must have no_new_privs set, which is
// what lets a process that is not root install a filter at all.
func installSeccomp() error {
	program, err := seccompProgram(runtime.GOARCH)
	if err != nil {
		return err
	}
	filter := make([]syscall.SockFilter, len(program))
	for i, each := range program {
		filter[i] = syscall.SockFilter{Code: each.Code, Jt: each.Jt, Jf: each.Jf, K: each.K}
	}
	prog := syscall.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter, uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return errno
	}
	runtime.KeepAlive(filter)
	return nil
}

// seccompAvailable reports whether a hypervisor can be put under the
// daemon's filter on this host: the driver has one for the
// architecture, and the kernel has seccomp filters and can kill a whole
// process from one (Linux 4.14).
func seccompAvailable() error {
	if _, err := seccompProgram(runtime.GOARCH); err != nil {
		return err
	}
	if sysSeccomp == 0 {
		return fmt.Errorf("no seccomp system call number for %s", runtime.GOARCH)
	}
	action := uint32(seccompKillProcess)
	if _, _, errno := syscall.RawSyscall(sysSeccomp, seccompGetActionAvail, 0, uintptr(unsafe.Pointer(&action))); errno != 0 {
		if errno == syscall.ENOSYS || errno == syscall.EINVAL || errno == syscall.EOPNOTSUPP {
			return errors.New("the kernel has no seccomp filters that can kill a process (CONFIG_SECCOMP_FILTER, Linux 4.14 or newer)")
		}
		return errno
	}
	return nil
}
