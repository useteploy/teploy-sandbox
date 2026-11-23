//go:build linux

package main

import (
	"log/slog"
	"os"
	"strings"
	"syscall"
)

// The prctl operations for KSM's process-wide merge flag (Linux 6.4+).
const (
	prGetMemoryMergeFlag = 68
	prSetMemoryMergeFlag = 67
)

// clearMemoryMerge turns off this process's KSM merge flag and says
// what the host's KSM is doing. The jail helper already clears the flag
// for every hypervisor; the daemon itself holds tenants' data in memory
// while it encrypts and decrypts it, and a service unit with
// MemoryKSM=yes would make those pages mergeable with anyone else's on
// the host.
func clearMemoryMerge(log *slog.Logger) {
	if run, err := os.ReadFile("/sys/kernel/mm/ksm/run"); err == nil {
		log.Info("host ksm", "run", strings.TrimSpace(string(run)))
	}
	flag, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prGetMemoryMergeFlag, 0, 0, 0, 0, 0)
	if errno == 0 && flag == 1 {
		log.Warn("the daemon's memory was KSM-mergeable (a parent service set the flag); turning it off: this process holds tenants' data in the clear while encrypting and decrypting it")
	}
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetMemoryMergeFlag, 0, 0, 0, 0, 0); errno == syscall.EINVAL {
		// The kernel has no such option: nothing can merge.
		return
	} else if errno != 0 {
		log.Error("cannot turn off this process's KSM merge flag", "error", errno.Error())
	}
}
