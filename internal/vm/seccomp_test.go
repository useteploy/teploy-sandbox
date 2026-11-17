package vm

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// runBPF evaluates a classic BPF program on one seccomp_data, as the
// kernel does, and returns what it answers. It knows the instructions a
// seccomp filter of this package may use and fails on any other, so a
// program that passes here is one the reading below is right about.
func runBPF(t *testing.T, program []bpfInsn, data [seccompDataSize]byte) uint32 {
	t.Helper()
	var a uint32
	for pc := 0; pc < len(program); pc++ {
		each := program[pc]
		jump := func(taken bool) {
			if taken {
				pc += int(each.Jt)
			} else {
				pc += int(each.Jf)
			}
		}
		switch each.Code {
		case bpfLdAbsW:
			if each.K%4 != 0 || each.K+4 > seccompDataSize {
				t.Fatalf("instruction %d loads from offset %d, outside seccomp_data", pc, each.K)
			}
			a = binary.LittleEndian.Uint32(data[each.K:])
		case bpfJeq:
			jump(a == each.K)
		case bpfJge:
			jump(a >= each.K)
		case bpfJset:
			jump(a&each.K != 0)
		case bpfRet:
			return each.K
		default:
			t.Fatalf("instruction %d has code %#x, which this interpreter does not know", pc, each.Code)
		}
	}
	t.Fatal("the program ran off its end without an answer")
	return 0
}

// seccompCall is one system call as a filter sees it.
func seccompCall(arch, nr uint32, args ...uint64) [seccompDataSize]byte {
	var data [seccompDataSize]byte
	binary.LittleEndian.PutUint32(data[seccompDataNr:], nr)
	binary.LittleEndian.PutUint32(data[seccompDataArch:], arch)
	for i, arg := range args {
		binary.LittleEndian.PutUint64(data[seccompDataArg0+8*i:], arg)
	}
	return data
}

const (
	answerAllow  = seccompAllow
	answerEPERM  = seccompErrno | errnoEPERM
	answerENOSYS = seccompErrno | errnoENOSYS
	answerKill   = seccompKillProcess
)

func answerName(answer uint32) string {
	switch answer {
	case answerAllow:
		return "allow"
	case answerEPERM:
		return "EPERM"
	case answerENOSYS:
		return "ENOSYS"
	case answerKill:
		return "kill the process"
	}
	return fmt.Sprintf("%#x", answer)
}

// What a hypervisor (and the helper before it) has to keep, by number,
// per architecture: none of it may be on the list by mistake.
var seccompNeeded = map[string]map[string]uint32{
	"amd64": {
		"read": 0, "write": 1, "close": 3, "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12,
		"rt_sigaction": 13, "ioctl": 16, "madvise": 28, "dup": 32, "getpid": 39, "connect": 42, "accept": 43,
		"sendmsg": 46, "recvmsg": 47, "bind": 49, "listen": 50, "exit": 60, "fcntl": 72, "prctl": 157,
		"gettid": 186, "futex": 202, "io_setup": 206, "io_destroy": 207, "io_getevents": 208, "io_submit": 209,
		"epoll_ctl": 233, "exit_group": 231, "openat": 257, "epoll_pwait": 281, "eventfd2": 290,
		"epoll_create1": 291, "pipe2": 293, "preadv": 295, "pwritev": 296, "seccomp": 317,
		"getrandom": 318, "memfd_create": 319, "execve": 59, "close_range": 436,
		"landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446,
		"timerfd_create": 283, "fallocate": 285, "fsync": 74, "sigaltstack": 131, "tkill": 200,
	},
	"arm64": {
		"read": 63, "write": 64, "close": 57, "mmap": 222, "mprotect": 226, "munmap": 215, "brk": 214,
		"rt_sigaction": 134, "ioctl": 29, "madvise": 233, "dup": 23, "getpid": 172, "connect": 203, "accept": 202,
		"sendmsg": 211, "recvmsg": 212, "bind": 200, "listen": 201, "exit": 93, "fcntl": 25, "prctl": 167,
		"gettid": 178, "futex": 98, "io_setup": 0, "io_destroy": 1, "io_submit": 2, "io_getevents": 4,
		"epoll_ctl": 21, "exit_group": 94, "openat": 56, "epoll_pwait": 22, "eventfd2": 19,
		"epoll_create1": 20, "pipe2": 59, "preadv": 69, "pwritev": 70, "seccomp": 277,
		"getrandom": 278, "memfd_create": 279, "execve": 221, "close_range": 436,
		"landlock_create_ruleset": 444, "landlock_add_rule": 445, "landlock_restrict_self": 446,
		"timerfd_create": 85, "fallocate": 47, "fsync": 82, "sigaltstack": 132, "tkill": 130,
	},
}

// The calls the task of this filter names; each must be refused on both
// architectures, whatever else the list holds.
var seccompMustDeny = []string{
	"unshare", "setns", "mount", "umount2", "pivot_root", "chroot", "ptrace",
	"process_vm_readv", "process_vm_writev", "keyctl", "add_key", "request_key",
	"bpf", "perf_event_open", "userfaultfd", "init_module", "finit_module",
	"kexec_load", "kexec_file_load", "open_by_handle_at", "name_to_handle_at",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	// Every entry to the mount API, the newest included: a list that
	// names open_tree and not open_tree_attr refuses nothing.
	"open_tree", "open_tree_attr", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick",
	"mount_setattr", "statmount", "listmount",
}

// The numbers of the calls that were added after the list was first
// written, as the kernel's tables have them (the same on every
// architecture): arch/x86/entry/syscalls/syscall_64.tbl and
// scripts/syscall.tbl.
func TestSeccompNamesTheNewerMountCalls(t *testing.T) {
	for name, want := range map[string]uint32{"statmount": 457, "listmount": 458, "open_tree_attr": 467} {
		for goarch, arch := range seccompArches {
			if got, listed := arch.deniedCalls()[name]; !listed || got != want {
				t.Errorf("%s on %s: the filter has %d (listed: %v), the kernel %d", name, goarch, got, listed, want)
			}
		}
	}
}

func TestSeccompFilterOnBothArchitectures(t *testing.T) {
	const (
		threadFlags = 0x003d0f00 // what a C library passes to make a thread
		sigchld     = 17         // a plain fork
	)
	namespaceFlags := map[string]uint64{
		"CLONE_NEWNS": 0x00020000, "CLONE_NEWCGROUP": 0x02000000, "CLONE_NEWUTS": 0x04000000,
		"CLONE_NEWIPC": 0x08000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000, "CLONE_NEWNET": 0x40000000,
	}
	families := map[string]uint64{"AF_INET": 2, "AF_INET6": 10, "AF_NETLINK": 16, "AF_PACKET": 17, "AF_ALG": 38, "AF_VSOCK": 40, "AF_XDP": 44, "AF_UNSPEC": 0}
	for goarch, arch := range seccompArches {
		t.Run(goarch, func(t *testing.T) {
			program, err := seccompProgram(goarch)
			if err != nil {
				t.Fatal(err)
			}
			if len(program) == 0 || len(program) > 4096 {
				t.Fatalf("a filter has between 1 and 4096 instructions, this one %d", len(program))
			}
			// Every jump lands inside the program, and the last
			// instruction is an answer: what the kernel checks before it
			// accepts a filter.
			for at, each := range program {
				if each.Code == bpfJeq || each.Code == bpfJge || each.Code == bpfJset {
					if at+1+int(each.Jt) >= len(program) || at+1+int(each.Jf) >= len(program) {
						t.Fatalf("instruction %d jumps out of the program", at)
					}
				}
			}
			if program[len(program)-1].Code != bpfRet {
				t.Fatal("the program does not end in an answer")
			}
			check := func(what string, want uint32, data [seccompDataSize]byte) {
				t.Helper()
				if got := runBPF(t, program, data); got != want {
					t.Errorf("%s: %s, want %s", what, answerName(got), answerName(want))
				}
			}
			denied := arch.deniedCalls()
			for _, name := range seccompMustDeny {
				if _, ok := denied[name]; !ok {
					t.Errorf("%s is not on the list", name)
				}
			}
			seen := map[uint32]string{}
			for name, nr := range denied {
				if other, dup := seen[nr]; dup {
					t.Errorf("%s and %s have the same number %d", name, other, nr)
				}
				seen[nr] = name
				// Whatever its arguments.
				check(name, answerEPERM, seccompCall(arch.audit, nr))
				check(name+" with arguments", answerEPERM, seccompCall(arch.audit, nr, ^uint64(0), 1, 2, 3, 4, 5))
			}
			for name, nr := range seccompNeeded[goarch] {
				if other, clash := seen[nr]; clash {
					t.Errorf("%s (%d), which a hypervisor needs, has the number of the refused %s", name, nr, other)
				}
				check(name, answerAllow, seccompCall(arch.audit, nr))
				check(name+" with arguments", answerAllow, seccompCall(arch.audit, nr, 0x10000000, 2, 16, 0, 0, 0))
			}
			// A number no table has yet is the hypervisor's own filter's
			// to judge.
			check("an unknown call", answerAllow, seccompCall(arch.audit, 999))

			check("clone3", answerENOSYS, seccompCall(arch.audit, arch.clone3))
			check("clone3 with arguments", answerENOSYS, seccompCall(arch.audit, arch.clone3, 0xdeadbeef, 88))
			check("clone for a thread", answerAllow, seccompCall(arch.audit, arch.clone, threadFlags))
			check("clone as fork", answerAllow, seccompCall(arch.audit, arch.clone, sigchld))
			// The kernel reads the low 32 bits of the flags; what is
			// above them is not a flag.
			check("clone with only high bits set", answerAllow, seccompCall(arch.audit, arch.clone, 0x10000000<<32|threadFlags))
			var every uint64
			for name, flag := range namespaceFlags {
				every |= flag
				check("clone with "+name, answerEPERM, seccompCall(arch.audit, arch.clone, flag|sigchld))
				check("clone for a thread with "+name, answerEPERM, seccompCall(arch.audit, arch.clone, flag|threadFlags))
				check("clone with "+name+" and high bits", answerEPERM, seccompCall(arch.audit, arch.clone, 0xffffffff<<32|flag))
			}
			if every != cloneNamespaceFlags {
				t.Errorf("the filter's namespace flags are %#x, want %#x", cloneNamespaceFlags, every)
			}
			for _, call := range []struct {
				name string
				nr   uint32
			}{{"socket", arch.socket}, {"socketpair", arch.socketpair}} {
				check(call.name+"(AF_UNIX)", answerAllow, seccompCall(arch.audit, call.nr, afUnix, 1, 0))
				for family, value := range families {
					check(call.name+"("+family+")", answerEPERM, seccompCall(arch.audit, call.nr, value, 1, 0))
				}
			}

			// Another architecture's table: not judged, killed. The
			// numbers would mean other calls.
			for name, foreign := range map[string]uint32{"i386": 0x40000003, "arm": 0x40000028, "riscv64": 0xc00000f3, "none": 0} {
				check("a read made as "+name, answerKill, seccompCall(foreign, seccompNeeded[goarch]["read"]))
			}
			for other, otherArch := range seccompArches {
				if other != goarch {
					check("a read made as "+other, answerKill, seccompCall(otherArch.audit, seccompNeeded[goarch]["read"]))
				}
			}
			x32 := seccompCall(arch.audit, x32Bit|seccompNeeded[goarch]["read"])
			if arch.x32 {
				check("a read through the x32 table", answerKill, x32)
				check("a mount through the x32 table", answerKill, seccompCall(arch.audit, x32Bit|denied["mount"]))
			} else {
				check("a number with the x32 bit, where there is no x32", answerAllow, x32)
			}
		})
	}
}

func TestSeccompFilterRefusesAnUnknownArchitecture(t *testing.T) {
	if _, err := seccompProgram("riscv64"); err == nil {
		t.Fatal("a filter was made for an architecture whose system call numbers the driver does not know")
	}
}
