package vm

import (
	"fmt"
	"sort"
)

// The daemon's own seccomp filter.
//
// The hypervisor filters its own system calls, per thread, and the
// threads a guest drives are held tightly. Its main thread is not: its
// filter lets it clone with any flags, open sockets of any family and
// set up io_uring, and threads share memory, so code execution in any
// thread is, with more work, code execution under the widest filter. A
// filter of the hypervisor's is also only as good as the hypervisor
// version that wrote it, and it is not there before the hypervisor has
// installed it.
//
// So the jail helper installs a filter of the daemon's just before it
// executes the hypervisor. Filters stack: the kernel runs every one and
// takes the strictest answer, so this one can only take away. It is a
// denylist, not an allowlist: what a hypervisor needs differs by version,
// architecture and device, and a call missing from an allowlist kills a
// VM at an hour nobody tested; the hypervisor's own allowlist is still
// in force for everything this list does not name. What is named is what
// widens the kernel surface or the reach of a process that was taken
// over, and what no hypervisor has a use for:
//
//   - new namespaces by any road: unshare, setns, clone with a namespace
//     flag. clone3 is answered with ENOSYS: its flags are behind a
//     pointer, which a filter cannot read, and a C library that is told
//     the call does not exist falls back to clone, whose flags are an
//     argument.
//   - sockets of any family but unix. The VM's own sockets (its API and
//     its vsock backend) are unix sockets; its tap is a descriptor it is
//     handed.
//   - io_uring. The hypervisor probes for it and uses the kernel's older
//     asynchronous I/O for the guest's disk when it is refused.
//   - the mount calls, other processes' memory, kernel keyrings, bpf,
//     perf events, userfaultfd, modules, kexec, file handles, and the
//     calls that only an administrator has a use for.
//   - the two ways to make memory mergeable by KSM: prctl with
//     PR_SET_MEMORY_MERGE (every mapping of the process) and madvise
//     with MADV_MERGEABLE (one range). KSM merges equal pages across
//     every process on the host that asked for it, and how long a write
//     to a merged page takes tells whoever wrote it that someone else
//     had the same page. The hypervisor is started with mergeable=off
//     and the jail helper clears the inherited flag; this keeps a
//     hypervisor that was taken over from asking again. prctl and
//     madvise are otherwise allowed: the hypervisor uses both.
//
// A denied call fails with EPERM and the process lives: the list is
// there to take the calls away, and a thread that asks for one out of
// habit (a probe for a kernel feature) must not cost a run. A system
// call made for another architecture's table is not judged at all: the
// process is killed.
//
// execve cannot be on the list: the filter is installed before the one
// execve that starts the hypervisor. The hypervisor's own filters refuse
// it from then on.

// bpfInsn is one instruction of a classic BPF program, as the kernel
// reads it (struct sock_filter).
type bpfInsn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// Classic BPF, as much of it as a seccomp filter uses.
const (
	bpfLdAbsW = 0x20 // A = the 32-bit word at offset K of seccomp_data
	bpfJeq    = 0x15 // if A == K
	bpfJge    = 0x35 // if A >= K
	bpfJset   = 0x45 // if A & K
	bpfRet    = 0x06 // return K
)

// What a filter answers (SECCOMP_RET_*).
const (
	seccompKillProcess = 0x80000000
	seccompErrno       = 0x00050000
	seccompAllow       = 0x7fff0000

	errnoEPERM  = 1
	errnoENOSYS = 38
)

// struct seccomp_data: the call's number, the architecture whose table
// the number is from, the instruction pointer and six 64-bit arguments.
// Both architectures here are little-endian, so the low half of an
// argument comes first.
const (
	seccompDataNr   = 0
	seccompDataArch = 4
	seccompDataArg0 = 16
	seccompDataSize = 64
)

// x32Bit marks, on x86-64, a call made through the x32 table: the same
// architecture value with other numbers.
const x32Bit = 0x40000000

// The namespaces clone can make. CLONE_NEWTIME is not among them: in
// clone's flags that bit is part of the exit signal, and a time
// namespace can only be made with unshare or clone3.
const cloneNamespaceFlags = 0x00020000 | // CLONE_NEWNS
	0x02000000 | // CLONE_NEWCGROUP
	0x04000000 | // CLONE_NEWUTS
	0x08000000 | // CLONE_NEWIPC
	0x10000000 | // CLONE_NEWUSER
	0x20000000 | // CLONE_NEWPID
	0x40000000 // CLONE_NEWNET

const afUnix = 1

// The KSM requests the filter refuses: prctl's option (its first
// argument) and madvise's advice (its third). Both are an int, so the
// low 32 bits the filter reads are the whole value, as the kernel reads
// it.
const (
	prSetMemoryMergeOption = 67 // PR_SET_MEMORY_MERGE
	madvMergeable          = 12 // MADV_MERGEABLE
	seccompDataArg2        = seccompDataArg0 + 2*8
)

// seccompArch is one architecture's system call table, as far as the
// filter names calls.
type seccompArch struct {
	// audit is the AUDIT_ARCH_* value the kernel reports for a native
	// call.
	audit uint32
	// x32 says the architecture has a second table behind x32Bit.
	x32 bool
	// The calls that are judged by an argument.
	clone, clone3, socket, socketpair, prctl, madvise uint32
	// denied is every call that is refused outright, by name.
	denied map[string]uint32
}

// sharedDenied are the refused calls that have one number on every
// architecture (everything added since Linux 5.1 has). The mount calls
// are all of them, the ones that only read as well: statmount and
// listmount tell a process what is mounted where and from what, which
// the jail, having no /proc, otherwise keeps from it, and
// open_tree_attr is open_tree and mount_setattr in one call.
var sharedDenied = map[string]uint32{
	"io_uring_setup":    425,
	"io_uring_enter":    426,
	"io_uring_register": 427,
	"open_tree":         428,
	"move_mount":        429,
	"fsopen":            430,
	"fsconfig":          431,
	"fsmount":           432,
	"fspick":            433,
	"pidfd_getfd":       438,
	"process_madvise":   440,
	"mount_setattr":     442,
	"quotactl_fd":       443,
	"memfd_secret":      447,
	"statmount":         457,
	"listmount":         458,
	"open_tree_attr":    467,
}

var seccompArches = map[string]seccompArch{
	"amd64": {
		audit: 0xc000003e, x32: true,
		clone: 56, clone3: 435, socket: 41, socketpair: 53, prctl: 157, madvise: 28,
		denied: map[string]uint32{
			"ptrace": 101, "syslog": 103, "uselib": 134, "personality": 135,
			"vhangup": 153, "modify_ldt": 154, "pivot_root": 155, "_sysctl": 156,
			"adjtimex": 159, "chroot": 161, "acct": 163, "settimeofday": 164,
			"mount": 165, "umount2": 166, "swapon": 167, "swapoff": 168,
			"reboot": 169, "sethostname": 170, "setdomainname": 171, "iopl": 172,
			"ioperm": 173, "create_module": 174, "init_module": 175, "delete_module": 176,
			"get_kernel_syms": 177, "query_module": 178, "quotactl": 179, "nfsservctl": 180,
			"lookup_dcookie": 212, "clock_settime": 227, "kexec_load": 246, "add_key": 248,
			"request_key": 249, "keyctl": 250, "unshare": 272, "perf_event_open": 298,
			"fanotify_init": 300, "name_to_handle_at": 303, "open_by_handle_at": 304, "clock_adjtime": 305,
			"setns": 308, "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312,
			"finit_module": 313, "kexec_file_load": 320, "bpf": 321, "userfaultfd": 323,
		},
	},
	"arm64": {
		audit: 0xc00000b7,
		clone: 220, clone3: 435, socket: 198, socketpair: 199, prctl: 167, madvise: 233,
		denied: map[string]uint32{
			"lookup_dcookie": 18, "umount2": 39, "mount": 40, "pivot_root": 41,
			"nfsservctl": 42, "chroot": 51, "vhangup": 58, "quotactl": 60,
			"acct": 89, "personality": 92, "unshare": 97, "kexec_load": 104,
			"init_module": 105, "delete_module": 106, "clock_settime": 112, "syslog": 116,
			"ptrace": 117, "reboot": 142, "sethostname": 161, "setdomainname": 162,
			"settimeofday": 170, "adjtimex": 171, "add_key": 217, "request_key": 218,
			"keyctl": 219, "swapon": 224, "swapoff": 225, "perf_event_open": 241,
			"fanotify_init": 262, "name_to_handle_at": 264, "open_by_handle_at": 265, "clock_adjtime": 266,
			"setns": 268, "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272,
			"finit_module": 273, "bpf": 280, "userfaultfd": 282, "kexec_file_load": 294,
		},
	},
}

// deniedCalls is every call the filter refuses outright on an
// architecture, by name.
func (a seccompArch) deniedCalls() map[string]uint32 {
	all := make(map[string]uint32, len(a.denied)+len(sharedDenied))
	for name, nr := range sharedDenied {
		all[name] = nr
	}
	for name, nr := range a.denied {
		all[name] = nr
	}
	return all
}

// bpfMaxJump is how far a conditional jump reaches.
const bpfMaxJump = 255

// seccompProgram is the filter for one architecture.
//
// It reads top to bottom: the architecture, then the call's number
// against each refused call, then the calls judged by an argument. Every answer is one of four return instructions at the end.
func seccompProgram(goarch string) ([]bpfInsn, error) {
	arch, ok := seccompArches[goarch]
	if !ok {
		return nil, fmt.Errorf("the vm driver has no seccomp filter for %s (it has one for amd64 and arm64)", goarch)
	}
	// An instruction that jumps names where to; the places are resolved
	// once the whole program is laid out.
	type insn struct {
		code   uint16
		k      uint32
		jt, jf string
	}
	var body []insn
	labels := map[string]int{}
	emit := func(code uint16, k uint32, jt, jf string) { body = append(body, insn{code, k, jt, jf}) }
	label := func(name string) { labels[name] = len(body) }

	emit(bpfLdAbsW, seccompDataArch, "", "")
	emit(bpfJeq, arch.audit, "", "kill")
	emit(bpfLdAbsW, seccompDataNr, "", "")
	if arch.x32 {
		emit(bpfJge, x32Bit, "kill", "")
	}
	emit(bpfJeq, arch.clone, "clone", "")
	emit(bpfJeq, arch.socket, "socket", "")
	emit(bpfJeq, arch.socketpair, "socket", "")
	emit(bpfJeq, arch.clone3, "enosys", "")
	emit(bpfJeq, arch.prctl, "prctl", "")
	emit(bpfJeq, arch.madvise, "madvise", "")
	denied := arch.deniedCalls()
	numbers := make([]uint32, 0, len(denied))
	for _, nr := range denied {
		numbers = append(numbers, nr)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	// A conditional jump reaches 255 instructions, which is more than
	// the whole program has; a list that outgrew it would fail below.
	for _, nr := range numbers {
		emit(bpfJeq, nr, "eperm", "")
	}
	emit(bpfRet, seccompAllow, "", "")
	// clone: refused with a namespace flag, and otherwise how a thread
	// is made.
	label("clone")
	emit(bpfLdAbsW, seccompDataArg0, "", "")
	emit(bpfJset, cloneNamespaceFlags, "eperm", "allow")
	// socket and socketpair: the family is the first argument.
	label("socket")
	emit(bpfLdAbsW, seccompDataArg0, "", "")
	emit(bpfJeq, afUnix, "allow", "eperm")
	// prctl: refused for PR_SET_MEMORY_MERGE, whichever way it is set.
	label("prctl")
	emit(bpfLdAbsW, seccompDataArg0, "", "")
	emit(bpfJeq, prSetMemoryMergeOption, "eperm", "allow")
	// madvise: refused for MADV_MERGEABLE.
	label("madvise")
	emit(bpfLdAbsW, seccompDataArg2, "", "")
	emit(bpfJeq, madvMergeable, "eperm", "allow")
	label("allow")
	emit(bpfRet, seccompAllow, "", "")
	label("eperm")
	emit(bpfRet, seccompErrno|errnoEPERM, "", "")
	label("enosys")
	emit(bpfRet, seccompErrno|errnoENOSYS, "", "")
	label("kill")
	emit(bpfRet, seccompKillProcess, "", "")

	program := make([]bpfInsn, len(body))
	for at, each := range body {
		out := bpfInsn{Code: each.code, K: each.k}
		for _, jump := range []struct {
			to   string
			slot *uint8
		}{{each.jt, &out.Jt}, {each.jf, &out.Jf}} {
			if jump.to == "" {
				continue
			}
			target, ok := labels[jump.to]
			distance := target - at - 1
			if !ok || distance < 0 || distance > bpfMaxJump {
				return nil, fmt.Errorf("seccomp filter for %s: instruction %d cannot jump to %q", goarch, at, jump.to)
			}
			*jump.slot = uint8(distance)
		}
		program[at] = out
	}
	return program, nil
}
