package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// The numbers the filter is built from, against the ones the syscall
// package has for the architecture this test was compiled for: a table
// typed in from another architecture's would pass every other unit test.
func TestSeccompNumbersAreThisArchitectures(t *testing.T) {
	arch, ok := seccompArches[runtime.GOARCH]
	if !ok {
		t.Skipf("no filter for %s", runtime.GOARCH)
	}
	denied := arch.deniedCalls()
	for name, want := range map[string]uintptr{
		"ptrace": syscall.SYS_PTRACE, "mount": syscall.SYS_MOUNT, "umount2": syscall.SYS_UMOUNT2,
		"pivot_root": syscall.SYS_PIVOT_ROOT, "chroot": syscall.SYS_CHROOT, "unshare": syscall.SYS_UNSHARE,
		"keyctl": syscall.SYS_KEYCTL, "add_key": syscall.SYS_ADD_KEY, "request_key": syscall.SYS_REQUEST_KEY,
		"perf_event_open": syscall.SYS_PERF_EVENT_OPEN, "init_module": syscall.SYS_INIT_MODULE,
		"delete_module": syscall.SYS_DELETE_MODULE, "kexec_load": syscall.SYS_KEXEC_LOAD,
		"swapon": syscall.SYS_SWAPON, "swapoff": syscall.SYS_SWAPOFF, "reboot": syscall.SYS_REBOOT,
		"acct": syscall.SYS_ACCT, "settimeofday": syscall.SYS_SETTIMEOFDAY, "clock_settime": syscall.SYS_CLOCK_SETTIME,
		"adjtimex": syscall.SYS_ADJTIMEX, "syslog": syscall.SYS_SYSLOG, "quotactl": syscall.SYS_QUOTACTL,
		"personality": syscall.SYS_PERSONALITY, "sethostname": syscall.SYS_SETHOSTNAME,
		"setdomainname": syscall.SYS_SETDOMAINNAME, "vhangup": syscall.SYS_VHANGUP,
		"fanotify_init": syscall.SYS_FANOTIFY_INIT, "lookup_dcookie": syscall.SYS_LOOKUP_DCOOKIE,
		"nfsservctl": syscall.SYS_NFSSERVCTL,
	} {
		if got, listed := denied[name]; !listed || uintptr(got) != want {
			t.Errorf("%s: the filter has %d (listed: %v), the syscall package %d", name, got, listed, want)
		}
	}
	for name, pair := range map[string][2]uintptr{
		"clone":      {uintptr(arch.clone), syscall.SYS_CLONE},
		"socket":     {uintptr(arch.socket), syscall.SYS_SOCKET},
		"socketpair": {uintptr(arch.socketpair), syscall.SYS_SOCKETPAIR},
		"setns":      {uintptr(denied["setns"]), sysSetns},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: the filter has %d, this architecture %d", name, pair[0], pair[1])
		}
	}
	for name, want := range seccompNeeded[runtime.GOARCH] {
		var have uintptr
		switch name {
		case "read":
			have = syscall.SYS_READ
		case "write":
			have = syscall.SYS_WRITE
		case "ioctl":
			have = syscall.SYS_IOCTL
		case "futex":
			have = syscall.SYS_FUTEX
		case "execve":
			have = syscall.SYS_EXECVE
		case "mmap":
			have = syscall.SYS_MMAP
		case "prctl":
			have = syscall.SYS_PRCTL
		case "seccomp":
			have = sysSeccomp
		default:
			continue
		}
		if uintptr(want) != have {
			t.Errorf("%s: the test's table has %d, this architecture %d", name, want, have)
		}
	}
}

// seccompAttempt is what one call gave a process: "" when it worked.
type seccompAttempt map[string]string

// probeSeccomp makes every call the filter names, and the ones it
// judges by an argument, and reports what each gave. The arguments are
// the ones that do nothing where a call is not refused.
func probeSeccomp() {
	arch := seccompArches[runtime.GOARCH]
	report := seccompAttempt{}
	attempt := func(name string, nr uint32, args ...uintptr) {
		var a [6]uintptr
		copy(a[:], args)
		r1, _, errno := syscall.RawSyscall6(uintptr(nr), a[0], a[1], a[2], a[3], a[4], a[5])
		if errno != 0 {
			report[name] = errno.Error()
			return
		}
		report[name] = ""
		// A descriptor it was given by mistake is not kept.
		if r1 > 2 && r1 < 1<<16 && (strings.HasPrefix(name, "socket(") || name == "userfaultfd" || name == "fanotify_init" || name == "memfd_secret") {
			_ = syscall.Close(int(r1))
		}
	}
	const nobody = 0x7ffffff0 // no process has this ID
	special := map[string][]uintptr{
		// Not PTRACE_TRACEME, which request 0 is.
		"ptrace":         {16 /* PTRACE_ATTACH */, nobody},
		"setns":          {^uintptr(0), 0},
		"keyctl":         {0 /* KEYCTL_GET_KEYRING_ID */, ^uintptr(2) /* the session keyring */, 0},
		"personality":    {0xffffffff /* ask, change nothing */},
		"pidfd_getfd":    {^uintptr(0), 0, 0},
		"kcmp":           {nobody, nobody, 0, 0, 0},
		"io_uring_enter": {^uintptr(0), 0, 0, 0, 0, 0},
	}
	for name, nr := range arch.deniedCalls() {
		attempt(name, nr, special[name]...)
	}
	attempt("unshare(CLONE_NEWUSER)", arch.denied["unshare"], syscall.CLONE_NEWUSER)
	attempt("unshare(CLONE_NEWNET)", arch.denied["unshare"], syscall.CLONE_NEWNET)
	attempt("clone3", arch.clone3, 0, 0)
	var pair [2]int32
	for family, value := range map[string]uintptr{"AF_UNIX": syscall.AF_UNIX, "AF_INET": syscall.AF_INET, "AF_INET6": syscall.AF_INET6, "AF_NETLINK": syscall.AF_NETLINK, "AF_PACKET": syscall.AF_PACKET, "AF_VSOCK": 40} {
		attempt("socket("+family+")", arch.socket, value, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		attempt("socketpair("+family+")", arch.socketpair, value, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0, uintptr(unsafe.Pointer(&pair)))
	}
	// clone, last: with a namespace flag it must be refused. Should it
	// not be, the child ends at once and says so by its exit status.
	if os.Getenv(jailProbeEnv+"_CLONE") != "" {
		for name, flags := range map[string]uintptr{
			"clone(CLONE_NEWUSER)": syscall.CLONE_NEWUSER | uintptr(syscall.SIGCHLD),
			"clone(CLONE_NEWNET)":  syscall.CLONE_NEWNET | uintptr(syscall.SIGCHLD),
			"clone(CLONE_NEWNS)":   syscall.CLONE_NEWNS | uintptr(syscall.SIGCHLD),
			"clone(CLONE_NEWPID)":  syscall.CLONE_NEWPID | uintptr(syscall.SIGCHLD),
			"clone as fork":        uintptr(syscall.SIGCHLD),
		} {
			child, _, errno := syscall.RawSyscall6(uintptr(arch.clone), flags, 0, 0, 0, 0, 0)
			if errno != 0 {
				report[name] = errno.Error()
				continue
			}
			if child == 0 {
				// The child: nothing but an exit.
				syscall.RawSyscall(syscall.SYS_EXIT_GROUP, 0, 0, 0)
			}
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(int(child), &status, 0, nil)
			report[name] = ""
		}
		// And a thread, as the runtime makes one: the filter is on it too.
		done := make(chan string)
		go func() {
			runtime.LockOSThread()
			_, _, errno := syscall.RawSyscall(uintptr(arch.denied["unshare"]), syscall.CLONE_NEWUSER, 0, 0)
			done <- errno.Error()
		}()
		report["unshare(CLONE_NEWUSER) on a new thread"] = <-done
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
}

// Every call the filter names, made by a process that came through the
// jail helper: the kernel answers each as the filter says. The same
// calls from a process with the same UID and no filter are the control:
// where one of them is refused there too, it is the kernel's own refusal
// of an unprivileged process and proves nothing about the filter, and
// the test says which those are.
func TestJailRefusesTheCallsTheFilterNames(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("building a jail needs root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if libraries, err := hypervisorLibraries(self); err != nil || len(libraries) != 0 {
		t.Skip("this test binary is not statically linked (build it with CGO_ENABLED=0)")
	}
	if err := seccompAvailable(); err != nil {
		t.Fatalf("the host check for seccomp: %v", err)
	}
	const uid = 70123
	base, err := os.MkdirTemp("/tmp", "jail-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	root, dir, kernel := filepath.Join(base, "mine"+jailRootSuffix), filepath.Join(base, "mine"), filepath.Join(base, "Image")
	for _, each := range []string{root, dir} {
		if err := os.Mkdir(each, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(kernel, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	spec := jailFor(root, uid, nil, self, kernel, "/dev/null", dir, nil)
	for i := range spec.Paths {
		if spec.Paths[i].Path == kvmDevice {
			spec.Paths[i].Path = "/dev/zero"
		}
	}
	run := func(cmd *exec.Cmd, clone bool) seccompAttempt {
		t.Helper()
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		cmd.Env = []string{jailProbeEnv + "=seccomp"}
		if clone {
			cmd.Env = append(cmd.Env, jailProbeEnv+"_CLONE=1")
		}
		cmd.Dir = "/"
		if err := cmd.Run(); err != nil {
			t.Fatalf("probe: %v\n%s", err, stderr.String())
		}
		report := seccompAttempt{}
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("report: %v\n%s\n%s", err, stdout.String(), stderr.String())
		}
		return report
	}
	jailed, err := jailCommand(spec, jailTestCgroup(t), self, nil)
	if err != nil {
		t.Fatal(err)
	}
	inside := run(jailed, true)
	// The control: the same UID, no jail and no filter. It makes no
	// clone: one that worked would be a second copy of this program.
	plain := exec.Command(runnableCopy(t, base))
	plain.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	outside := run(plain, false)

	const eperm, enosys = "operation not permitted", "function not implemented"
	want := map[string]string{
		"clone3": enosys, "clone as fork": "", "socket(AF_UNIX)": "", "socketpair(AF_UNIX)": "",
	}
	for name := range inside {
		if _, set := want[name]; !set {
			want[name] = eperm
		}
	}
	names := make([]string, 0, len(inside))
	for name := range inside {
		names = append(names, name)
	}
	sort.Strings(names)
	var lines, proven, unproven []string
	for _, name := range names {
		got, control, hasControl := inside[name], outside[name], true
		if _, hasControl = outside[name]; !hasControl {
			control = "(not made)"
		}
		show := func(result string) string {
			if result == "" {
				return "ok"
			}
			return result
		}
		lines = append(lines, fmt.Sprintf("%-40s under the filter: %-26s without: %s", name, show(got), show(control)))
		if got != want[name] {
			t.Errorf("%s under the filter: %q, want %q", name, show(got), show(want[name]))
		}
		if want[name] == eperm || want[name] == enosys {
			if hasControl && control != want[name] {
				proven = append(proven, name)
			} else if hasControl {
				unproven = append(unproven, name)
			}
		}
	}
	t.Logf("%d calls on %s:\n  %s", len(names), runtime.GOARCH, strings.Join(lines, "\n  "))
	t.Logf("refused by the filter and not by the kernel itself (%d): %s", len(proven), strings.Join(proven, ", "))
	t.Logf("refused without the filter too, so the filter is not what this run shows (%d): %s", len(unproven), strings.Join(unproven, ", "))
	// The ones an unprivileged process can make on any kernel: these
	// must be the filter's doing.
	for _, name := range []string{"socket(AF_INET)", "socket(AF_NETLINK)", "socket(AF_INET6)", "setns", "keyctl", "personality", "clone3", "unshare(CLONE_NEWUSER)"} {
		if outside[name] == inside[name] {
			t.Errorf("control: %s gives %q without the filter as well; the filter is not shown to refuse it", name, outside[name])
		}
	}
	for _, name := range []string{"clone(CLONE_NEWUSER)", "clone(CLONE_NEWNET)", "clone(CLONE_NEWNS)", "clone(CLONE_NEWPID)", "unshare(CLONE_NEWUSER) on a new thread"} {
		if inside[name] != eperm {
			t.Errorf("%s under the filter: %q", name, inside[name])
		}
	}
}
