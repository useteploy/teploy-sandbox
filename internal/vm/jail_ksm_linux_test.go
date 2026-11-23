package vm

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// prGetMemoryMerge is PR_GET_MEMORY_MERGE: 1 when every mapping of the
// calling process is mergeable by KSM.
const prGetMemoryMerge = 68

// ksmReport is what a process found about KSM: the flag it was started
// with, and what asking to turn merging on gave ("" when it worked).
type ksmReport struct {
	Flag    string
	Set     string
	Madvise string
}

func errnoText(errno syscall.Errno) string {
	if errno == 0 {
		return ""
	}
	return errno.Error()
}

// probeKSM reports the process's PR_SET_MEMORY_MERGE flag first, then
// tries both ways of making memory mergeable.
func probeKSM() {
	var report ksmReport
	flag, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prGetMemoryMerge, 0, 0, 0, 0, 0)
	if errno != 0 {
		report.Flag = errno.Error()
	} else {
		report.Flag = strconv.Itoa(int(flag))
	}
	_, _, errno = syscall.RawSyscall6(syscall.SYS_PRCTL, prSetMemoryMerge, 1, 0, 0, 0, 0)
	report.Set = errnoText(errno)
	page, err := syscall.Mmap(-1, 0, os.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		report.Madvise = "mmap: " + err.Error()
	} else {
		_, _, errno = syscall.RawSyscall(syscall.SYS_MADVISE, uintptr(unsafe.Pointer(&page[0])), uintptr(len(page)), madvMergeable)
		report.Madvise = errnoText(errno)
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
}

// A daemon whose memory is mergeable by KSM (PR_SET_MEMORY_MERGE, which
// a systemd unit's MemoryKSM=yes sets) does not hand that to the
// hypervisor: the jail helper clears it before the execve, and the
// daemon's filter refuses both ways of asking for it again. The control
// is the same program started by the same process without the jail: it
// is started with the flag, which is what shows that the flag is
// inherited across fork and execve on this kernel and that the clearing
// is the helper's doing.
func TestJailClearsTheMemoryMergeFlag(t *testing.T) {
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
	// This test process becomes the daemon started with the flag. It is
	// put back as it was at the end.
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetMemoryMerge, 1, 0, 0, 0, 0); errno != 0 {
		if errno == syscall.EINVAL {
			t.Skip("this kernel has no PR_SET_MEMORY_MERGE (Linux 6.4 or newer, with CONFIG_KSM): there is no flag to inherit")
		}
		t.Fatalf("set PR_SET_MEMORY_MERGE on the test process: %v", errno)
	}
	t.Cleanup(func() {
		if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetMemoryMerge, 0, 0, 0, 0, 0); errno != 0 {
			t.Errorf("clear PR_SET_MEMORY_MERGE on the test process: %v", errno)
		}
	})
	if flag, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prGetMemoryMerge, 0, 0, 0, 0, 0); errno != 0 || flag != 1 {
		t.Fatalf("the test process's flag after setting it: %d %v", flag, errno)
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
	run := func(cmd *exec.Cmd) ksmReport {
		t.Helper()
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		cmd.Env = []string{jailProbeEnv + "=ksm"}
		cmd.Dir = "/"
		if err := cmd.Run(); err != nil {
			t.Fatalf("probe: %v\n%s", err, stderr.String())
		}
		var report ksmReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("report: %v\n%s\n%s", err, stdout.String(), stderr.String())
		}
		return report
	}
	jailed, err := jailCommand(spec, jailTestCgroup(t), self, nil)
	if err != nil {
		t.Fatal(err)
	}
	inside := run(jailed)
	plain := exec.Command(runnableCopy(t, base))
	plain.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	outside := run(plain)
	t.Logf("started by a process with PR_SET_MEMORY_MERGE set: jailed %+v; without the jail %+v", inside, outside)

	if outside.Flag != "1" {
		t.Errorf("control: a program started without the jail has PR_GET_MEMORY_MERGE %q, want 1 (inherited across fork and execve); the jailed result proves nothing on this kernel", outside.Flag)
	}
	if outside.Set != "" || outside.Madvise != "" {
		t.Errorf("control: without the filter, PR_SET_MEMORY_MERGE gave %q and MADV_MERGEABLE %q; the refusals under the filter are not shown to be the filter's", outside.Set, outside.Madvise)
	}
	if inside.Flag != "0" {
		t.Errorf("the jailed program has PR_GET_MEMORY_MERGE %q, want 0: its memory is mergeable by KSM", inside.Flag)
	}
	const eperm = "operation not permitted"
	if inside.Set != eperm {
		t.Errorf("PR_SET_MEMORY_MERGE in the jail: %q, want %q", inside.Set, eperm)
	}
	if inside.Madvise != eperm {
		t.Errorf("MADV_MERGEABLE in the jail: %q, want %q", inside.Madvise, eperm)
	}
}
