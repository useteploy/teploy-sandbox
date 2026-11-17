package vm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fillReport is how far a process got filling a directory.
type fillReport struct {
	// Bytes is what one file took before a write failed, WriteError why
	// it did; Files and CreateError the same for empty files.
	Bytes       int64
	WriteError  string
	Files       int
	CreateError string
}

// probeFill writes to dir until it cannot: first one file, then names.
// What it made stays, for whoever asked to look at.
func probeFill(dir string) {
	var report fillReport
	file, err := os.OpenFile(filepath.Join(dir, "fill"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		report.WriteError = err.Error()
	} else {
		chunk := make([]byte, 4096)
		for report.Bytes < 64<<20 {
			n, err := file.Write(chunk)
			report.Bytes += int64(n)
			if err != nil {
				report.WriteError = err.Error()
				break
			}
		}
		file.Close()
	}
	for report.Files < 100000 {
		file, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("name-%d", report.Files)), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			report.CreateError = err.Error()
			break
		}
		file.Close()
		report.Files++
	}
	_ = json.NewEncoder(os.Stdout).Encode(report)
}

// filesystemUse is the blocks and inodes in use on the filesystem that
// holds path.
func filesystemUse(t *testing.T, path string) (blocks, inodes int64) {
	t.Helper()
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		t.Fatal(err)
	}
	return int64(stat.Blocks-stat.Bfree) * int64(stat.Bsize) / 4096, int64(stat.Files - stat.Ffree)
}

// A VM's socket directory, as the daemon mounts it: a process with the
// VM's UID fills it and gets no further than the filesystem's own few
// blocks and names, and the filesystem under it does not notice.
func TestSocketDirIsBounded(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("mounting needs root")
	}
	const uid = 70123
	// On /run where there is one: the host's tmpfs a VM's dir is on.
	parent := "/run"
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		parent = "/tmp"
	}
	base, err := os.MkdirTemp(parent, "sockdir-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	// The probe program, where the other UID can start it; /run and
	// /tmp may both refuse to execute anything.
	programs, err := os.MkdirTemp("/var/tmp", "sockdir-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(programs)
	if err := os.Chmod(programs, 0o711); err != nil {
		t.Fatal(err)
	}
	self := runnableCopy(t, programs)
	if err := probeSocketDir(base); err != nil {
		t.Fatalf("the host check: %v", err)
	}
	dir := filepath.Join(base, "vm")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fill := func() fillReport {
		t.Helper()
		cmd := exec.Command(self)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		cmd.Env = []string{jailProbeEnv + "=fill", jailProbeEnv + "_DIR=" + dir}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("fill: %v\n%s", err, stderr.String())
		}
		var report fillReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("report: %v\n%s", err, stdout.String())
		}
		return report
	}
	blocksBefore, inodesBefore := filesystemUse(t, base)
	if err := mountSocketDir(dir); err != nil {
		t.Fatal(err)
	}
	defer unmountSocketDir(dir)
	if err := os.Lchown(dir, uid, uid); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 || info.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatalf("the mounted dir: %v %v, want 0700 and the VM's", info, err)
	}
	report := fill()
	blocksAfter, inodesAfter := filesystemUse(t, base)
	t.Logf("as uid %d in the mounted dir: one file took %d bytes before %q; %d more names before %q", uid, report.Bytes, report.WriteError, report.Files, report.CreateError)
	t.Logf("the filesystem under it (%s): %d blocks of 4 KiB and %d inodes in use before, %d and %d after", parent, blocksBefore, inodesBefore, blocksAfter, inodesAfter)
	if report.Bytes > SocketDirKB<<10 || !strings.Contains(report.WriteError, "no space left") {
		t.Errorf("a file grew to %d bytes (%q), want at most %d KiB and then no space", report.Bytes, report.WriteError, SocketDirKB)
	}
	if report.Files >= SocketDirInodes || report.CreateError == "" {
		t.Errorf("%d names were made (%q), want fewer than %d inodes' worth", report.Files, report.CreateError, SocketDirInodes)
	}
	// Other things write to /run too; what was tried here is 64 MiB and
	// 100000 names.
	if grew := blocksAfter - blocksBefore; grew > 8 {
		t.Errorf("the filesystem under the dir grew by %d blocks", grew)
	}
	if grew := inodesAfter - inodesBefore; grew > 8 {
		t.Errorf("the filesystem under the dir gained %d inodes", grew)
	}
	// Taken away, with everything in it: the dir is empty and the VM's
	// files are nowhere.
	if err := unmountSocketDir(dir); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("after the unmount the dir holds %v (%v)", entries, err)
	}
	if err := unmountSocketDir(dir); err != nil {
		t.Errorf("unmounting what is not mounted: %v", err)
	}
	if err := unmountSocketDir(filepath.Join(base, "absent")); err != nil {
		t.Errorf("unmounting what is not there: %v", err)
	}
	mounts, _ := os.ReadFile("/proc/self/mountinfo")
	if strings.Contains(string(mounts), base) {
		t.Errorf("a mount is left:\n%s", mounts)
	}

	// The control: the same process in the same dir without its own
	// filesystem takes what it asks for from the host's.
	if err := os.Lchown(dir, uid, uid); err != nil {
		t.Fatal(err)
	}
	control := fillControl(t, dir, uid)
	blocksControl, _ := filesystemUse(t, base)
	t.Logf("control, the same dir with nothing mounted on it: a file of %d bytes, and the filesystem under it grew by %d blocks", control, blocksControl-blocksAfter)
	if control <= SocketDirKB<<10 {
		t.Errorf("control: without the mount the process wrote only %d bytes; the limit above is not shown to be the mount's", control)
	}
}

// runnableCopy puts this test binary where a process of any UID can
// start it: the directory it was built in may be its builder's alone.
func runnableCopy(t *testing.T, dir string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(dir, "probe")
	if err := os.WriteFile(copied, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return copied
}

// fillControl writes one megabyte into dir as uid and returns how much
// of it arrived.
func fillControl(t *testing.T, dir string, uid uint32) int64 {
	t.Helper()
	cmd := exec.Command("dd", "if=/dev/zero", "of="+filepath.Join(dir, "control"), "bs=4096", "count=256")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
	_ = cmd.Run()
	info, err := os.Stat(filepath.Join(dir, "control"))
	if err != nil {
		return 0
	}
	return info.Size()
}
