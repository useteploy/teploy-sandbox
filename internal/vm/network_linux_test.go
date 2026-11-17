package vm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
)

// setns has a number on both architectures the driver is built for. The
// syscall package names it on arm64 and not on amd64, so code that used
// the name compiled where it was written and nowhere else: CI builds
// both (see .github/workflows/ci.yml), and this is the same said in a
// test.
func TestSetnsHasANumberOnEveryArchitectureTheDriverIsBuiltFor(t *testing.T) {
	for arch, want := range map[string]uintptr{"amd64": 308, "arm64": 268} {
		if setnsNumbers[arch] != want {
			t.Errorf("setns on %s: %d, want %d", arch, setnsNumbers[arch], want)
		}
	}
	if (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") && sysSetns == 0 {
		t.Errorf("no setns number on %s", runtime.GOARCH)
	}
}

// The number is the right one here: a function run in a namespace sees
// that namespace, and the caller's thread stays where it was.
func TestInNamespaceRunsThere(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("entering a network namespace needs root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip(err)
	}
	name := fmt.Sprintf("tvntest-%d", os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Skipf("no network namespaces here: %v: %s", err, out)
	}
	defer exec.Command("ip", "netns", "del", name).Run()
	own := func() string {
		link, err := os.Readlink("/proc/thread-self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		return link
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, inside := own(), ""
	if err := inNamespace(name, func() error {
		inside = own()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var want string
	if info, err := os.Stat("/run/netns/" + name); err == nil {
		want = fmt.Sprintf("net:[%d]", inodeOf(info))
	}
	if inside == before || inside != want {
		t.Errorf("the function ran in %s, want the namespace %s and not the caller's %s", inside, want, before)
	}
	if after := own(); after != before {
		t.Errorf("the caller's thread moved from %s to %s", before, after)
	}
}

func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
