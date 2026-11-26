package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// hostClass is everything a memory image depends on of the host it was
// saved on. The hypervisor's snapshot holds vCPU and device state whose
// layout is the hypervisor's, which KVM takes or refuses by the CPU it
// is asked to put it back on; the guest kernel is in the guest's memory
// and in its devices' expectations. An image restores only where every
// one of these is what it was, and anywhere else the run boots from its
// disk.
type hostClass struct {
	// id is the class: the SHA-256 of the parts below, as hex.
	id string
	// hypervisor is the hypervisor's version and kernel the guest
	// kernel's SHA-256, kept beside the digest so that a mismatch can
	// say what changed.
	hypervisor, kernel string
}

// classParts are what a class is computed from.
type classParts struct {
	arch string
	// kernel is the host kernel's release, whole: a stable-series
	// update can change what KVM's state holds.
	kernel string
	// cpu is the first processor of /proc/cpuinfo: vendor, family,
	// model, stepping and flags, from which KVM derives the CPU the
	// guest sees.
	cpu string
	// hypervisor is the hypervisor binary's SHA-256 and
	// hypervisorVersion what it prints for --version.
	hypervisor, hypervisorVersion string
	// guestKernel is the guest kernel image's SHA-256.
	guestKernel string
}

func (p classParts) class() hostClass {
	text := fmt.Sprintf("arch=%s\nkernel=%s\nhypervisor=%s\nhypervisor-version=%s\nguest-kernel=%s\n%s\n",
		p.arch, p.kernel, p.hypervisor, p.hypervisorVersion, p.guestKernel, p.cpu)
	sum := sha256.Sum256([]byte(text))
	return hostClass{id: hex.EncodeToString(sum[:]), hypervisor: p.hypervisorVersion, kernel: p.guestKernel}
}

// cpuIdentity is the first processor's stanza of /proc/cpuinfo, as it
// is written, with trailing blanks dropped.
func cpuIdentity(cpuinfo []byte) string {
	text := string(cpuinfo)
	if end := strings.Index(text, "\n\n"); end >= 0 {
		text = text[:end]
	}
	var lines []string
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimRight(line, " \t"); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// hypervisorVersion is what the hypervisor says of itself, on one line.
func hypervisorVersion(out []byte) string {
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line)
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// detectHostClass measures this host's class.
func detectHostClass(ctx context.Context, config Config, hypervisor string) (hostClass, error) {
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return hostClass{}, fmt.Errorf("the host kernel's release: %w", err)
	}
	cpu, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return hostClass{}, fmt.Errorf("the host's CPUs: %w", err)
	}
	binary, err := sha256File(hypervisor)
	if err != nil {
		return hostClass{}, fmt.Errorf("the hypervisor binary: %w", err)
	}
	version, err := (execCommander{}).Run(ctx, hypervisor, "--version")
	if err != nil {
		return hostClass{}, fmt.Errorf("the hypervisor's version: %w", err)
	}
	guest, err := sha256File(config.Kernel)
	if err != nil {
		return hostClass{}, fmt.Errorf("the guest kernel image: %w", err)
	}
	return (classParts{
		arch: runtime.GOARCH, kernel: strings.TrimSpace(string(release)),
		cpu:               cpuIdentity(cpu),
		hypervisor:        binary,
		hypervisorVersion: hypervisorVersion(version),
		guestKernel:       guest,
	}).class(), nil
}
