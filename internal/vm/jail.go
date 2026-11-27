package vm

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// The jail is the file tree, and the set of processes, a hypervisor
// lives in. A hypervisor that a guest took over still has a UID, and a
// UID can connect to every unix socket on the host that anyone may
// connect to (the system bus, the journal, the resolver), read every
// world-readable file and see every process. Landlock does not judge a
// connect to a socket by its path. So the hypervisor is not started in
// the host's tree at all.
//
// The daemon starts its own binary again as a small helper, as root, in
// new mount, PID, IPC, UTS, cgroup and network namespaces and already in
// the VM's cgroup. The helper makes an empty tmpfs, binds into it the few
// paths in a jailSpec and nothing else, makes it the root with
// pivot_root, detaches the old root (the host's tree is then not
// reachable by any path, which a chroot would not give), drops to the
// VM's UID and executes the hypervisor in its place. The hypervisor is
// process 1 of a PID namespace that holds nothing else, and there is no
// /proc and no /sys in its tree.
//
// Every path keeps the name it has on the host, so the command line, the
// hypervisor's own Landlock rules and the daemon's view of the VM's
// sockets (the socket directory is the host's, bound in) are the same
// inside and outside. The one exception is the guest kernel: it is
// bound at JailKernel whatever its path on the host, and the hypervisor
// is told that path. Where an operator keeps it (under /var/lib by
// default) says something about the host's layout, and a jail holds
// nothing of that.

// jailArg0 is the name the daemon's binary is started under to act as
// the jail helper.
const jailArg0 = "teploy-sandbox-vm-jail"

// jailRootSuffix makes, from a VM's runtime dir, the name of the
// directory beside it that the VM's helper mounts its root on. It is only
// a mount point: the mount exists in the helper's namespace and nowhere
// else, the directory stays empty on the host, and it is removed with
// the VM.
const jailRootSuffix = ".jail"

// What a path in the jail is.
const (
	jailFile    = "file"
	jailDir     = "dir"
	jailDevice  = "device"
	jailSymlink = "symlink"
)

// JailKernel is where a VM's jail holds the guest kernel image, and so
// the path the hypervisor is told to boot (and its Landlock rules
// allow), whatever --vm-kernel names on the host.
const JailKernel = "/kernel"

// jailPath is one thing that exists in a jail.
type jailPath struct {
	// Path is where it is in the jail, and on the host unless Source
	// says otherwise.
	Path string `json:"path"`
	// Source is where a file is on the host when that is not Path.
	Source string `json:"source,omitempty"`
	Kind   string `json:"kind"`
	// Write leaves the mount writable and Exec leaves it executable;
	// without them it is read-only and noexec. All are nosuid, and all
	// but a device are nodev.
	Write bool `json:"write,omitempty"`
	Exec  bool `json:"exec,omitempty"`
	// Target is what a symlink points to.
	Target string `json:"target,omitempty"`
	// Slave keeps the bind a slave of the host's mount of the same
	// directory: what the daemon mounts below that directory afterwards
	// appears in the jail too, while nothing below it in the jail reaches
	// the host (a slave receives; it has no peers of its own). It is for
	// a directory whose content is mounted while the VM runs: a VM's
	// outbox, where the daemon mounts each of its memory images for the
	// moment of the snapshot and takes it away again. A directory only,
	// and the daemon must have made the host's mount shared
	// (mountSharedDir) or nothing arrives.
	Slave bool `json:"slave,omitempty"`
}

// jailSpec is everything the helper is told.
type jailSpec struct {
	// Root is an existing directory to mount the jail's root on.
	Root   string   `json:"root"`
	UID    uint32   `json:"uid"`
	GID    uint32   `json:"gid"`
	Groups []uint32 `json:"groups,omitempty"`
	// Paths is the whole content of the jail.
	Paths []jailPath `json:"paths"`
	// Descriptors is how many open files the program is given, counted
	// from 0: its input and two outputs, and whatever the daemon hands it
	// after those (none, for a hypervisor: a VM's tap reaches it later,
	// over its API socket). No other descriptor the helper was started
	// with reaches the program. An open directory of the host would be a
	// way out of the jail's root for whoever holds it, and the daemon
	// cannot know what it was itself started with: a lock file a wrapper
	// script holds, a log, a working directory.
	Descriptors int `json:"descriptors"`
}

// standardDescriptors are a program's input and its two outputs.
const standardDescriptors = 3

func (s jailSpec) validate() error {
	switch {
	case s.UID == 0 || s.GID == 0:
		return errors.New("refusing to start a hypervisor as root")
	case slices.Contains(s.Groups, 0):
		return errors.New("refusing to start a hypervisor in group root")
	case !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) == "/":
		return fmt.Errorf("%q is not a directory to mount a jail on", s.Root)
	case s.Descriptors < standardDescriptors:
		return fmt.Errorf("a jailed program is given at least its %d standard descriptors, not %d", standardDescriptors, s.Descriptors)
	}
	for _, each := range s.Paths {
		if !filepath.IsAbs(each.Path) || filepath.Clean(each.Path) != each.Path || each.Path == "/" {
			return fmt.Errorf("%q is not a path a jail can hold", each.Path)
		}
		if each.Source != "" && (each.Kind != jailFile || !filepath.IsAbs(each.Source) || filepath.Clean(each.Source) != each.Source) {
			return fmt.Errorf("%s: %q is not a file of the host a jail can hold", each.Path, each.Source)
		}
		switch each.Kind {
		case jailFile, jailDir, jailDevice:
		case jailSymlink:
			if each.Target == "" {
				return fmt.Errorf("the link %s points nowhere", each.Path)
			}
		default:
			return fmt.Errorf("%s: no such kind of path: %q", each.Path, each.Kind)
		}
		if each.Slave && each.Kind != jailDir {
			// Only a directory has anything mounted below it, and a file
			// bound as a slave would be a way to hand the jail a file the
			// daemon never looked at.
			return fmt.Errorf("%s: only a directory can be a slave of the host's mount", each.Path)
		}
	}
	return nil
}

// jailArgs is the helper's command line: its name, what to build, and
// the program to become. The hypervisor's own arguments stay in it as
// they are, so a process is recognised as a VM of this daemon by them
// before the helper has become the hypervisor as well as after.
func jailArgs(spec jailSpec, bin string, args []string) ([]string, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	return append([]string{jailArg0, string(encoded), bin}, args...), nil
}

// The devices every hypervisor needs besides its disk: KVM, and the
// host's random numbers, which the guest's entropy device reads.
const (
	kvmDevice = "/dev/kvm"
	rngDevice = "/dev/urandom"
)

// jailFor is the jail of one VM: the hypervisor's binary (and what it is
// linked against, if anything), the kernel image (at JailKernel), the VM's own disk
// node, /dev/kvm and /dev/urandom, and the directory its two sockets are
// made in. A tap is a descriptor and needs no path: the daemon hands it
// over the VM's API socket once the VM runs (AddNet).
func jailFor(root string, uid uint32, groups []uint32, bin, kernel, disk, dir string, libraries []jailPath) jailSpec {
	paths := []jailPath{
		{Path: bin, Kind: jailFile, Exec: true},
		{Path: JailKernel, Source: kernel, Kind: jailFile},
		{Path: disk, Kind: jailDevice},
		{Path: kvmDevice, Kind: jailDevice},
		{Path: rngDevice, Kind: jailDevice},
		{Path: dir, Kind: jailDir, Write: true},
	}
	return jailSpec{Root: root, UID: uid, GID: uid, Groups: groups, Paths: append(paths, libraries...), Descriptors: standardDescriptors}
}

// libraryDirs are where a dynamically linked program's loader and
// libraries are looked for.
var libraryDirs = []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"}

// hypervisorLibraries is what a hypervisor binary needs in its jail
// besides itself. A statically linked one (the upstream release builds
// are) needs nothing. One that names a loader gets the host's library
// directories, read-only: more of the host than a jail should hold, which
// is why New says so in the log.
func hypervisorLibraries(bin string) ([]jailPath, error) {
	file, err := elf.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("%s is not a program this driver can jail: %w", bin, err)
	}
	defer file.Close()
	dynamic := false
	for _, program := range file.Progs {
		dynamic = dynamic || program.Type == elf.PT_INTERP
	}
	if !dynamic {
		return nil, nil
	}
	var paths []jailPath
	seen := map[string]bool{}
	for _, dir := range libraryDirs {
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(dir)
			if err != nil {
				return nil, err
			}
			paths = append(paths, jailPath{Path: dir, Kind: jailSymlink, Target: target})
		}
		if !seen[real] {
			seen[real] = true
			paths = append(paths, jailPath{Path: real, Kind: jailDir, Exec: true})
		}
	}
	if _, err := os.Stat("/etc/ld.so.cache"); err == nil {
		paths = append(paths, jailPath{Path: "/etc/ld.so.cache", Kind: jailFile})
	}
	return paths, nil
}
