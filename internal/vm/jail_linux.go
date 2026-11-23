package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
)

// The helper runs before anything else in every program this package is
// linked into: the daemon, and the test binaries that start real VMs.
func init() {
	if len(os.Args) > 0 && os.Args[0] == jailArg0 {
		// Everything from here to the exec happens on one thread: the
		// last steps (the bounding set, no_new_privs) are per thread.
		runtime.LockOSThread()
		err := enterJail(os.Args[1:], os.Environ())
		fmt.Fprintf(os.Stderr, "%s: %v\n", jailArg0, err)
		os.Exit(125)
	}
}

// selfExe is the daemon's own binary, as the kernel has it: the running
// program even after the file it was started from was replaced.
const selfExe = "/proc/self/exe"

// jailCloneFlags are the namespaces a hypervisor is created in. Network
// and IPC are empty and stay so; the mount namespace is the jail; in the
// PID namespace the hypervisor is process 1 and alone; the UTS and cgroup
// namespaces only keep the host's name and the cgroup's path from it.
// No user namespace: it would make the process root somewhere.
const jailCloneFlags = syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
	syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | syscall.CLONE_NEWCGROUP

// jailCommand is the process that becomes a VM's hypervisor: the daemon's
// own binary as the jail helper, created directly in the VM's cgroup and
// in namespaces of its own. It is root until it has built its jail, and
// until then it runs nothing but this package's enterJail.
func jailCommand(spec jailSpec, cgroup *os.File, bin string, args []string) (*exec.Cmd, error) {
	if cgroup == nil {
		return nil, errors.New("refusing to start a hypervisor outside a cgroup")
	}
	argv, err := jailArgs(spec, bin, args)
	if err != nil {
		return nil, err
	}
	// Not exec.Command: it would look the name up.
	cmd := &exec.Cmd{Path: selfExe, Args: argv}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Its own session: a signal aimed at the daemon's process group
		// (a terminal's ^C) must not take every run with it.
		Setsid:      true,
		Cloneflags:  jailCloneFlags,
		UseCgroupFD: true,
		CgroupFD:    int(cgroup.Fd()),
	}
	return cmd, nil
}

const (
	// close_range has one number on every architecture; with
	// closeRangeCloexec it marks the descriptors instead of closing them
	// (Linux 5.11, older than the Landlock this driver requires).
	sysCloseRange     = 436
	closeRangeCloexec = 4

	prSetNoNewPrivs = 38
	prCapBSetDrop   = 24
	// prSetMemoryMerge is PR_SET_MEMORY_MERGE (Linux 6.4): with 1 every
	// mapping of the process is mergeable by KSM, with 0 none is that
	// was not advised one by one.
	prSetMemoryMerge = 67
	// lastCapability is beyond the highest capability any kernel has.
	lastCapability = 63

	jailHostname = "vm"
	// The jail's root holds mount points and nothing else.
	jailRootOptions = "mode=0755,size=64k,nr_inodes=256"
)

// enterJail builds the jail of args[0], enters it for good, gives up
// root and becomes args[1:]. It only returns when it failed.
func enterJail(args, env []string) error {
	if len(args) < 2 {
		return errors.New("usage: SPEC PROGRAM [ARGUMENT...]")
	}
	var spec jailSpec
	if err := json.Unmarshal([]byte(args[0]), &spec); err != nil {
		return fmt.Errorf("read the jail's description: %w", err)
	}
	if err := spec.validate(); err != nil {
		return err
	}
	// The mounts below are only harmless in a mount namespace of the
	// helper's own. It was created in one together with its PID
	// namespace, and being process 1 is how that shows.
	if os.Getpid() != 1 {
		return errors.New("not started in namespaces of its own")
	}
	if os.Geteuid() != 0 {
		return errors.New("not started as root: it cannot build a jail")
	}
	step := func(what string, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	}
	// Nothing mounted from here on reaches the host's namespace.
	if err := step("make the mount tree private", syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")); err != nil {
		return err
	}
	if err := step("mount the jail's root on "+spec.Root,
		syscall.Mount("tmpfs", spec.Root, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, jailRootOptions)); err != nil {
		return err
	}
	for _, each := range spec.Paths {
		if err := step("put "+each.Path+" in the jail", jailAdd(spec.Root, each)); err != nil {
			return err
		}
	}
	// pivot_root, not chroot: the old root is taken out of the namespace
	// altogether, so there is no path, descriptor or working directory
	// that still leads to the host's tree.
	if err := step("enter the jail's root", syscall.Chdir(spec.Root)); err != nil {
		return err
	}
	if err := step("pivot_root", syscall.PivotRoot(".", ".")); err != nil {
		return err
	}
	if err := step("detach the host's root", syscall.Unmount(".", syscall.MNT_DETACH)); err != nil {
		return err
	}
	if err := step("enter the jail's root", syscall.Chdir("/")); err != nil {
		return err
	}
	if err := step("make the jail's root read-only",
		syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "")); err != nil {
		return err
	}
	if err := step("set the host name", syscall.Sethostname([]byte(jailHostname))); err != nil {
		return err
	}
	// No core dump: a hypervisor's memory is its guest's memory. The
	// limit is 1 and not 0 because 0 does not stop the kernel handing
	// the dump to a core_pattern that is a pipe (a crash reporter); 1 is
	// below the size of any dump, and is the value the kernel itself
	// reads as "do not dump to a pipe". The hard limit keeps the process
	// from raising it again.
	if err := step("turn core dumps off", syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 1, Max: 1})); err != nil {
		return err
	}
	// Not mergeable by KSM. PR_SET_MEMORY_MERGE is a flag of the
	// process's memory that is kept across fork and execve, so a daemon
	// started with it (a systemd unit with MemoryKSM=yes, or anything
	// its parent set) would hand it to every hypervisor, and the guest's
	// RAM would be merged with the rest of the host's mergeable memory:
	// a timing side channel between tenants, and between a tenant and
	// the host. Cleared here, before the execve, it is not passed on.
	// EINVAL is a kernel older than 6.4 or one without KSM, where there
	// is no such flag to clear. The hypervisor is started with
	// mergeable=off, and the filter below refuses both ways of turning
	// merging back on.
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetMemoryMerge, 0, 0, 0, 0, 0); errno != 0 && errno != syscall.EINVAL {
		return fmt.Errorf("make the hypervisor's memory unmergeable (PR_SET_MEMORY_MERGE): %w", errno)
	}
	// Nothing to regain: the bounding set is emptied while still root.
	for capability := uintptr(0); capability <= lastCapability; capability++ {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prCapBSetDrop, capability, 0); errno != 0 && errno != syscall.EINVAL {
			return fmt.Errorf("drop capability %d from the bounding set: %w", capability, errno)
		}
	}
	groups := make([]int, len(spec.Groups))
	for i, group := range spec.Groups {
		groups[i] = int(group)
	}
	if err := step("set the groups", syscall.Setgroups(groups)); err != nil {
		return err
	}
	if err := step("set the group", syscall.Setgid(int(spec.GID))); err != nil {
		return err
	}
	// Changing to a non-zero UID drops every capability; none is kept
	// and none is ambient.
	if err := step("set the user", syscall.Setuid(int(spec.UID))); err != nil {
		return err
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getgid() == 0 || os.Getegid() == 0 {
		return errors.New("still root after giving it up")
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); errno != 0 {
		return fmt.Errorf("set no_new_privs: %w", errno)
	}
	// The daemon's own filter (seccomp.go), under whatever the program
	// installs for itself: from here on this thread, and everything that
	// comes of it, can make no namespace, no socket that is not a unix
	// socket and none of the calls the filter names. It needs
	// no_new_privs, and nothing after it needs a call it refuses.
	if err := step("install the seccomp filter", installSeccomp()); err != nil {
		return err
	}
	// Whatever else this process was started with stays behind: the
	// daemon's own files are close-on-exec, but what the daemon itself
	// inherited from whoever started it is not, and a descriptor is not
	// stopped by a root that has no path to its file. Marked rather than
	// closed, so that the runtime's own are there until the exec, and
	// last, so that nothing opened on the way is missed.
	if _, _, errno := syscall.RawSyscall(sysCloseRange, uintptr(spec.Descriptors), uintptr(^uint32(0)), closeRangeCloexec); errno != 0 {
		return fmt.Errorf("close the descriptors from %d on: %w", spec.Descriptors, errno)
	}
	return step("execute "+args[1], syscall.Exec(args[1], args[1:], env))
}

// jailAdd makes one path of the jail under root.
func jailAdd(root string, each jailPath) error {
	target := filepath.Join(root, each.Path)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if each.Kind == jailSymlink {
		return os.Symlink(each.Target, target)
	}
	source := each.Path
	if each.Source != "" {
		source = each.Source
	}
	info, err := os.Stat(source)
	if err != nil {
		// The error names the path in the jail (the caller's message),
		// not the host's: what the helper prints reaches the VM's
		// diagnostics, and where the host keeps the file is not theirs.
		var pathErr *fs.PathError
		if each.Source != "" && errors.As(err, &pathErr) {
			return fmt.Errorf("the file bound at %s: %w", each.Path, pathErr.Err)
		}
		return err
	}
	switch isDevice := info.Mode()&os.ModeDevice != 0; {
	case each.Kind == jailDir && !info.IsDir():
		return errors.New("not a directory")
	case each.Kind == jailFile && !info.Mode().IsRegular():
		return errors.New("not a regular file")
	case each.Kind == jailDevice && !isDevice:
		return errors.New("not a device")
	}
	if each.Kind == jailDir {
		err = os.MkdirAll(target, 0o755)
	} else {
		var file *os.File
		if file, err = os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o444); err == nil {
			err = file.Close()
		}
	}
	if err != nil {
		return err
	}
	// Not recursive: what is mounted below a directory on the host does
	// not come along.
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	// A bind mount takes its flags from where it came from; they are set
	// in a second step.
	flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_NOSUID)
	if each.Kind != jailDevice {
		flags |= syscall.MS_NODEV
	}
	if !each.Exec {
		flags |= syscall.MS_NOEXEC
	}
	if !each.Write {
		// Read-only is about the filesystem: a device behind a read-only
		// mount is still written to through its node.
		flags |= syscall.MS_RDONLY
	}
	if err := syscall.Mount("", target, "", flags, ""); err != nil {
		return fmt.Errorf("set mount flags: %w", err)
	}
	return nil
}
