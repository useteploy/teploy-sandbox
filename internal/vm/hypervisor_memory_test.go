package vm

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The hypervisor's memory image calls (Machine.Snapshot, Machine.Restore,
// Machine.MapsFile), and a hypervisor started for a restore.

// apiListener is a unix socket where a test plays the hypervisor's API:
// every request is read whole, with the descriptors it arrived with, and
// answered with the status a test sets.
type apiListener struct {
	listener *net.UnixListener
	status   atomic.Value
	received chan apiRequest
}

type apiRequest struct {
	method, path, body string
	files              []*os.File
}

func listenAPI(t *testing.T, dir string) *apiListener {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, apiSocketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	api := &apiListener{listener: listener, received: make(chan apiRequest, 4)}
	api.status.Store("204 No Content")
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			buf, oob := make([]byte, 8192), make([]byte, 1024)
			n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
			if err != nil {
				// A connection that said nothing: closed, as the daemon
				// closes one whose listener it does not trust.
				conn.Close()
				continue
			}
			request := apiRequest{}
			head, body, _ := strings.Cut(string(buf[:n]), "\r\n\r\n")
			fmt.Sscanf(head, "%s %s", &request.method, &request.path)
			request.body = body
			if messages, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for _, message := range messages {
					fds, _ := syscall.ParseUnixRights(&message)
					for _, fd := range fds {
						request.files = append(request.files, os.NewFile(uintptr(fd), "received"))
					}
				}
			}
			api.received <- request
			_, _ = io.WriteString(conn, "HTTP/1.1 "+api.status.Load().(string)+"\r\nContent-Length: 0\r\n\r\n")
			conn.Close()
		}
	}()
	return api
}

func apiMachine(dir string, owner *uint32) *chMachine {
	cell := &cell{uid: 70123, owner: &confinement{sys: confineSys{socketOwner: func(net.Conn) (uint32, error) { return *owner, nil }}}}
	return &chMachine{dir: dir, cell: cell}
}

// replace writes a sealed image's file anew: it is read-only, so it is
// removed first.
func replace(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o444); err != nil {
		t.Fatal(err)
	}
}

func sameFile(file *os.File, info os.FileInfo) bool {
	got, err := file.Stat()
	return err == nil && os.SameFile(got, info)
}

// vm.restore gets the image's directory, the copy-on-write mode in the
// API's own spelling and no prefaulting (which the hypervisor refuses
// outside its copy mode), and the run's tap as a descriptor the body
// counts.
func TestRestoreSpeaksTheHypervisorsRestoreCall(t *testing.T) {
	dir := shortDir(t)
	api := listenAPI(t, dir)
	owner := uint32(70123)
	machine := apiMachine(dir, &owner)

	if err := machine.Restore(context.Background(), RestoreRequest{SourceURL: "file:///run/vm.inbox"}); err != nil {
		t.Fatalf("restore without a network device: %v", err)
	}
	got := <-api.received
	if got.method != "PUT" || got.path != "/api/v1/vm.restore" || got.body != `{"memory_restore_mode":"CopyOnWrite","prefault":false,"source_url":"file:///run/vm.inbox"}` || len(got.files) != 0 {
		t.Fatalf("the request: %+v", got)
	}

	tap, err := os.CreateTemp(dir, "tap")
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Close()
	tapInfo, _ := tap.Stat()
	if err := machine.Restore(context.Background(), RestoreRequest{SourceURL: "file:///run/vm.inbox", NetDevice: netDeviceID, NetFD: tap}); err != nil {
		t.Fatalf("restore with the tap: %v", err)
	}
	got = <-api.received
	// net_fds as the hypervisor reads it: each device by id, with how
	// many descriptors follow it (one tap).
	want := `{"memory_restore_mode":"CopyOnWrite","net_fds":[{"id":"net0","num_fds":1}],"prefault":false,"source_url":"file:///run/vm.inbox"}`
	if got.body != want || len(got.files) != 1 || !sameFile(got.files[0], tapInfo) {
		t.Fatalf("the request: %+v, want body %s with the tap", got, want)
	}
	for _, file := range got.files {
		file.Close()
	}
	// The daemon's own descriptor is still its own to close.
	if _, err := tap.Stat(); err != nil {
		t.Fatalf("Restore closed the caller's tap: %v", err)
	}

	// A refusal is an error with the hypervisor's words, and something
	// else listening there is told nothing, the tap least of all.
	api.status.Store("400 Bad Request")
	if err := machine.Restore(context.Background(), RestoreRequest{SourceURL: "file:///run/vm.inbox", NetDevice: netDeviceID, NetFD: tap}); err == nil || !strings.Contains(err.Error(), "vm.restore: 400") {
		t.Fatalf("a refused restore: %v", err)
	}
	for _, file := range (<-api.received).files {
		file.Close()
	}
	owner = 0
	if err := machine.Restore(context.Background(), RestoreRequest{SourceURL: "file:///run/vm.inbox", NetDevice: netDeviceID, NetFD: tap}); err == nil || !strings.Contains(err.Error(), "not this VM's uid") {
		t.Fatalf("a restore asked of a socket another UID listens on: %v", err)
	}
	select {
	case got := <-api.received:
		t.Fatalf("a socket of another UID was sent %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
}

// vm.snapshot gets the directory to write and nothing else, and needs
// the caller's deadline: the hypervisor writes for as long as the guest
// is big.
func TestSnapshotSpeaksTheHypervisorsSnapshotCall(t *testing.T) {
	dir := shortDir(t)
	api := listenAPI(t, dir)
	owner := uint32(70123)
	machine := apiMachine(dir, &owner)
	if err := machine.Snapshot(context.Background(), "file:///run/vm/outbox/1"); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("a snapshot without a deadline: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := machine.Snapshot(ctx, "file:///run/vm/outbox/1"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	got := <-api.received
	if got.method != "PUT" || got.path != "/api/v1/vm.snapshot" || got.body != `{"destination_url":"file:///run/vm/outbox/1"}` || len(got.files) != 0 {
		t.Fatalf("the request: %+v", got)
	}
	api.status.Store("500 Internal Server Error")
	if err := machine.Snapshot(ctx, "file:///run/vm/outbox/2"); err == nil || !strings.Contains(err.Error(), "vm.snapshot: 500") {
		t.Fatalf("a refused snapshot: %v", err)
	}
	<-api.received
}

// What tells a copy-on-write restore from one the hypervisor silently
// turned into a copy: the first maps the memory file over its whole
// length, privately (the hypervisor's MAP_PRIVATE: guest writes stay out
// of the file); the second read the file and maps nothing of it.
func TestMapsFileSeesOnlyAWholeMappingOfTheMemoryFile(t *testing.T) {
	const size = 512 << 20
	mapping := func(from, to uint64, perms, dev, ino, path string) string {
		return fmt.Sprintf("%012x-%012x %s 00000000 %s %s %s\n", from, to, perms, dev, ino, path)
	}
	whole := mapping(0, size, "rw-p", "fd:01", "42", "/run/vm.inbox/memory-ranges")
	for name, c := range map[string]struct {
		maps string
		want bool
	}{
		"the whole file, private":    {whole, true},
		"the whole file, read-only":  {mapping(0, size, "r--p", "fd:01", "42", "/x/memory-ranges"), false},
		"the whole file, shared":     {mapping(0, size, "rw-s", "fd:01", "42", "/x/memory-ranges"), false},
		"the whole file, write-only": {mapping(0, size, "-w-p", "fd:01", "42", "/x/memory-ranges"), false},
		"the whole file, executable": {mapping(0, size, "rwxp", "fd:01", "42", "/x/memory-ranges"), false},
		"half shared and half private": {mapping(0, size/2, "rw-s", "fd:01", "42", "/x/memory-ranges") +
			mapping(size/2, size, "rw-p", "fd:01", "42", "/x/memory-ranges"), false},
		"the whole file at another address":    {mapping(0x7f0000000000, 0x7f0000000000+size, "rw-p", "fd:01", "42", "/x/memory-ranges"), true},
		"the first page only":                  {mapping(0, 4096, "rw-p", "fd:01", "42", "/x/memory-ranges"), false},
		"all but one page":                     {mapping(4096, size, "rw-p", "fd:01", "42", "/x/memory-ranges"), false},
		"another inode":                        {mapping(0, size, "rw-p", "fd:01", "43", "/x/memory-ranges"), false},
		"another device":                       {mapping(0, size, "rw-p", "fd:02", "42", "/x/memory-ranges"), false},
		"under any path at all (the jail's)":   {mapping(0, size, "rw-p", "fd:01", "42", "/run/sbx/abc/x.inbox/memory-ranges"), true},
		"anonymous memory, as a copy leaves":   {"7f0000000000-7f2000000000 rw-p 00000000 00:00 0 \n", false},
		"the image's state.json":               {mapping(0, size, "rw-p", "fd:01", "41", "/x/state.json"), false},
		"a line that is not a mapping":         {"SwapPss: 0 kB " + whole, false},
		"a line with no addresses":             {" rw-p 00000000 fd:01 42 /x/memory-ranges\n", false},
		"a mapping with no device":             {fmt.Sprintf("000000000000-%012x rw-p 00000000 42 /x/memory-ranges\n", uint64(size)), false},
		"a mapping that ends before it begins": {fmt.Sprintf("%012x-000000000000 rw-p 00000000 fd:01 42 /x/memory-ranges\n", uint64(size)), false},
		"a mapping with no inode":              {fmt.Sprintf("000000000000-%012x rw-p 00000000 fd:01 /x/memory-ranges\n", uint64(size)), false},
		"a kernel-style path":                  {fmt.Sprintf("000000000000-%012x rw-p 00000000 fd:01 42   /run/vm.inbox/memory-ranges (deleted)\n", uint64(size)), true},
	} {
		if got := mapsFile([]byte(c.maps), "fd:01", "42", size); got != c.want {
			t.Errorf("%s: %t", name, got)
		}
	}
	// A mapping the kernel has split still covers the whole file, and one
	// mapped twice is still the whole file.
	split := mapping(0, 0x10000, "rw-p", "fd:01", "42", "/x/memory-ranges") + mapping(0x10000, size, "rw-p", "fd:01", "42", "/x/memory-ranges")
	if !mapsFile([]byte(split), "fd:01", "42", size) || !mapsFile([]byte(whole+whole), "fd:01", "42", size) {
		t.Error("a whole file in two mappings, or mapped twice, was not seen")
	}
	if mapsFile([]byte(whole), "fd:01", "42", size+1) {
		t.Error("a mapping shorter than the file was taken for the whole file")
	}
	if runtime.GOOS != "linux" {
		// Elsewhere there is no /proc to read a process's mappings from.
		return
	}
	// Against this process's own mappings of a real file.
	path := filepath.Join(t.TempDir(), imageMemoryFile)
	if err := os.WriteFile(path, make([]byte, 3*4096), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	machine := &chMachine{process: &os.Process{Pid: os.Getpid()}}
	if machine.MapsFile(path) {
		t.Fatal("a file nothing maps")
	}
	one, err := syscall.Mmap(int(file.Fd()), 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(one)
	if machine.MapsFile(path) {
		t.Fatal("one page of three mapped was taken for the whole file")
	}
	rest, err := syscall.Mmap(int(file.Fd()), 4096, 2*4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(rest)
	if !machine.MapsFile(path) {
		t.Fatal("the file mapped privately over its whole length was not seen")
	}
	// A shared mapping of the whole file is not a copy-on-write restore,
	// whatever it covers: what the VM wrote would reach the image.
	other := filepath.Join(t.TempDir(), imageMemoryFile)
	if err := os.WriteFile(other, make([]byte, 3*4096), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(other, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	shared, err := syscall.Mmap(int(writer.Fd()), 0, 3*4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Munmap(shared)
	if machine.MapsFile(other) {
		t.Fatal("a file mapped shared over its whole length was taken for a copy-on-write restore")
	}
}

// TestHypervisorStandIn is the stand-in for the hypervisor when another
// test runs the test binary as one (hypervisorFor): given the daemon's
// arguments after "--", it maps a file of its own privately, opens the
// API socket, prints what it is asked and answers, and runs until it is
// killed. Run as a test of its own it has no such arguments and is over
// at once.
func TestHypervisorStandIn(t *testing.T) {
	args := standInArgs()
	if args == nil {
		return
	}
	fmt.Printf("args %q\n", args)
	if executable, err := os.Executable(); err == nil {
		if mapped, err := mapWhole(executable); err == nil {
			fmt.Printf("mapped %s %d\n", executable, len(mapped))
		}
	}
	serveAPI(args)
}

// TestHypervisorStandInExits is the stand-in for a hypervisor that dies
// before its API answers.
func TestHypervisorStandInExits(t *testing.T) {
	if standInArgs() == nil {
		return
	}
	os.Exit(0)
}

func standInArgs() []string {
	at := slices.Index(os.Args, "--")
	if at < 0 || at+1 >= len(os.Args) {
		return nil
	}
	return os.Args[at+1:]
}

// mapWhole maps a file privately, as the hypervisor maps a restored
// guest's memory.
func mapWhole(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	return syscall.Mmap(int(file.Fd()), 0, int(info.Size()), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE)
}

// serveAPI answers the hypervisor's REST API on the socket its arguments
// name, printing each request.
func serveAPI(args []string) {
	at := slices.Index(args, "--api-socket")
	if at < 0 || at+1 >= len(args) {
		fmt.Println("no api socket in the arguments")
		os.Exit(2)
	}
	listener, err := net.Listen("unix", args[at+1])
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		os.Exit(3)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Printf("request %s %s %s\n", r.Method, r.URL.Path, body)
		w.WriteHeader(http.StatusNoContent)
	})}
	_ = server.Serve(listener)
	os.Exit(0)
}

// hypervisorFor has the confinement start the test binary as the
// hypervisor, running the test function *standIn plays it.
func hypervisorFor(confine *confinement, standIn *string) {
	inner := confine.sys.command
	confine.sys.command = func(jail jailSpec, cgroup *os.File, bin string, args []string) (*exec.Cmd, error) {
		cmd, err := inner(jail, cgroup, bin, args)
		if err != nil {
			return nil, err
		}
		// The test binary by its absolute path: the hypervisor runs from
		// "/", where a relative one names nothing.
		executable, err := os.Executable()
		if err != nil {
			return nil, err
		}
		replacement := exec.Command(executable, append([]string{"-test.run=^" + *standIn + "$", "--"}, args...)...)
		replacement.SysProcAttr = cmd.SysProcAttr
		return replacement, nil
	}
}

// A hypervisor started for a restore is confined like one started for a
// boot, and differs only in what it is given: no payload and no
// --landlock on its command line (the hypervisor refuses that without a
// payload), the VM's configuration the daemon's own and rewritten, and
// the image as three read-only files.
func TestAHypervisorStartedForARestoreIsConfinedAndGivenTheDaemonsConfiguration(t *testing.T) {
	root := shortDir(t)
	confine, log, _ := newTestConfinement(t, root)
	confine.outboxes = true
	// The stand-in listens as the VM's own user.
	confine.sys.socketOwner = func(net.Conn) (uint32, error) { return 70000, nil }
	standIn := "TestHypervisorStandIn"
	hypervisorFor(confine, &standIn)
	h := &CloudHypervisor{Bin: "/opt/ch", Kernel: "/boot/Image", Cmdline: savedCmdline, RunDir: filepath.Join(root, "run"), confine: confine}
	name := runName(3)
	image := filepath.Join(root, "image")
	if err := os.MkdirAll(image, 0o755); err != nil {
		t.Fatal(err)
	}
	// The image: as a VM of another runtime directory of this daemon's
	// was saved.
	saved := savedDocument()
	savedDisk := savedDevDir + "/" + runName(1)
	savedDir := filepath.Join(h.RunDir, runName(1))
	set("disks.0.path", savedDisk)(saved)
	set("vsock.socket", savedDir+"/"+vsockSocketName)(saved)
	set("landlock_rules", []any{map[string]any{"path": savedDir + "/" + outboxName, "access": "rw"}})(saved)
	for file, content := range map[string][]byte{imageConfigFile: encoded(t, saved), imageStateFile: []byte(`{}`), imageMemoryFile: make([]byte, 4096)} {
		replace(t, filepath.Join(image, file), content)
	}
	config := RestoreConfig{
		MachineConfig: MachineConfig{Name: name, Disk: "/dev/zvol/tank/" + name, CPUs: 1, MemoryMB: 512},
		ImageDir:      image, SavedDisk: savedDisk, Networked: true, SavedMAC: savedMAC,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Without memory images there is no restore: no hypervisor is started.
	plain := &CloudHypervisor{Bin: h.Bin, Kernel: h.Kernel, Cmdline: h.Cmdline, RunDir: h.RunDir, confine: confine}
	confine.outboxes = false
	if machine, err := plain.Restore(ctx, config); err == nil || machine != nil || !strings.Contains(err.Error(), "keeps no memory images") {
		t.Fatalf("a restore without memory images: %v", err)
	}
	confine.outboxes = true
	if len(log.started) != 0 || len(confine.uids.held) != 0 {
		t.Fatalf("started %v, uids held %v", log.started, confine.uids.held)
	}

	machine, err := h.Restore(ctx, config)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	dir := filepath.Join(h.RunDir, name)
	inbox := dir + inboxSuffix
	if machine.Inbox() != inbox || machine.Disk() != filepath.Join(confine.devDir, name) || machine.Outbox() != filepath.Join(dir, outboxName) || machine.UID() != 70000 {
		t.Fatalf("inbox %q, disk %q, outbox %q, uid %d", machine.Inbox(), machine.Disk(), machine.Outbox(), machine.UID())
	}
	// The process: the API socket and its seccomp filter, and nothing of
	// a VM (the configuration holds it all) and no --landlock, which the
	// hypervisor refuses without a payload.
	var diagnostics string
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(diagnostics, "request GET /api/v1/vmm.ping") {
		if time.Now().After(deadline) {
			t.Fatalf("the hypervisor's API was never asked anything: %q", machine.Diagnostics())
		}
		time.Sleep(10 * time.Millisecond)
		diagnostics = machine.Diagnostics()
	}
	want := fmt.Sprintf("args %q\n", []string{"--api-socket", filepath.Join(dir, apiSocketName), "--seccomp", "true"})
	if at := strings.Index(diagnostics, "args "); at < 0 || !strings.HasPrefix(diagnostics[at:], want) {
		t.Fatalf("the hypervisor was started with:\n%s\nwant %s", diagnostics, want)
	}
	if want := "uid=70000 gid=70000 groups=[993] cgroup=" + confine.cgroups.path(name); !slices.Equal(log.started, []string{want}) {
		t.Fatalf("the hypervisor was started as %v, want %s", log.started, want)
	}
	// The jail: a boot's paths, the outbox, and the image as three
	// read-only files, the daemon's configuration among them.
	jail := log.jails[len(log.jails)-1]
	files := []jailPath{
		{Path: filepath.Join(inbox, imageConfigFile), Kind: jailFile},
		{Path: filepath.Join(inbox, imageStateFile), Source: filepath.Join(image, imageStateFile), Kind: jailFile},
		{Path: filepath.Join(inbox, imageMemoryFile), Source: filepath.Join(image, imageMemoryFile), Kind: jailFile},
	}
	if len(jail.Paths) != 10 || jail.Paths[6] != (jailPath{Path: filepath.Join(dir, outboxName), Kind: jailDir, Write: true, Slave: true}) || !reflect.DeepEqual(jail.Paths[7:], files) || jail.Descriptors != standardDescriptors {
		t.Fatalf("the jail: %+v", jail)
	}
	for _, each := range jail.Paths[7:] {
		if each.Write || each.Exec {
			t.Errorf("a file of the image is writable or executable in the jail: %+v", each)
		}
		// Each is a file: the daemon's where it wrote it, the image's
		// where the dataset is mounted.
		source := each.Path
		if each.Source != "" {
			source = each.Source
		}
		if info, err := os.Lstat(source); err != nil || !info.Mode().IsRegular() {
			t.Errorf("the image's %s: %v %v", source, info, err)
		}
	}
	// The configuration the VM is restored from is the daemon's: the
	// saved one with the new VM's paths, Landlock on, and the network
	// device's descriptors replaced by what the restore hands over. It
	// is root's and read-only, and the sealed image is as it was.
	wanted := savedWant()
	wanted.savedDisk, wanted.runtimeRoot = savedDisk, h.RunDir
	wanted.disk, wanted.vsockSocket, wanted.outbox = machine.Disk(), filepath.Join(dir, vsockSocketName), machine.Outbox()
	rewritten, err := rewriteMemoryConfig(encoded(t, saved), wanted)
	if err != nil {
		t.Fatalf("the saved configuration: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(inbox, imageConfigFile))
	if err != nil || string(got) != string(rewritten) {
		t.Fatalf("the inbox's configuration:\n%s\nwant\n%s (%v)", got, rewritten, err)
	}
	if info, err := os.Stat(filepath.Join(inbox, imageConfigFile)); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("the inbox's configuration: %v %v", info, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(image, imageConfigFile)); string(raw) != string(encoded(t, saved)) {
		t.Fatalf("the sealed image's configuration was changed:\n%s", raw)
	}

	// What the process mapped is what MapsFile reports: a file of its own
	// over its whole length, and nothing else.
	if runtime.GOOS == "linux" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(diagnostics, "mapped "+executable+" ") || !machine.MapsFile(executable) {
			t.Errorf("the stand-in's mapping of its own binary was not seen:\n%s", diagnostics)
		}
	}
	other := filepath.Join(root, "other-file")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if machine.MapsFile(other) || machine.MapsFile(image) {
		t.Error("a file nothing maps, or a directory, was seen")
	}

	if err := machine.Restore(ctx, RestoreRequest{SourceURL: "file://" + inbox, NetDevice: netDeviceID}); err != nil {
		t.Fatalf("vm.restore: %v", err)
	}
	// The stand-in's account of it comes through its output, a moment later.
	want = `request PUT /api/v1/vm.restore {"memory_restore_mode":"CopyOnWrite","prefault":false,"source_url":"file://` + inbox + `"`
	deadline = time.Now().Add(5 * time.Second)
	for !strings.Contains(machine.Diagnostics(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("the restore request:\n%s", machine.Diagnostics())
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Gone: the inbox goes with the VM, and nothing of it is held.
	if err := machine.Kill(ctx); err != nil {
		t.Fatalf("kill: %v", err)
	}
	for _, gone := range []string{dir, inbox, filepath.Join(confine.devDir, name)} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", gone, err)
		}
	}
	if len(confine.uids.held) != 0 {
		t.Fatalf("the VM's UID was not returned: %v", confine.uids.held)
	}

	// An image whose configuration is not this daemon's refuses the
	// restore before any process starts, and nothing is left behind.
	hostile := savedDocument()
	set("memory.mergeable", true)(hostile)
	replace(t, filepath.Join(image, imageConfigFile), encoded(t, hostile))
	refused := config
	refused.Name, refused.Disk = runName(4), "/dev/zvol/tank/"+runName(4)
	if machine, err := h.Restore(ctx, refused); err == nil || machine != nil || !strings.Contains(err.Error(), "mergeable") {
		t.Fatalf("an image with mergeable memory was restored: %v", err)
	}
	replace(t, filepath.Join(image, imageConfigFile), encoded(t, saved))
	if len(log.started) != 1 || len(confine.uids.held) != 0 {
		t.Fatalf("started %v, uids held %v", log.started, confine.uids.held)
	}
	if groups, _ := confine.cgroups.fs.children(confine.cgroups.dir); len(groups) != 0 {
		t.Fatalf("a refused restore left a cgroup: %v", groups)
	}
	if _, err := os.Stat(filepath.Join(h.RunDir, refused.Name)); !os.IsNotExist(err) {
		t.Fatalf("a refused restore left its runtime dir: %v", err)
	}

	// A hypervisor that dies before its API answers is given back too.
	standIn = "TestHypervisorStandInExits"
	dead := config
	dead.Name, dead.Disk = runName(5), "/dev/zvol/tank/"+runName(5)
	if machine, err := h.Restore(ctx, dead); err == nil || machine != nil || !strings.Contains(err.Error(), "exited before its API answered") {
		t.Fatalf("a hypervisor that died: %v", err)
	}
	if len(confine.uids.held) != 0 || len(log.started) != 2 {
		t.Fatalf("the dead hypervisor is still held: uids %v, started %v", confine.uids.held, log.started)
	}
}
