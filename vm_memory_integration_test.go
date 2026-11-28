//go:build vmintegration

// Live tests of memory stop and resume (--vm-memory-snapshots): a stop
// saves the VM's memory beside its disk snapshot and a resume restores
// the VM from it, under the daemon's whole confinement; every image that
// cannot be used boots the disk; the guest's random state is shown to be
// new at a restore, two ways that can fail; and what it costs is
// measured. They run with the rest of the live suite (see
// vm_integration_test.go).
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// memoryTestConfig is the suite's host config with memory images on, in
// places of the suite's own: the images under a dataset of the suite's
// in the pool (destroyed at the end, so the pool is left as it was
// found), mounted under the runtime directory, with a host secret there
// too.
func memoryTestConfig(t *testing.T) vm.Config {
	t.Helper()
	config := vmTestConfig(t)
	config.MemorySnapshots = true
	config.ImageDataset = config.Pool + "/teploy-img-vmtest"
	config.ImageMountDir = "/run/teploy-vmtest-images"
	config.HostSecret = "/run/teploy-vmtest-host.secret"
	config.PoolReserve = 0
	t.Cleanup(func() {
		// The suite's dataset alone, whatever a failed attempt left in it.
		_ = exec.Command("zfs", "destroy", "-r", config.ImageDataset).Run()
		_ = os.RemoveAll(config.ImageMountDir)
		_ = os.Remove(config.HostSecret)
		_ = os.Remove(config.HostSecret + ".other")
	})
	return config
}

// memoryLog is the daemon's log, which a test reads while the daemon
// may still be writing it.
type memoryLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *memoryLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *memoryLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// memoryRig is one life of a daemon that keeps memory images, wired as
// serve wires it, and its log.
type memoryRig struct {
	manager *run.Manager
	driver  *vm.Driver
	log     *memoryLog
	config  vm.Config
	state   string
}

// newMemoryDaemon is a daemon life: another on the same state directory
// is a restart.
func newMemoryDaemon(t *testing.T, config vm.Config, stateDir string) *memoryRig {
	t.Helper()
	log := &memoryLog{}
	manager, driver, _, _ := newVMManagerLogging(t, config, stateDir, log)
	return &memoryRig{manager: manager, driver: driver, log: log, config: config, state: stateDir}
}

// says lists the log lines that carry every field.
func (r *memoryRig) says(fields ...string) []string {
	var lines []string
	for _, line := range strings.Split(r.log.String(), "\n") {
		if !slices.ContainsFunc(fields, func(field string) bool { return !strings.Contains(line, field) }) {
			lines = append(lines, line)
		}
	}
	return lines
}

// memoryImage is what a stopped run says of its image, which must be
// saved.
func memoryImage(t *testing.T, r *memoryRig, id string) run.MemoryView {
	t.Helper()
	view, err := r.manager.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if view.Memory == nil {
		t.Fatalf("run %s says nothing of a memory image:\n%s", id, r.log.String())
	}
	return *view.Memory
}

// imageDir is where a stopped run's memory image is mounted on the host.
func imageDir(t *testing.T, r *memoryRig, id string) string {
	t.Helper()
	image := memoryImage(t, r, id)
	if image.State != run.MemorySaved || image.Image == "" {
		t.Fatalf("the stopped run's memory image: %+v\n%s", image, r.log.String())
	}
	return filepath.Join(r.config.ImageMountDir, image.Image)
}

func zfs(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("zfs", args...).Output()
	if err != nil {
		t.Fatalf("zfs %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// zfsProperty is one property of a dataset as zfs reports it.
func zfsProperty(t *testing.T, dataset, name string) string {
	t.Helper()
	return zfs(t, "get", "-H", "-o", "value", name, dataset)
}

func kernelMessages(t *testing.T, since time.Time, pattern string) []string {
	t.Helper()
	out, err := exec.Command("journalctl", "-k", "--no-pager", "-o", "cat", "--since", since.Format("2006-01-02 15:04:05")).Output()
	if err != nil {
		t.Fatalf("journalctl: %v", err)
	}
	var found []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, pattern) {
			found = append(found, line)
		}
	}
	return found
}

const (
	// The ticker is started by a script with a name of its own, so that
	// its process is told from one that merely has its pid after a boot.
	tickerName   = "teploy-ticker-7f3a9c"
	tickerScript = "/work/" + tickerName
	tickerPID    = "/work/ticker.pid"
	tickerFile   = "/work/ticker.log"
	serverPort   = "8099"
	// tickerPattern is tickerScript as a grep pattern that is not the
	// string itself (see tickerAlive).
	tickerPattern = "/work/teploy-ticker-7f3a9[c]"
)

// tickerAlive prints process-alive when the guest runs the ticker it
// was started with: the process one of whose arguments is its script,
// exactly. A boot from the disk reuses low pids, and this very check
// runs in a shell whose command line names the script too, so the pid
// alone says nothing: an argument must be the script's path and no less.
// Nor is the path spelled out where the check's own grep could carry it
// as an argument: a guest booted from the disk still has the stale pid in
// its pid file, and when that pid is the one the check's own grep gets,
// the grep finds itself. (Seen live once: a guest booted from the disk
// answered process-alive.) The pattern is the path with its last letter
// in brackets, which matches the path and is not the path.
const tickerAlive = `p="$(cat ` + tickerPID + ` 2>/dev/null)" && [ -n "$p" ] && tr "\000" "\n" < "/proc/$p/cmdline" 2>/dev/null | grep -qx "` + tickerPattern + `" && echo process-alive
`

// guestStarts starts what a resume is to bring back: a file, a process
// that goes on writing the time, and a listening server, both in
// sessions of their own as a service would be.
func guestStarts(t *testing.T, r *memoryRig, id string) {
	t.Helper()
	got := vmRun(t, r.manager, id, `echo kept > /work/kept; rm -f `+tickerFile+` `+tickerPID+`
printf '#!/bin/sh\necho $$ > `+tickerPID+`\nwhile :; do date +%%s.%%N >> `+tickerFile+`; sleep 0.2; done\n' > `+tickerScript+`; chmod +x `+tickerScript+`
setsid nohup sh `+tickerScript+` >/dev/null 2>&1 &
(cd /work && setsid nohup python3 -m http.server `+serverPort+` --bind 127.0.0.1 >/dev/null 2>&1 &)
for i in $(seq 1 100); do out=$(curl -s -m 2 http://127.0.0.1:`+serverPort+`/kept 2>&1); [ "$out" = kept ] && break; sleep 0.2; done
echo "server=[$out] python3=[$(command -v python3)] curl=[$(command -v curl)] ticker=[$(cat `+tickerPID+`)] ticks=$(wc -l < `+tickerFile+`)]"
`+tickerAlive, "", nil, 60*time.Second)
	t.Logf("before the stop: %+v", got)
	if !strings.Contains(got.stdout, "server=[kept]") || !strings.Contains(got.stdout, "process-alive") || !strings.Contains(got.stdout, "python3=[/usr/bin/python3]") || !strings.Contains(got.stdout, "curl=[/usr/bin/curl]") || got.code != 0 {
		t.Fatalf("before the stop: %+v\n%s", got, r.log.String())
	}
}

// forkReseeds is how many times so far the guest's kernel has reseeded
// its random generator because its VM was forked or restored. Its VM
// Generation ID driver logs each one ("crng reseeded due to virtual
// machine fork"), and nothing else does. The hypervisor changes the ID
// and notifies the guest's device before a restored VM runs again, so
// the driver reseeds at every restore.
//
// The count is compared across a restore, not merely found. Since Linux
// 6.10 the driver logs nothing at boot and one line at every restore;
// the driver before that logged one at boot and none at a restore, so
// for it the count does not move, which is the finding.
func forkReseeds(t *testing.T, r *memoryRig, id string) int {
	t.Helper()
	got := vmRun(t, r.manager, id, `dmesg | grep -c 'crng reseeded due to virtual machine fork'`, "", nil, 30*time.Second)
	if got.stderr != "" {
		t.Fatalf("the guest's kernel log could not be read: %q %q", got.stdout, got.stderr)
	}
	n, err := strconv.Atoi(strings.TrimSpace(got.stdout))
	if err != nil {
		t.Fatalf("the guest's count of reseeds reads %q: %v", got.stdout, err)
	}
	return n
}

// guestCameBack is what a resumed guest must still have. From its disk,
// it is a fresh boot of the saved filesystem: the file is there, and
// nothing that ran before is. From its memory, the file, the process
// (the same one, still writing), the listening server, and the host's
// clock are there too; its random state is its own (the kernel's count
// of reseeds has grown across the restore: reseedsBefore is what it
// read before the stop), and its hypervisor maps the image as a
// copy-on-write restore does.
//
// Two readings of /dev/urandom, one before the stop and one after the
// restore, are not compared: they differ whether or not anything
// reseeded the generator, since the stream had moved on past the first
// reading when the memory was saved (a review of the first cut).
func guestCameBack(t *testing.T, r *memoryRig, id string, reseedsBefore int, restored bool) {
	t.Helper()
	if got := vmRun(t, r.manager, id, `cat /work/kept`, "", nil, 30*time.Second); got.stdout != "kept\n" {
		t.Fatalf("the file: %+v", got)
	}
	if !restored {
		got := vmRun(t, r.manager, id, tickerAlive+`curl -s -m 3 -o /dev/null -w 'server-%{http_code}' http://127.0.0.1:`+serverPort+`/kept || true`, "", nil, 30*time.Second)
		if strings.Contains(got.stdout, "process-alive") || strings.Contains(got.stdout, "server-200") {
			// Who that is, with the pid the snapshot saved.
			who := vmRun(t, r.manager, id, `p="$(cat `+tickerPID+` 2>/dev/null)"; echo "pid $p: $(tr "\000" " " < "/proc/$p/cmdline" 2>/dev/null)"`, "", nil, 30*time.Second)
			t.Fatalf("a guest booted from the disk still runs what ran before the stop: %+v\n%s", got, who.stdout)
		}
		return
	}
	if got := vmRun(t, r.manager, id, tickerAlive, "", nil, 30*time.Second); !strings.Contains(got.stdout, "process-alive") {
		t.Fatalf("the process: %+v", got)
	}
	if got := vmRun(t, r.manager, id, `curl -s -m 5 http://127.0.0.1:`+serverPort+`/kept`, "", nil, 30*time.Second); got.stdout != "kept\n" {
		t.Fatalf("the listening server: %+v", got)
	}
	// The last tick is recent: a guest whose clock was left where it was
	// saved would write the time of the stop, however long ago it was.
	got := vmRun(t, r.manager, id, `sleep 1; tail -n 1 `+tickerFile, "", nil, 30*time.Second)
	last, err := strconv.ParseFloat(strings.TrimSpace(got.stdout), 64)
	if err != nil {
		t.Fatalf("the ticker wrote %q: %v", got.stdout, err)
	}
	if drift := time.Since(time.Unix(0, int64(last*1e9))); drift < -time.Second || drift > 5*time.Second {
		t.Fatalf("the guest's clock is %s from the host's", drift.Round(time.Millisecond))
	}
	// The kernel says so itself, and the count is what shows it happened
	// at this restore and not at some time before the stop: the VM
	// Generation ID driver reseeds the generator on the hypervisor's
	// notification, once per restore.
	after := forkReseeds(t, r, id)
	t.Logf("the guest kernel's reseeds: %d before the stop, %d after the restore", reseedsBefore, after)
	if after <= reseedsBefore {
		t.Fatalf("the guest kernel's count of reseeds is %d after the restore and was %d before the stop: nothing reseeded its random state at the restore", after, reseedsBefore)
	}
	// The hypervisor maps the memory file over its whole length,
	// privately: nothing it writes reaches the image, and nothing of the
	// VM's memory is mergeable.
	pids := hypervisorProcesses(t, r.config.RunDir)
	if len(pids) != 1 {
		t.Fatalf("hypervisor processes of the suite: %v, want the run's one", pids)
	}
	raw, err := os.ReadFile("/proc/" + pids[0] + "/maps")
	if err != nil {
		t.Fatal(err)
	}
	images, err := os.ReadDir(r.config.ImageMountDir)
	if err != nil || len(images) != 1 {
		t.Fatalf("images mounted while one run is restored: %v %v", images, err)
	}
	info, err := os.Stat(filepath.Join(r.config.ImageMountDir, images[0].Name(), "memory-ranges"))
	if err != nil {
		t.Fatal(err)
	}
	var mapped int64
	var mappings []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasSuffix(line, "/memory-ranges") {
			continue
		}
		fields := strings.Fields(line)
		ends := strings.Split(fields[0], "-")
		start, _ := strconv.ParseInt(ends[0], 16, 64)
		end, _ := strconv.ParseInt(ends[1], 16, 64)
		mapped += end - start
		mappings = append(mappings, fmt.Sprintf("%s %d", fields[1], end-start))
	}
	if mapped < info.Size() || len(mappings) == 0 {
		t.Fatalf("the memory file (%d bytes) is mapped over %d bytes in %d mappings", info.Size(), mapped, len(mappings))
	}
	for _, mapping := range mappings {
		if !strings.HasPrefix(mapping, "rw-p ") {
			t.Errorf("the memory file is mapped %s, want privately and read-write", mapping)
		}
	}
	pid, _ := strconv.Atoi(pids[0])
	if merged := mergeableMappings(t, pid); len(merged) > 0 {
		t.Errorf("the restored VM has mergeable mappings: %v", merged)
	}
	t.Logf("the memory file is mapped over %d mappings: %s", len(mappings), strings.Join(mappings, ", "))
	// What the restore cost, step by step.
	for _, line := range r.says("vm restore steps", "name=teploy-sbx-"+strings.ToLower(id)) {
		t.Log(line)
	}
}

// mountedAt is whether anything is mounted at path (as /proc/self/mountinfo
// says of it).
func mountedAt(t *testing.T, path string) bool {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if fields := strings.Fields(line); len(fields) > 6 && fields[4] == path {
			return true
		}
	}
	return false
}

// registryImage is the stopped run's memory image as the daemon's
// registry keeps it: the wrapped key included, which the API never
// shows.
func registryImage(t *testing.T, stateDir, id string) run.MemoryImage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDir, "runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Runs []struct {
			ID     string          `json:"id"`
			Memory json.RawMessage `json:"memory"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	for _, entry := range registry.Runs {
		if entry.ID == id {
			var memory run.MemoryImage
			if err := json.Unmarshal(entry.Memory, &memory); err != nil || memory.ID == "" {
				t.Fatalf("run %s names no memory image in the registry (%v)", id, err)
			}
			return memory
		}
	}
	t.Fatalf("run %s is not in the registry", id)
	return run.MemoryImage{}
}

// imageKey unwraps a run's image key as the daemon does before a resume:
// the registry's wrapped key under the host's secret, bound to the run
// and the image together (internal/vm/memory_images.go). The daemon
// closes an image when it hands it to a record, so whoever would look
// inside one needs both.
func imageKey(t *testing.T, config vm.Config, runID string, memory run.MemoryImage) []byte {
	t.Helper()
	secret, err := os.ReadFile(config.HostSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	wrapping, err := hkdf.Key(sha256.New, secret, nil, "teploy-sandbox/v2/local-image-wrap", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrapping)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := base64.RawStdEncoding.DecodeString(memory.Key)
	if err != nil || len(blob) < aead.NonceSize() {
		t.Fatalf("the registry's wrapped key of image %s: %v", memory.ID, err)
	}
	nonce, sealed := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	key, err := aead.Open(nil, nonce, sealed, []byte("teploy-sandbox/v2/local-image/default/"+runID+"/"+memory.ID))
	if err != nil || len(key) != 32 {
		t.Fatalf("the record's key does not open under the host's secret: %v", err)
	}
	return key
}

// unseal opens a sealed image for a moment, as an administrator would to
// repair it (its key loaded, then mounted), and leaves it as the daemon
// does: closed, and sealed.
func unseal(t *testing.T, config vm.Config, runID string, memory run.MemoryImage, change func()) {
	t.Helper()
	dataset := config.ImageDataset + "/" + memory.ID
	key := imageKey(t, config, runID, memory)
	defer clear(key)
	load := exec.Command("zfs", "load-key", dataset)
	load.Stdin = bytes.NewReader(key)
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("zfs load-key %s: %v %s", dataset, err, out)
	}
	defer zfs(t, "unload-key", dataset)
	zfs(t, "mount", dataset)
	defer zfs(t, "unmount", dataset)
	zfs(t, "set", "readonly=off", dataset)
	defer zfs(t, "set", "readonly=on", dataset)
	change()
}

// rewrite writes a file of an unsealed image and leaves it as sealing
// left it: root's and read-only.
func rewrite(t *testing.T, path string, change func(raw []byte) []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Chmod(path, 0o600))
	must(os.WriteFile(path, change(raw), 0o600))
	must(os.Chmod(path, 0o444))
}

// registryChange changes the run's memory image in the daemon's
// registry, in place, as a registry written on another host would differ.
func registryChange(t *testing.T, stateDir, id string, change func(memory map[string]any)) {
	t.Helper()
	path := filepath.Join(stateDir, "runs.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var registry map[string]any
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range registry["runs"].([]any) {
		run := entry.(map[string]any)
		if run["id"] == id {
			if run["memory"] == nil {
				t.Fatalf("run %s names no memory image in the registry", id)
			}
			change(run["memory"].(map[string]any))
			found = true
		}
	}
	if !found {
		t.Fatalf("run %s is not in the registry", id)
	}
	if raw, err = json.MarshalIndent(registry, "", "  "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestVMMemoryResume is the whole of it on a real hypervisor and a real
// pool: stop and resume with the processes, files and a listening server
// intact; corrupted, missing, wrong-key and wrong-class images each
// falling back to the disk; a networked run restored onto its device; a
// daemon restart; no seccomp kill; and the timings.
func TestVMMemoryResume(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := memoryTestConfig(t)
	ctx := context.Background()
	started := time.Now()
	baseline := poolListing(t, config.Pool)
	if slices.Contains(baseline, config.ImageDataset) {
		t.Fatalf("%s is in the pool before the test: a previous attempt left it", config.ImageDataset)
	}
	stateDir := t.TempDir()
	r := newMemoryDaemon(t, config, stateDir)
	var ids []string
	t.Cleanup(func() {
		for _, id := range ids {
			_ = r.manager.Destroy(context.Background(), id)
		}
	})
	create := func(network string) string {
		t.Helper()
		created, err := r.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, TTLSec: 3600, Network: network, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		ids = append(ids, created.ID)
		return created.ID
	}
	stop := func(id string) (dataset string) {
		t.Helper()
		if _, err := r.manager.Stop(ctx, id); err != nil {
			t.Fatalf("stop: %v", err)
		}
		return config.ImageDataset + "/" + memoryImage(t, r, id).Image
	}
	resume := func(id, from string) {
		t.Helper()
		resumed, err := r.manager.Resume(ctx, id, 0)
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		if resumed.ResumedFrom != from {
			t.Fatalf("the run resumed from %q, want %q; the daemon said:\n%s", resumed.ResumedFrom, from, r.log.String())
		}
	}
	destroy := func(id string) {
		t.Helper()
		if err := r.manager.Destroy(ctx, id); err != nil {
			t.Fatalf("destroy: %v", err)
		}
	}

	// --- a stop saves the memory beside the disk snapshot, and the resume
	// restores the VM from it.
	id := create(run.NetworkNone)
	guestStarts(t, r, id)
	reseedsBefore := forkReseeds(t, r, id)
	// While the image is written the VM's memory limit covers it: the
	// snapshot of a restored VM reads its last image's pages into the
	// page cache of the VM's own memory group, which killed a hypervisor
	// mid-snapshot once (465 MiB resident against the 584 MiB allowed).
	// The limit is watched while the stop runs, and is the VM's own again
	// after.
	// The window is asserted, not only its widths: the guest never runs
	// with the limit raised, and the limit is raised with the image in
	// the jail's reach and put back once it is out of it (watchStop).
	watch := watchStop(t, config, id)
	began := time.Now()
	dataset := stop(id)
	stopTook := time.Since(began)
	wantLimit, wantWidest := int64(vm.MemoryLimitMB(512))<<20, int64(vm.MemoryLimitMB(512))<<20+r.driver.MemoryNeedsBytes(512)
	watch.assertWindow(t, "the stop of a booted VM", wantLimit, wantWidest)
	image := imageDir(t, r, id)
	// The image: an encrypted filesystem of its own, sealed; and closed
	// while the run is stopped, as nothing reads it: unmounted and its key
	// unloaded, where only root can name it.
	for name, want := range map[string]string{
		"encryption": "aes-256-gcm", "keyformat": "raw", "keylocation": "prompt", "keystatus": "unavailable", "mounted": "no",
		"readonly": "on", "exec": "off", "setuid": "off", "devices": "off", "compression": "lz4", "primarycache": "metadata",
		"quota": "576M",
	} {
		if got := zfsProperty(t, dataset, name); got != want {
			t.Errorf("the image dataset's %s is %q, want %q", name, got, want)
		}
	}
	if mountedAt(t, image) {
		t.Errorf("the image of a stopped run is mounted at %s", image)
	}
	if entries, err := os.ReadDir(image); err != nil || len(entries) != 0 {
		t.Errorf("where a closed image is mounted there is %v (%v), want the empty mount point", entries, err)
	}
	if info, err := os.Stat(config.ImageMountDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the images' directory: %v %v", info, err)
	}
	if lines := r.says("vm memory image saved"); len(lines) != 1 {
		t.Errorf("the daemon did not say the image was saved:\n%s", r.log.String())
	}
	// Nothing of the image stays where the VM could reach it.
	if out, _ := exec.Command("grep", "-rl", memoryImage(t, r, id).Image, config.RunDir).Output(); len(out) > 0 {
		t.Errorf("a VM's runtime directory names the image: %s", out)
	}

	began = time.Now()
	resume(id, run.ResumedFromMemory)
	resumeTook := time.Since(began)
	first := vmRun(t, r.manager, id, "true", "", nil, 30*time.Second)
	firstExecTook := time.Since(began)
	if first.code != 0 {
		t.Fatalf("first exec: %+v", first)
	}
	guestCameBack(t, r, id, reseedsBefore, true)
	if lines := r.says("vm restored from its memory image"); len(lines) != 1 {
		t.Errorf("the daemon did not say the VM was restored:\n%s", r.log.String())
	}
	// The resume opened the image, and it stays open while the VM
	// restored from it lives, since the VM reads its memory through the
	// mount: mounted, its key loaded, its files root's and read-only.
	for name, want := range map[string]string{"keystatus": "available", "mounted": "yes"} {
		if got := zfsProperty(t, dataset, name); got != want {
			t.Errorf("the restored VM's image has %s %q, want %q", name, got, want)
		}
	}
	var names []string
	for _, entry := range mustReadDir(t, image) {
		info, _ := entry.Info()
		names = append(names, fmt.Sprintf("%s %04o", entry.Name(), info.Mode().Perm()))
	}
	if got := strings.Join(names, ", "); got != "config.json 0444, memory-ranges 0444, state.json 0444" {
		t.Errorf("the image holds %s", got)
	}
	if info, err := os.Stat(image); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("the image's directory: %v %v", info, err)
	}
	// What the hypervisor wrote, for the record: the unit tests mirror
	// this file.
	if raw, err := os.ReadFile(filepath.Join(image, "config.json")); err == nil {
		t.Logf("the saved configuration of the VM:\n%s", raw)
	}
	t.Logf("stop with memory %s; resume %s; first exec after %s", stopTook.Round(time.Millisecond), resumeTook.Round(time.Millisecond), firstExecTook.Round(time.Millisecond))
	for _, line := range r.says("vm restore steps", "vm memory image saved") {
		t.Log(line)
	}
	// The record no longer names the image; the VM restored from it holds
	// it, and it goes when that VM does.
	if view, _ := r.manager.Get(id); view.Memory != nil {
		t.Errorf("a running run claims a memory image: %+v", view.Memory)
	}
	if !slices.Contains(poolListing(t, config.ImageDataset), dataset) {
		t.Fatal("the image went before the VM restored from it")
	}
	// A VM restored from an image can be saved again: its hypervisor,
	// whose sandbox came from the daemon's rewritten configuration,
	// writes its snapshot where that configuration allows, and nowhere
	// else. If it had not been allowed to, the stop would say so.
	// The same for a VM restored from an image, which is the one that
	// was killed: its image's pages are its own memory, read through the
	// mount, and the new image goes on top.
	watch = watchStop(t, config, id)
	if again := stop(id); again == dataset {
		t.Fatal("the second stop saved the same image")
	} else if image := memoryImage(t, r, id); image.State != run.MemorySaved {
		t.Fatalf("a VM restored from its memory could not be saved again: %+v\n%s", image, r.log.String())
	}
	watch.assertWindow(t, "the stop of a restored VM", wantLimit, wantWidest)
	if slices.Contains(poolListing(t, config.ImageDataset), dataset) {
		t.Fatal("the first image outlived the VM restored from it, which is gone now")
	}
	destroy(id)
	ids = nil
	if left := poolListing(t, config.ImageDataset); !slices.Equal(left, []string{config.ImageDataset}) {
		t.Fatalf("images left on the pool: %v", left)
	}

	// --- every image that cannot be used boots the disk: the same guest,
	// from its disk snapshot.
	for name, spoil := range map[string]func(t *testing.T, config vm.Config, runID string, memory run.MemoryImage, dataset, image string){
		"corrupted": func(t *testing.T, config vm.Config, runID string, memory run.MemoryImage, dataset, image string) {
			// The devices' state, scrambled where it is sealed: the
			// hypervisor can make no VM of it. The image is closed at
			// rest; whoever repairs one opens it as this does.
			unseal(t, config, runID, memory, func() {
				rewrite(t, filepath.Join(image, "state.json"), func(raw []byte) []byte {
					for i := range min(len(raw), 4096) {
						raw[i] = 0xff
					}
					return raw
				})
			})
		},
		"truncated": func(t *testing.T, config vm.Config, runID string, memory run.MemoryImage, dataset, image string) {
			// Less memory than the guest has.
			unseal(t, config, runID, memory, func() {
				rewrite(t, filepath.Join(image, "memory-ranges"), func(raw []byte) []byte { return raw[:1<<20] })
			})
		},
		"missing": func(t *testing.T, _ vm.Config, _ string, _ run.MemoryImage, dataset, _ string) {
			zfs(t, "destroy", dataset)
		},
	} {
		id := create(run.NetworkNone)
		guestStarts(t, r, id)
		reseedsBefore := forkReseeds(t, r, id)
		dataset := stop(id)
		memory := registryImage(t, stateDir, id)
		image := filepath.Join(r.config.ImageMountDir, memory.ID)
		spoil(t, config, id, memory, dataset, image)
		resume(id, run.ResumedFromDisk)
		guestCameBack(t, r, id, reseedsBefore, false)
		if lines := r.says("vm memory image not used; booting from the disk"); len(lines) == 0 {
			t.Errorf("%s: the daemon did not say the image was not used:\n%s", name, r.log.String())
		}
		destroy(id)
	}
	ids = nil

	// --- the key of another host: a registry copied from elsewhere opens
	// none of its images, and a restart on the same host opens them.
	id = create(run.NetworkNone)
	guestStarts(t, r, id)
	reseedsBefore = forkReseeds(t, r, id)
	stop(id)
	other := config
	other.HostSecret = config.HostSecret + ".other"
	r = newMemoryDaemon(t, other, stateDir)
	resume(id, run.ResumedFromDisk)
	guestCameBack(t, r, id, reseedsBefore, false)
	destroy(id)
	ids = nil

	// --- an image of another host class: the hypervisor was upgraded.
	id = create(run.NetworkNone)
	guestStarts(t, r, id)
	reseedsBefore = forkReseeds(t, r, id)
	dataset = stop(id)
	registryChange(t, stateDir, id, func(memory map[string]any) { memory["class"] = "another class" })
	r = newMemoryDaemon(t, config, stateDir)
	resume(id, run.ResumedFromDisk)
	guestCameBack(t, r, id, reseedsBefore, false)
	destroy(id)
	ids = nil

	// --- a daemon restart on the same host: the image is still the run's.
	id = create(run.NetworkNone)
	guestStarts(t, r, id)
	reseedsBefore = forkReseeds(t, r, id)
	dataset = stop(id)
	r = newMemoryDaemon(t, config, stateDir)
	resume(id, run.ResumedFromMemory)
	guestCameBack(t, r, id, reseedsBefore, true)
	destroy(id)
	ids = nil

	// --- timings: five stops, resumed from memory and from the disk in
	// turn, to the first exec.
	t.Logf("TIMINGS %s", memoryTimings(t, config, stateDir, r))
	ids = nil

	// --- a networked run is restored onto a new device, moved to the
	// run's address of the day.
	id = create(run.NetworkOpen)
	if got := vmRun(t, r.manager, id, `curl -s -m 15 -o /dev/null -w '%{http_code}' http://deb.debian.org/`, "", nil, 40*time.Second); !strings.HasSuffix(got.stdout, "200") && !strings.HasSuffix(got.stdout, "301") {
		t.Fatalf("the networked run does not reach the network before its stop: %+v", got)
	}
	devices := vmRun(t, r.manager, id, `ls /sys/class/net | grep -v '^lo$' | wc -l`, "", nil, 30*time.Second)
	stop(id)
	resume(id, run.ResumedFromMemory)
	if got := vmRun(t, r.manager, id, `ls /sys/class/net | grep -v '^lo$' | wc -l`, "", nil, 30*time.Second); got.stdout != devices.stdout {
		t.Fatalf("the restored VM's devices: %q (before %q)", got.stdout, devices.stdout)
	}
	if got := vmRun(t, r.manager, id, `curl -s -m 15 -o /dev/null -w '%{http_code}' http://deb.debian.org/`, "", nil, 40*time.Second); !strings.HasSuffix(got.stdout, "200") && !strings.HasSuffix(got.stdout, "301") {
		t.Fatalf("the restored networked run does not reach the network: %+v:\n%s", got, r.log.String())
	}
	if lines := r.says("vm restored network device ready"); len(lines) != 1 {
		t.Errorf("the daemon did not move the restored VM's device:\n%s", r.log.String())
	}
	destroy(id)
	ids = nil

	// --- nothing was killed by a filter, and the pool is as it was.
	if kills := kernelMessages(t, started, "type=1326"); len(kills) > 0 {
		t.Errorf("the kernel's seccomp audit logged %d kills:\n%s", len(kills), strings.Join(kills, "\n"))
	}
	if denials := kernelMessages(t, started, "landlock"); len(denials) > 0 {
		t.Errorf("the kernel logged Landlock denials:\n%s", strings.Join(denials, "\n"))
	}
	for _, line := range strings.Split(r.log.String(), "\n") {
		if strings.Contains(line, "level=ERROR") {
			t.Errorf("the daemon logged an error:\n%s", line)
		}
	}
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left: %v", left)
	}
	// The suite's image dataset is empty now; it goes in the cleanup.
	if got := poolListing(t, config.ImageDataset); !slices.Equal(got, []string{config.ImageDataset}) {
		t.Errorf("images left on the pool: %v", got)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, append(slices.Clone(baseline), config.ImageDataset)) {
		t.Fatalf("the pool after the test:\n  %v\nwant the baseline and %s:\n  %v", got, config.ImageDataset, baseline)
	}
}

func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// memoryTimings stops and resumes one run ten times, in turn from its
// memory and from its disk, and reports each median (min–max) in
// milliseconds.
func memoryTimings(t *testing.T, config vm.Config, stateDir string, r *memoryRig) string {
	t.Helper()
	ctx := context.Background()
	created, err := r.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, TTLSec: 3600, Limits: &run.Limits{MemoryMB: 512, CPUs: 1}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.ID
	defer func() { _ = r.manager.Destroy(context.Background(), id) }()
	samples := map[string][]time.Duration{}
	for i := range 10 {
		began := time.Now()
		stopped, err := r.manager.Stop(ctx, id)
		if err != nil {
			t.Fatalf("stop %d: %v", i, err)
		}
		samples["stopWithMemory"] = append(samples["stopWithMemory"], time.Since(began))
		if stopped.Memory == nil || stopped.Memory.State != run.MemorySaved {
			t.Fatalf("stop %d saved no image: %+v", i, stopped.Memory)
		}
		kind := "memory"
		if i%2 == 1 {
			// A cold resume: the same run, its image gone.
			kind = "disk"
			zfs(t, "destroy", config.ImageDataset+"/"+stopped.Memory.Image)
		}
		began = time.Now()
		resumed, err := r.manager.Resume(ctx, id, 0)
		if err != nil {
			t.Fatalf("resume %d: %v", i, err)
		}
		samples[kind+"ResumeCall"] = append(samples[kind+"ResumeCall"], time.Since(began))
		want := run.ResumedFromMemory
		if kind == "disk" {
			want = run.ResumedFromDisk
		}
		if resumed.ResumedFrom != want {
			t.Fatalf("resume %d: from %q, want %q:\n%s", i, resumed.ResumedFrom, want, r.log.String())
		}
		first := vmRun(t, r.manager, id, "true", "", nil, 30*time.Second)
		if first.code != 0 {
			t.Fatalf("first exec %d: %+v", i, first)
		}
		samples[kind+"ResumeToFirstExec"] = append(samples[kind+"ResumeToFirstExec"], time.Since(began))
	}
	report := map[string]string{}
	for name, times := range samples {
		report[name] = median(times)
	}
	raw, _ := json.Marshal(report)
	return string(raw)
}

// median is "median (min–max)" of samples, in milliseconds.
func median(samples []time.Duration) string {
	if len(samples) == 0 {
		return "none"
	}
	sorted := slices.Clone(samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	ms := func(d time.Duration) int64 { return d.Milliseconds() }
	middle := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		middle = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	return fmt.Sprintf("%d (%d–%d)", ms(middle), ms(sorted[0]), ms(sorted[len(sorted)-1]))
}

// Two restores of one image do not read one random stream: the first
// bytes each restored guest reads from its generator differ. Both start
// from the state the image saved, so without a reseed at the restore
// they would read the same stream, and whatever generated a key in the
// memory of one could be replayed from the other. (A reading before the
// stop compared with one after it shows nothing: the stream had moved on
// past the first reading when the memory was saved. A review of the
// first cut asked for a check that can fail.)
//
// This goes through the driver as a resume does, with the record holding
// the image across both restores: the manager lets a record go of its
// image at the first resume, so it could not restore one twice. One VM
// runs at a time.
func TestVMMemoryRestoresOfOneImageReadTwoRandomStreams(t *testing.T) {
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	config := memoryTestConfig(t)
	baseline := poolListing(t, config.Pool)
	if slices.Contains(baseline, config.ImageDataset) {
		t.Fatalf("%s is in the pool before the test: a previous attempt left it", config.ImageDataset)
	}
	r := newMemoryDaemon(t, config, t.TempDir())
	ctx := context.Background()
	driver := r.driver
	const memoryMB, cpus = 512, 1
	// A reading in a VM the driver runs for the test alone: the first
	// bytes of the random stream, or the kernel's count of reseeds.
	in := func(id, what string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code, timedOut, err := driver.Exec(ctx, id, what, "/", nil, 30*time.Second, &stdout, &stderr); err != nil || timedOut || code != 0 || stderr.Len() > 0 {
			t.Fatalf("in the VM %s, %q: code %d, timed out %t, %v\nstdout: %s\nstderr: %s", id, what, code, timedOut, err, stdout.String(), stderr.String())
		}
		return strings.TrimSpace(stdout.String())
	}
	const sample = "head -c 32 /dev/urandom | sha256sum | cut -c1-16"
	// grep -c answers 0 with the status of "no line": here that is a
	// reading, not a failure. A kernel log that cannot be read is one.
	const reseeds = "dmesg | grep -c 'crng reseeded due to virtual machine fork' || test $? = 1"
	var record *run.MemoryImage
	var ref string
	var vms []string
	t.Cleanup(func() {
		// Whatever a failed attempt left, before the suite's dataset goes
		// in memoryTestConfig's cleanup.
		for _, id := range vms {
			_ = driver.Remove(ctx, id)
		}
		if record != nil {
			_ = driver.ReleaseMemory(ctx, record)
		}
		if ref != "" {
			_ = driver.RemoveImage(ctx, ref)
		}
	})
	name := func() string { return run.ContainerName(run.NewULID(time.Now())) }
	spec := run.CreateSpec{Name: name(), Image: vm.GoldenImage, MemoryMB: memoryMB, CPUs: cpus}
	saved, err := driver.Create(ctx, spec)
	if err != nil || saved != spec.Name {
		t.Fatalf("create: %q %v", saved, err)
	}
	vms = append(vms, saved)
	// What the image will hold: the kernel log as it is before any
	// restore (empty of reseeds, with a driver that logs one only at a
	// restore).
	count := in(saved, reseeds)
	reseedsBefore, err := strconv.Atoi(count)
	if err != nil {
		t.Fatalf("the kernel's count of reseeds reads %q: %v", count, err)
	}
	// The run the image belongs to: its key is wrapped for that run and
	// that image together, so every restore of it names the same run.
	runID := "run-" + saved
	ref = driver.NewSnapshotRef(time.Now())
	record, note, err := driver.SaveMemory(ctx, runID, saved, ref)
	if err != nil || record == nil || note != "" {
		t.Fatalf("save: %+v %q %v\n%s", record, note, err, r.log.String())
	}
	// The VM that wrote it is gone; the record's is the image now, and it
	// stays for the second restore.
	if err := driver.Remove(ctx, saved); err != nil {
		t.Fatal(err)
	}
	vms = nil
	dataset := config.ImageDataset + "/" + record.ID
	if !slices.Contains(poolListing(t, config.ImageDataset), dataset) {
		t.Fatal("the image went with the VM that wrote it, while its record still names it")
	}

	restore := func(n int) string {
		t.Helper()
		spec := run.CreateSpec{Name: name(), Image: ref, MemoryMB: memoryMB, CPUs: cpus}
		id, from, note, err := driver.ResumeMemory(ctx, runID, spec, record)
		if err != nil || from != run.ResumedFromMemory || note != "" {
			t.Fatalf("restore %d: id %q from %q note %q err %v\n%s", n, id, from, note, err, r.log.String())
		}
		vms = append(vms, id)
		// The kernel reseeded at this restore, of this image: the count
		// is one more than the image was saved with.
		if after, err := strconv.Atoi(in(id, reseeds)); err != nil || after != reseedsBefore+1 {
			t.Errorf("restore %d: the kernel's count of reseeds is %d (%v), want %d", n, after, err, reseedsBefore+1)
		}
		first := in(id, sample)
		if err := driver.Remove(ctx, id); err != nil {
			t.Fatal(err)
		}
		vms = vms[:len(vms)-1]
		return first
	}
	first, second := restore(1), restore(2)
	t.Logf("the first 32 bytes of the restored guests' random streams: %s, %s", first, second)
	if len(first) != 16 || len(second) != 16 {
		t.Fatalf("the readings are %q and %q", first, second)
	}
	if first == second {
		t.Fatalf("two restores of one image read the same random stream: %s", first)
	}
	// Nothing of the test is left: the image with its record's claim, the
	// snapshot, the VMs; and the pool is as it was found.
	if err := driver.ReleaseMemory(ctx, record); err != nil {
		t.Fatal(err)
	}
	record = nil
	if err := driver.RemoveImage(ctx, ref); err != nil {
		t.Fatal(err)
	}
	ref = ""
	if left := hypervisorProcesses(t, config.RunDir); len(left) != 0 {
		t.Errorf("hypervisor processes left: %v", left)
	}
	if got := poolListing(t, config.ImageDataset); !slices.Equal(got, []string{config.ImageDataset}) {
		t.Errorf("images left on the pool: %v", got)
	}
	if got := poolListing(t, config.Pool); !slices.Equal(got, append(slices.Clone(baseline), config.ImageDataset)) {
		t.Errorf("the pool after the test: %v, want the baseline and %s: %v", got, config.ImageDataset, baseline)
	}
}
