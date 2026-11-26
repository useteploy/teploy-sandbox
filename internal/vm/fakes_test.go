package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
)

// fakeZFS models the part of ZFS the driver depends on, with the rules
// that make the driver's job hard kept intact: a snapshot with clones
// cannot be destroyed, a volume with snapshots cannot be destroyed, and
// promote moves the origin snapshot and every older one to the clone.
// Each volume carries a file map standing in for its disk, so a test can
// follow bytes through clones.
type fakeZFS struct {
	mu        sync.Mutex
	datasets  map[string]*fakeDataset
	snapshots map[string]*fakeSnapshot
	txg       int
	// calls is every mutation, in order; sends every stream sent, as
	// "[from ]snapshot".
	calls []string
	sends []string
	// fail makes the named call ("destroy pool/x") return an error once.
	fail map[string]error
	// blockClone, when not nil, is consumed by the next Clone, which
	// waits for it to close (or its context to end) and then fails.
	blockClone chan struct{}
	// poolProps are the properties set on the pool, which a volume
	// without its own value inherits.
	poolProps map[string]string
	guids     int
	guidBase  int
	// available and used are what Space reports; spaceAsked is the last
	// dataset it was asked about.
	available, used int64
	spaceAsked      string
	// fsCalls are the mounts and key loads of filesystems: they change
	// nothing in the pool, so they are not among calls.
	fsCalls []string
	// receiveAnything turns off Receive's check of a stream's first
	// record: for tests of what holds when that check is not there.
	receiveAnything bool
}

type fakeDataset struct {
	origin string
	props  map[string]string
	files  map[string][]byte
	// filesystem: not a volume. The driver makes only memory images;
	// a stream can.
	filesystem bool
	// For a filesystem that is an encryption root: its raw key, whether
	// the kernel has it (LoadKey), and whether it is mounted.
	fsKey       []byte
	fsKeyLoaded bool
	fsMounted   bool
}

type fakeSnapshot struct {
	txg int
	// guid is the snapshot's identity, which a stream carries with it.
	guid  string
	props map[string]string
	files map[string][]byte
}

const (
	testPool   = "tank/sbx"
	testGolden = testPool + "/golden@v1"
	testOwner  = "0123456789abcdef0123456789abcdef"
)

// newFakeZFS has a pool with an unowned golden volume and snapshot.
func newFakeZFS() *fakeZFS {
	z := &fakeZFS{datasets: map[string]*fakeDataset{}, snapshots: map[string]*fakeSnapshot{}, fail: map[string]error{}, poolProps: map[string]string{propVolmode: volmodeDev}}
	z.datasets[testPool+"/golden"] = &fakeDataset{props: map[string]string{}, files: map[string][]byte{}}
	z.snapshots[testGolden] = &fakeSnapshot{txg: z.tick(), guid: z.newGUID(), props: map[string]string{}, files: map[string][]byte{}}
	return z
}

func (z *fakeZFS) tick() int { z.txg++; return z.txg }

// newGUID is unique to a pool: guidBase tells two fake pools apart.
func (z *fakeZFS) newGUID() string {
	z.guids++
	return fmt.Sprint(z.guidBase + 7000 + z.guids)
}

func (z *fakeZFS) record(call string) error {
	z.calls = append(z.calls, call)
	if err, ok := z.fail[call]; ok {
		delete(z.fail, call)
		return err
	}
	return nil
}

func cloneFiles(files map[string][]byte) map[string][]byte {
	copied := make(map[string][]byte, len(files))
	for name, data := range files {
		copied[name] = bytes.Clone(data)
	}
	return copied
}

func (z *fakeZFS) describe(name string) Dataset {
	dataset := z.datasets[name]
	return Dataset{Name: name, Origin: dataset.origin, Owner: dataset.props[propOwner], Kind: dataset.props[propKind]}
}

func (z *fakeZFS) Dataset(_ context.Context, name string) (Dataset, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if _, ok := z.datasets[name]; !ok {
		return Dataset{}, ErrNoDataset
	}
	return z.describe(name), nil
}

func (z *fakeZFS) Volumes(_ context.Context, root string) ([]Dataset, error) {
	return z.list(root, false), nil
}

func (z *fakeZFS) Filesystems(_ context.Context, root string) ([]Dataset, error) {
	return z.list(root, true), nil
}

func (z *fakeZFS) list(root string, filesystems bool) []Dataset {
	z.mu.Lock()
	defer z.mu.Unlock()
	var listed []Dataset
	for name, dataset := range z.datasets {
		if strings.HasPrefix(name, root+"/") && dataset.filesystem == filesystems {
			listed = append(listed, z.describe(name))
		}
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].Name < listed[j].Name })
	return listed
}

func (z *fakeZFS) clonesOf(snapshot string) []string {
	var clones []string
	for name, dataset := range z.datasets {
		if dataset.origin == snapshot {
			clones = append(clones, name)
		}
	}
	sort.Strings(clones)
	return clones
}

func (z *fakeZFS) Snapshots(_ context.Context, dataset string) ([]SnapshotInfo, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if _, ok := z.datasets[dataset]; !ok {
		return nil, fmt.Errorf("cannot open '%s': dataset does not exist", dataset)
	}
	var names []string
	for name := range z.snapshots {
		if datasetOf(name) == dataset {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return z.snapshots[names[i]].txg < z.snapshots[names[j]].txg })
	infos := make([]SnapshotInfo, 0, len(names))
	for _, name := range names {
		infos = append(infos, SnapshotInfo{Name: name, Clones: z.clonesOf(name), Dead: z.snapshots[name].props[propDead] != ""})
	}
	return infos, nil
}

func (z *fakeZFS) Exists(_ context.Context, name string) (bool, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	_, isDataset := z.datasets[name]
	_, isSnapshot := z.snapshots[name]
	return isDataset || isSnapshot || name == strings.SplitN(testPool, "/", 2)[0] || name == testPool, nil
}

func (z *fakeZFS) Clone(ctx context.Context, snapshot, dataset string, props map[string]string) error {
	if z.blockClone != nil {
		// A test's hold on the next clone: it fails once, with the
		// caller's context error when that has run out.
		wait := z.blockClone
		z.blockClone = nil
		select {
		case <-wait:
		case <-ctx.Done():
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.New("clone held and released by a test")
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("clone " + snapshot + " " + dataset); err != nil {
		return err
	}
	source, ok := z.snapshots[snapshot]
	if !ok {
		return fmt.Errorf("cannot open '%s': dataset does not exist", snapshot)
	}
	if _, exists := z.datasets[dataset]; exists {
		return fmt.Errorf("cannot create '%s': dataset already exists", dataset)
	}
	z.datasets[dataset] = &fakeDataset{origin: snapshot, props: maps.Clone(props), files: cloneFiles(source.files)}
	return nil
}

func (z *fakeZFS) CreateVolume(_ context.Context, name string, _ int64, props map[string]string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("create " + name); err != nil {
		return err
	}
	if _, exists := z.datasets[name]; exists {
		return fmt.Errorf("cannot create '%s': dataset already exists", name)
	}
	z.datasets[name] = &fakeDataset{props: maps.Clone(props), files: map[string][]byte{}}
	return nil
}

func (z *fakeZFS) Snapshot(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("snapshot " + name); err != nil {
		return err
	}
	dataset, ok := z.datasets[datasetOf(name)]
	if !ok {
		return fmt.Errorf("cannot open '%s': dataset does not exist", datasetOf(name))
	}
	if _, exists := z.snapshots[name]; exists {
		return fmt.Errorf("cannot create snapshot '%s': dataset already exists", name)
	}
	z.snapshots[name] = &fakeSnapshot{txg: z.tick(), guid: z.newGUID(), props: map[string]string{}, files: cloneFiles(dataset.files)}
	return nil
}

func (z *fakeZFS) Promote(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("promote " + name); err != nil {
		return err
	}
	clone, ok := z.datasets[name]
	if !ok {
		return fmt.Errorf("cannot open '%s': dataset does not exist", name)
	}
	if clone.origin == "" {
		return fmt.Errorf("cannot promote '%s': not a cloned filesystem", name)
	}
	parentName := datasetOf(clone.origin)
	parent := z.datasets[parentName]
	cutoff := z.snapshots[clone.origin].txg
	moves := map[string]string{}
	for snapshot, info := range z.snapshots {
		if datasetOf(snapshot) == parentName && info.txg <= cutoff {
			moved := name + "@" + strings.SplitN(snapshot, "@", 2)[1]
			if _, conflict := z.snapshots[moved]; conflict {
				return fmt.Errorf("cannot promote '%s': conflicting snapshot '%s' from parent '%s'", name, moved, parentName)
			}
			moves[snapshot] = moved
		}
	}
	for from, to := range moves {
		z.snapshots[to] = z.snapshots[from]
		delete(z.snapshots, from)
	}
	oldOrigin := clone.origin
	for _, dataset := range z.datasets {
		if to, ok := moves[dataset.origin]; ok {
			dataset.origin = to
		}
	}
	clone.origin = parent.origin
	parent.origin = moves[oldOrigin]
	return nil
}

func (z *fakeZFS) Destroy(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("destroy " + name); err != nil {
		return err
	}
	if _, ok := z.snapshots[name]; ok {
		if clones := z.clonesOf(name); len(clones) > 0 {
			return fmt.Errorf("cannot destroy '%s': snapshot has dependent clones", name)
		}
		delete(z.snapshots, name)
		return nil
	}
	if _, ok := z.datasets[name]; !ok {
		// As the real one: a command's failure, which isMissing knows.
		return zfsError(fmt.Sprintf("cannot open '%s': dataset does not exist", name))
	}
	for snapshot := range z.snapshots {
		if datasetOf(snapshot) == name {
			return fmt.Errorf("cannot destroy '%s': volume has children", name)
		}
	}
	delete(z.datasets, name)
	return nil
}

func (z *fakeZFS) Property(_ context.Context, name, key string) (string, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if snapshot, ok := z.snapshots[name]; ok && key == "guid" {
		return snapshot.guid, nil
	}
	if dataset, ok := z.datasets[name]; ok {
		if key == "type" {
			if dataset.filesystem {
				return "filesystem", nil
			}
			return "volume", nil
		}
		if value, ok := dataset.props[key]; ok {
			return value, nil
		}
		// What zfs reports of an encrypted filesystem, as zfs get does.
		if dataset.filesystem {
			switch key {
			case propMounted:
				if dataset.fsKey == nil {
					return "-", nil
				}
				if dataset.fsMounted {
					return "yes", nil
				}
				return "no", nil
			case propKeyStatus:
				if dataset.fsKey == nil {
					return "-", nil
				}
				if dataset.fsKeyLoaded {
					return "available", nil
				}
				return "unavailable", nil
			}
		}
	}
	return z.poolProps[key], nil
}

func (z *fakeZFS) SetProperty(_ context.Context, name, key, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("set " + key + "=" + value + " " + name); err != nil {
		return err
	}
	if snapshot, ok := z.snapshots[name]; ok {
		snapshot.props[key] = value
		return nil
	}
	if dataset, ok := z.datasets[name]; ok {
		dataset.props[key] = value
		return nil
	}
	return fmt.Errorf("cannot open '%s': dataset does not exist", name)
}

// fakeStream is what the fake pool sends: the snapshot's identity, the
// identity of what it is incremental against, and its files. A real
// stream carries only the difference; the rules around it are the same.
type fakeStream struct {
	GUID     string
	FromGUID string
	Files    map[string][]byte
	// Filesystem: the stream of a filesystem, which a volume's pool
	// must never be made to hold.
	Filesystem bool `json:",omitempty"`
}

func (z *fakeZFS) Send(_ context.Context, snapshot, from string, w io.Writer) error {
	z.mu.Lock()
	source, ok := z.snapshots[snapshot]
	if !ok {
		z.mu.Unlock()
		return fmt.Errorf("cannot open '%s': dataset does not exist", snapshot)
	}
	stream := fakeStream{GUID: source.guid, Files: cloneFiles(source.files)}
	if from != "" {
		base, ok := z.snapshots[from]
		if !ok {
			z.mu.Unlock()
			return fmt.Errorf("cannot open '%s': dataset does not exist", from)
		}
		if base.txg >= source.txg {
			z.mu.Unlock()
			return fmt.Errorf("incremental source (%s) is not earlier than it", from)
		}
		stream.FromGUID = base.guid
	}
	// Not among calls: a send changes nothing.
	z.sends = append(z.sends, strings.TrimSpace(from+" "+snapshot))
	z.mu.Unlock()
	encoded, err := json.Marshal(stream)
	if err != nil {
		return err
	}
	// A length in front, so that a stream cut short is seen as one.
	header := fmt.Sprintf("%016d", len(encoded))
	_, err = w.Write(append([]byte(header), encoded...))
	return err
}

func (z *fakeZFS) Receive(_ context.Context, snapshot, origin string, props map[string]string, expect StreamIdentity, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("receive " + snapshot); err != nil {
		return err
	}
	if len(data) < 16 {
		return errors.New("cannot receive: incomplete stream")
	}
	var length int
	if _, err := fmt.Sscanf(string(data[:16]), "%d", &length); err != nil || len(data)-16 != length {
		return errors.New("cannot receive new filesystem stream: incomplete stream")
	}
	var stream fakeStream
	if err := json.Unmarshal(data[16:], &stream); err != nil {
		return errors.New("cannot receive: invalid stream")
	}
	// As the real Receive holds a stream to its first record.
	if !z.receiveAnything && (stream.Filesystem || stream.GUID != expect.GUID || stream.FromGUID != expect.FromGUID) {
		return fmt.Errorf("zfs receive %s refused: the stream is not the one the manifest names", snapshot)
	}
	dataset := datasetOf(snapshot)
	if _, exists := z.datasets[dataset]; exists {
		return fmt.Errorf("cannot receive new filesystem stream: destination '%s' exists", dataset)
	}
	switch {
	case stream.FromGUID != "" && origin == "":
		return errors.New("cannot receive incremental stream: no origin given")
	case stream.FromGUID != "":
		base, ok := z.snapshots[origin]
		if !ok {
			return fmt.Errorf("cannot receive: local origin '%s' does not exist", origin)
		}
		if base.guid != stream.FromGUID {
			return fmt.Errorf("cannot receive: local origin for clone %s does not match the stream", origin)
		}
	case origin != "":
		return errors.New("cannot receive: a full stream has no origin")
	}
	z.datasets[dataset] = &fakeDataset{origin: origin, props: maps.Clone(props), files: cloneFiles(stream.Files), filesystem: stream.Filesystem}
	z.snapshots[snapshot] = &fakeSnapshot{txg: z.tick(), guid: stream.GUID, props: map[string]string{}, files: cloneFiles(stream.Files)}
	return nil
}

func (z *fakeZFS) Space(_ context.Context, name string) (int64, int64, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.spaceAsked = name
	return z.available, z.used, nil
}

// names lists every dataset and snapshot, sorted: the whole pool.
func (z *fakeZFS) names() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	names := slices.Collect(maps.Keys(z.datasets))
	names = slices.AppendSeq(names, maps.Keys(z.snapshots))
	sort.Strings(names)
	return names
}

func (z *fakeZFS) originOf(name string) string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.datasets[name].origin
}

// mutations returns the calls that changed something outside the given
// names — what a test uses to prove foreign datasets were left alone.
func (z *fakeZFS) callsTouching(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	var touching []string
	for _, call := range z.calls {
		fields := strings.Fields(call)
		// The last field is what a call changes (clone's target, the
		// destroyed, promoted or re-propertied name).
		if target := fields[len(fields)-1]; target == name || datasetOf(target) == name {
			touching = append(touching, call)
		}
	}
	return touching
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestVolumes is Volumes on a fake pool, with device nodes that appear
// at once.
func newTestVolumes(z *fakeZFS) *Volumes {
	v := NewVolumes(z, testPool, testGolden, testOwner, quietLog())
	v.waitDevice = func(context.Context, string) error { return nil }
	v.flushDevice = func(string) error { return nil }
	v.checkDevice = func(string) error { return nil }
	return v
}

func runName(n int) string             { return fmt.Sprintf("%s%026d", runPrefix, n) }
func refID(n int) string               { return fmt.Sprintf("%026d", n) }
func noQuiesce() (func() error, error) { return func() error { return nil }, nil }

// pristine is what the pool holds when the driver owns nothing in it.
var pristine = []string{testPool + "/golden", testGolden}

func assertPool(t *testing.T, z *fakeZFS, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := z.names(); !slices.Equal(got, want) {
		t.Fatalf("pool holds\n  %v\nwant\n  %v", got, want)
	}
}

// fakeHypervisor boots fake machines whose guest filesystem is the fake
// volume they were given as a disk.
type fakeHypervisor struct {
	mu  sync.Mutex
	zfs *fakeZFS
	// deviceDir is stripped from a disk path to find its volume.
	deviceDir string
	started   []MachineConfig
	machines  map[string]*fakeMachine
	startErr  error
	// bootErr makes the next machine's agent never answer pings.
	bootErr error
	// dieOnBoot makes the next machine exit before its agent answers.
	dieOnBoot bool
	// bootGate, when set, holds every new machine's agent silent until
	// it is closed: a boot that takes as long as the test likes.
	bootGate chan struct{}
	// booting counts machines whose agent has not answered yet, and
	// peak the most there were at once.
	booting, peak int
	swept         int
	sweepErr      error
	// onStart is called with each new machine before it is returned.
	onStart func(*fakeMachine)
	// zfsCallsAtSweep is how many zfs mutations had happened when the
	// process sweep ran.
	zfsCallsAtSweep int
	// restored are the restore starts, in order (Restore); startErr
	// makes the next one fail before there is a machine, and
	// startedErr makes it fail after one was started, which is handed
	// back with the error.
	restored   []RestoreConfig
	restoreErr error
	startedErr error
	// outboxes: every booted VM's jail holds an outbox, at a directory
	// under outboxRoot, as it does when the driver keeps memory images.
	outboxes   bool
	outboxRoot string
}

func newFakeHypervisor(z *fakeZFS) *fakeHypervisor {
	return &fakeHypervisor{zfs: z, deviceDir: "/dev/zvol", machines: map[string]*fakeMachine{}}
}

func (h *fakeHypervisor) Start(_ context.Context, config MachineConfig) (Machine, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.startErr != nil {
		return nil, h.startErr
	}
	h.started = append(h.started, config)
	machine := &fakeMachine{
		config: config, zfs: h.zfs, volume: strings.TrimPrefix(config.Disk, h.deviceDir+"/"),
		exited: make(chan struct{}), pingErr: h.bootErr, gate: h.bootGate, hypervisor: h,
	}
	if h.outboxes {
		// The jail's outbox, made by the confinement on the host.
		machine.outbox = filepath.Join(h.outboxRoot, config.Name, outboxName)
		_ = os.MkdirAll(machine.outbox, 0o755)
	}
	h.booting++
	h.peak = max(h.peak, h.booting)
	if h.dieOnBoot {
		machine.pingErr = errors.New("connection refused")
		close(machine.exited)
		machine.dead = true
	}
	h.bootErr, h.dieOnBoot = nil, false
	if h.onStart != nil {
		h.onStart(machine)
	}
	h.machines[config.Name] = machine
	return machine, nil
}

// Restore is a hypervisor started for a restore: its API is up, and
// its machine has no VM until Machine.Restore.
func (h *fakeHypervisor) Restore(_ context.Context, config RestoreConfig) (Machine, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.restoreErr != nil {
		err := h.restoreErr
		h.restoreErr = nil
		return nil, err
	}
	h.restored = append(h.restored, config)
	machine := &fakeMachine{
		config: config.MachineConfig, zfs: h.zfs, volume: strings.TrimPrefix(config.Disk, h.deviceDir+"/"),
		exited: make(chan struct{}), up: true, hypervisor: h,
		inbox: "/run/sbx/abc/" + config.Name + inboxSuffix, imageDir: config.ImageDir,
	}
	if h.outboxes {
		// A restored VM's jail has an outbox too: it may be stopped
		// again with its memory saved.
		machine.outbox = filepath.Join(h.outboxRoot, config.Name, outboxName)
		_ = os.MkdirAll(machine.outbox, 0o755)
	}
	if h.onStart != nil {
		h.onStart(machine)
	}
	h.machines[config.Name] = machine
	if h.startedErr != nil {
		err := h.startedErr
		h.startedErr = nil
		return machine, errors.Join(errors.New("the hypervisor's API did not answer within 10s"), err)
	}
	return machine, nil
}

func (h *fakeHypervisor) Sweep(context.Context) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.swept++
	h.zfs.mu.Lock()
	h.zfsCallsAtSweep = len(h.zfs.calls)
	h.zfs.mu.Unlock()
	return 0, h.sweepErr
}

// mounted says that a mount under a VM's outbox appeared in its jail,
// or went: what a slave bind of the outbox does on a real host.
func (h *fakeHypervisor) mounted(target string, on bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, machine := range h.machines {
		if machine.outbox != "" && strings.HasPrefix(target, machine.outbox+string(filepath.Separator)) {
			machine.mu.Lock()
			if on {
				if machine.mounts == nil {
					machine.mounts = map[string]bool{}
				}
				machine.mounts[target] = true
			} else {
				delete(machine.mounts, target)
			}
			machine.mu.Unlock()
		}
	}
}

func (h *fakeHypervisor) machine(name string) *fakeMachine {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.machines[name]
}

// running lists the machines that have not been killed.
func (h *fakeHypervisor) running() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var names []string
	for name, machine := range h.machines {
		if !machine.isDead() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

type fakeMachine struct {
	config     MachineConfig
	zfs        *fakeZFS
	volume     string
	hypervisor *fakeHypervisor
	// gate holds the agent silent until it is closed; up records that it
	// has answered once.
	gate chan struct{}
	up   bool

	mu     sync.Mutex
	dead   bool
	paused bool
	// resumeErr is what Resume answers; nil resumes.
	resumeErr error
	// gone: the process is dead and its sockets fail, while exited may
	// not be closed yet (die).
	gone     bool
	exit     MachineExit
	exited   chan struct{}
	pingErr  error
	killErr  error
	pauseErr error
	// pauseLands makes a failing pause take effect anyway: the hypervisor
	// paused the VM, and the answer was lost.
	pauseLands bool
	syncErr    error
	// netMAC is the MAC of the network device the machine was given,
	// netTap whether the tap was open when it was handed over, and
	// addNetErr what AddNet answers.
	netMAC    string
	netTap    bool
	addNetErr error
	// events is the order of sync, pause, resume and kill calls.
	events []string
	// killDeadline is the deadline the last Kill was given.
	killDeadline time.Time
	// execs records each exec's merged environment; setups is the guest
	// setup scripts the driver ran, which are not a run's execs.
	execs  []map[string]string
	setups []string
	// execFunc answers an exec; nil echoes the command.
	execFunc func(cmd, cwd string, env map[string]string, timeout time.Duration, stdout, stderr io.Writer) (int, bool, error)
	// setupFunc answers the guest setup script; nil succeeds.
	setupFunc func(script string, stderr io.Writer) (int, bool, error)
	// booted records that the driver called Booted, and pinged whether
	// the agent had answered by then; bootedErr is what Booted answers.
	booted, pingedBeforeBooted bool
	bootedErr                  error
	// bootRead is what BootRead answers.
	bootRead int64
	// connectFunc answers a connect (guest protocol v2); nil is an agent
	// older than v2.
	connectFunc func(port int) (net.Conn, error)

	// Memory images: where the VM's outbox and, for a restored VM, its
	// image are; how its snapshot and restore answer.
	outbox, inbox, imageDir string
	snapshotErr             error
	// snapshotHook runs once the snapshot's files are written, with the
	// directory they were written to: what a hypervisor the guest took
	// over may add. snapshotWhilePaused records that the hypervisor was
	// asked for the memory of a paused VM.
	snapshotHook                func(dir string)
	snapshotWhilePaused         bool
	snapshotCalls, restoreCalls []string
	restoreErr                  error
	restoredRequests            []RestoreRequest
	cowFallsBack, restoredGuest bool
	mounts                      map[string]bool
	// restoredOp answers the "restored" handshake op (guest protocol
	// v3); nil is an agent older than v3.
	restoredOp func(nowNs int64, entropy []byte) (guest.RestoredResult, error)
	// entropySeen is what the restored op was given, in order.
	entropySeen [][]byte
	// handshake is each guest command the driver ran to bring a
	// restored guest up to date (its clock and its network device).
	handshake []string
	// restoreHook answers those commands; nil succeeds and prints what
	// a guest that did them would (restoreHookAnswers).
	restoreHook func(script string, stdout, stderr io.Writer) (int, bool, error)
}

func (m *fakeMachine) Agent() Agent            { return (*fakeAgent)(m) }
func (m *fakeMachine) Exited() <-chan struct{} { return m.exited }
func (m *fakeMachine) Diagnostics() string     { return "fake serial log" }

// Exit is how the process ended, and nothing before it has been reaped:
// a real machine's wait status is not there to be read until Exited is
// closed, and a driver that read it early would see no kill at all.
func (m *fakeMachine) Exit() MachineExit {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dead {
		return MachineExit{}
	}
	return m.exit
}

// die ends the machine as something other than the daemon would, and as
// a real hypervisor's end looks to the daemon: its sockets fail at once,
// and exited is closed lag later, once the process has been reaped.
func (m *fakeMachine) die(exit MachineExit, lag time.Duration) {
	m.mu.Lock()
	if m.gone || m.dead {
		m.mu.Unlock()
		return
	}
	m.gone, m.exit = true, exit
	m.mu.Unlock()
	reaped := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.dead {
			m.dead = true
			close(m.exited)
		}
	}
	if lag <= 0 {
		reaped()
		return
	}
	time.AfterFunc(lag, reaped)
}

func (m *fakeMachine) isDead() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dead
}

func (m *fakeMachine) event(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, name)
}

func (m *fakeMachine) Pause(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pauseErr != nil {
		if m.pauseLands {
			m.paused = true
		}
		return m.pauseErr
	}
	m.events = append(m.events, "pause")
	m.paused = true
	return nil
}

func (m *fakeMachine) Resume(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, "resume")
	if m.resumeErr == nil {
		m.paused = false
	}
	return m.resumeErr
}

func (m *fakeMachine) AddNet(_ context.Context, tap *os.File, mac string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addNetErr != nil {
		return m.addNetErr
	}
	if m.dead || m.gone {
		return errors.New("connection refused: vm is gone")
	}
	if m.netMAC != "" {
		return errors.New("the vm already has a network device")
	}
	_, statErr := tap.Stat()
	m.netMAC, m.netTap = mac, statErr == nil
	m.events = append(m.events, "add-net")
	return nil
}

func (m *fakeMachine) Booted() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.booted, m.pingedBeforeBooted = true, m.up
	return m.bootedErr
}

func (m *fakeMachine) BootRead() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bootRead
}

const fakeVMUID = 70123

func (m *fakeMachine) UID() uint32    { return fakeVMUID }
func (m *fakeMachine) Disk() string   { return m.config.Disk }
func (m *fakeMachine) Outbox() string { return m.outbox }
func (m *fakeMachine) Inbox() string  { return m.inbox }

// Snapshot writes the three files of a snapshot into the directory the
// daemon mounted for it, as the hypervisor does, and only while paused.
func (m *fakeMachine) Snapshot(_ context.Context, destination string) error {
	m.mu.Lock()
	if m.dead || m.gone {
		m.mu.Unlock()
		return errors.New("connection refused: vm is gone")
	}
	m.snapshotCalls = append(m.snapshotCalls, destination)
	if m.snapshotErr != nil {
		err := m.snapshotErr
		m.mu.Unlock()
		return err
	}
	if !m.paused {
		m.mu.Unlock()
		return &hypervisorRefusal{action: "vm.snapshot", status: "500 Internal Server Error", body: "Trying to snapshot while VM is running"}
	}
	m.snapshotWhilePaused = m.paused
	m.mu.Unlock()
	if !m.paused {
		return errors.New("not paused")
	}
	dir := strings.TrimPrefix(destination, "file://")
	memory, err := os.OpenFile(filepath.Join(dir, imageMemoryFile), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = memory.Truncate(int64(m.config.MemoryMB) << 20)
	memory.Close()
	_ = os.WriteFile(filepath.Join(dir, imageConfigFile), []byte(`{"cpus":{"boot_vcpus":1}}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, imageStateFile), []byte(`{}`), 0o600)
	if m.snapshotHook != nil {
		m.snapshotHook(dir)
	}
	return nil
}

// Restore brings the VM back, paused, from its image; the device's tap
// must be an open descriptor the hypervisor can take.
func (m *fakeMachine) Restore(_ context.Context, request RestoreRequest) error {
	m.event("restore")
	m.mu.Lock()
	if m.dead || m.gone {
		m.mu.Unlock()
		return errors.New("connection refused: vm is gone")
	}
	m.restoredRequests = append(m.restoredRequests, request)
	if m.restoreErr != nil {
		err := m.restoreErr
		m.mu.Unlock()
		return err
	}
	if request.NetFD != nil {
		if _, err := request.NetFD.Stat(); err != nil {
			m.mu.Unlock()
			return &hypervisorRefusal{action: "vm.restore", status: "400 Bad Request", body: "the tap is not an open descriptor"}
		}
	}
	m.restoredGuest, m.paused = true, true
	m.mu.Unlock()
	return nil
}

func (m *fakeMachine) MapsFile(hostPath string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoredGuest && !m.cowFallsBack && m.imageDir != "" && filepath.Join(m.imageDir, imageMemoryFile) == hostPath
}

func (m *fakeMachine) HasMount(path string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mounts[path]
}

func (m *fakeMachine) Kill(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.killDeadline, _ = ctx.Deadline()
	if m.killErr != nil {
		return m.killErr
	}
	m.events = append(m.events, "kill")
	if !m.dead {
		if !m.gone {
			m.exit = MachineExit{Signal: syscall.SIGKILL}
		}
		m.dead, m.gone = true, true
		close(m.exited)
		if !m.up && m.hypervisor != nil {
			m.up = true
			m.hypervisor.mu.Lock()
			m.hypervisor.booting--
			m.hypervisor.mu.Unlock()
		}
	}
	return nil
}

// fakeAgent is the guest side of a fakeMachine: files live in the fake
// volume the machine booted from.
type fakeAgent fakeMachine

func (a *fakeAgent) alive() error {
	m := (*fakeMachine)(a)
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.dead || m.gone:
		return errors.New("connection refused: vm is gone")
	case m.paused:
		return errors.New("vm is paused")
	}
	return nil
}

func (a *fakeAgent) Ping(ctx context.Context) (string, error) {
	if a.gate != nil {
		select {
		case <-a.gate:
		case <-a.exited:
			return "", errors.New("connection refused: vm is gone")
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if a.pingErr != nil {
		return "", a.pingErr
	}
	if err := a.alive(); err != nil {
		return "", err
	}
	m := (*fakeMachine)(a)
	m.mu.Lock()
	first := !m.up
	m.up = true
	m.mu.Unlock()
	if first && m.hypervisor != nil {
		m.hypervisor.mu.Lock()
		m.hypervisor.booting--
		m.hypervisor.mu.Unlock()
	}
	return "fake-agent", nil
}

func (a *fakeAgent) Connect(_ context.Context, port int) (net.Conn, error) {
	if err := a.alive(); err != nil {
		return nil, err
	}
	m := (*fakeMachine)(a)
	m.mu.Lock()
	connect := m.connectFunc
	m.mu.Unlock()
	if connect == nil {
		return nil, &guest.Error{Code: guest.CodeUnsupportedVersion, Message: "protocol version 2 is not supported; this agent speaks 1"}
	}
	return connect(port)
}

// Restored answers the "restored" handshake (guest protocol v3). The
// machine's restoredOp says what the guest did; nil is an agent built
// before version 3. Every call's entropy is kept, in order.
func (a *fakeAgent) Restored(_ context.Context, nowNs int64, entropy []byte) (guest.RestoredResult, error) {
	if err := a.alive(); err != nil {
		return guest.RestoredResult{}, err
	}
	m := (*fakeMachine)(a)
	m.mu.Lock()
	op := m.restoredOp
	a.entropySeen = append(a.entropySeen, bytes.Clone(entropy))
	m.mu.Unlock()
	if op == nil {
		return guest.RestoredResult{}, &guest.Error{Code: guest.CodeUnsupportedVersion, Message: "protocol version 3 is not supported; this agent speaks 1 to 2"}
	}
	return op(nowNs, entropy)
}

func (a *fakeAgent) Sync(context.Context) error {
	if a.syncErr != nil {
		return a.syncErr
	}
	if err := a.alive(); err != nil {
		return err
	}
	(*fakeMachine)(a).event("sync")
	return nil
}

func (a *fakeAgent) Exec(_ context.Context, cmd, cwd string, env map[string]string, timeout time.Duration, stdout, stderr io.Writer) (int, bool, error) {
	if err := a.alive(); err != nil {
		return -1, false, err
	}
	a.mu.Lock()
	setup := strings.HasPrefix(cmd, guestSetupMark)
	handshake := strings.HasPrefix(cmd, restoreClockMark) || strings.HasPrefix(cmd, restoreNetMark)
	switch {
	case setup:
		a.setups = append(a.setups, cmd)
	case handshake:
		a.handshake = append(a.handshake, cmd)
	default:
		a.execs = append(a.execs, maps.Clone(env))
	}
	execFunc, restoreHook := a.execFunc, a.restoreHook
	a.mu.Unlock()
	if setup && a.setupFunc != nil {
		return a.setupFunc(cmd, stderr)
	}
	if handshake && restoreHook != nil {
		return restoreHook(cmd, stdout, stderr)
	}
	if setup || handshake {
		if handshake {
			restoreHookAnswers(cmd, stdout)
		}
		return 0, false, nil
	}
	if execFunc != nil {
		return execFunc(cmd, cwd, env, timeout, stdout, stderr)
	}
	_, _ = io.WriteString(stdout, cwd+"$ "+cmd)
	return 0, false, nil
}

func (a *fakeAgent) WriteFile(_ context.Context, path string, data io.Reader) error {
	if err := a.alive(); err != nil {
		return err
	}
	body, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	a.zfs.mu.Lock()
	defer a.zfs.mu.Unlock()
	volume, ok := a.zfs.datasets[a.volume]
	if !ok {
		return fmt.Errorf("disk %s is gone", a.volume)
	}
	volume.files[path] = body
	return nil
}

func (a *fakeAgent) ReadFile(_ context.Context, path string) ([]byte, error) {
	if err := a.alive(); err != nil {
		return nil, err
	}
	a.zfs.mu.Lock()
	defer a.zfs.mu.Unlock()
	volume, ok := a.zfs.datasets[a.volume]
	if !ok {
		return nil, fmt.Errorf("disk %s is gone", a.volume)
	}
	data, ok := volume.files[path]
	if !ok {
		return nil, errors.New("guest agent: no such file")
	}
	return bytes.Clone(data), nil
}

// scriptedCommander answers commands from a table and records them.
type scriptedCommander struct {
	mu    sync.Mutex
	calls []string
	// answer is asked for every call; the default answers nothing.
	answer func(call string) ([]byte, error)
}

func (c *scriptedCommander) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	c.mu.Lock()
	c.calls = append(c.calls, call)
	answer := c.answer
	c.mu.Unlock()
	if answer == nil {
		return nil, nil
	}
	return answer(call)
}

func zfsError(stderr string) error {
	return &CommandError{Command: "zfs", Stderr: stderr, Err: errors.New("exit status 1")}
}

// liveRefs lists the snapshot references in the pool that are usable.
func (z *fakeZFS) liveRefs() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	var refs []string
	for name, snapshot := range z.snapshots {
		dataset := z.datasets[datasetOf(name)]
		if dataset != nil && dataset.props[propKind] == kindSnapshot && snapshot.props[propDead] == "" &&
			strings.HasSuffix(datasetOf(name), strings.SplitN(name, "@", 2)[1]) {
			refs = append(refs, name)
		}
	}
	sort.Strings(refs)
	return refs
}

// The memory images' half of the fake pool: filesystems that are each
// their own encryption root, as zfs has them.

func (z *fakeZFS) CreateFilesystem(_ context.Context, name string, props map[string]string, key []byte) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if err := z.record("createfs " + name); err != nil {
		return err
	}
	parent := name[:strings.LastIndex(name, "/")]
	if _, ok := z.datasets[parent]; !ok && parent != testPool && parent != "tank" {
		return fmt.Errorf("cannot create '%s': parent '%s' does not exist", name, parent)
	}
	if _, exists := z.datasets[name]; exists {
		return fmt.Errorf("cannot create '%s': dataset already exists", name)
	}
	if key != nil && len(key) != 32 {
		return errors.New("Raw key too short (expected 32)")
	}
	// As zfs does: created mounted at its mountpoint, which it makes.
	if props["mountpoint"] != "none" {
		if err := os.MkdirAll(props["mountpoint"], 0o755); err != nil {
			return err
		}
	}
	z.datasets[name] = &fakeDataset{
		props: maps.Clone(props), files: map[string][]byte{}, filesystem: true,
		fsKey: bytes.Clone(key), fsKeyLoaded: key != nil, fsMounted: props["mountpoint"] != "none",
	}
	return nil
}

func (z *fakeZFS) Mount(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.fsCalls = append(z.fsCalls, "mount "+name)
	dataset, ok := z.datasets[name]
	if !ok || !dataset.filesystem {
		return fmt.Errorf("cannot mount '%s': not a filesystem", name)
	}
	if dataset.fsMounted {
		return fmt.Errorf("cannot mount '%s': filesystem already mounted", name)
	}
	if dataset.fsKey != nil && !dataset.fsKeyLoaded {
		return fmt.Errorf("cannot mount '%s': encryption key not loaded", name)
	}
	dataset.fsMounted = true
	return nil
}

func (z *fakeZFS) Unmount(_ context.Context, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.fsCalls = append(z.fsCalls, "unmount "+name)
	dataset, ok := z.datasets[name]
	if !ok || !dataset.fsMounted {
		return fmt.Errorf("cannot unmount '%s': not currently mounted", name)
	}
	dataset.fsMounted = false
	return nil
}

func (z *fakeZFS) LoadKey(_ context.Context, name string, key []byte) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.fsCalls = append(z.fsCalls, "load-key "+name)
	dataset, ok := z.datasets[name]
	if !ok || dataset.fsKey == nil {
		return fmt.Errorf("cannot load key for '%s': not an encryption root", name)
	}
	if !bytes.Equal(dataset.fsKey, key) {
		return fmt.Errorf("Key load error: Incorrect key provided for '%s'", name)
	}
	if dataset.fsKeyLoaded {
		return fmt.Errorf("Key load error: Key already loaded for '%s'", name)
	}
	dataset.fsKeyLoaded = true
	return nil
}

func (z *fakeZFS) CheckKey(_ context.Context, name string, key []byte) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.fsCalls = append(z.fsCalls, "check-key "+name)
	dataset, ok := z.datasets[name]
	if !ok || dataset.fsKey == nil {
		return fmt.Errorf("Key load error: '%s' is not encrypted", name)
	}
	if !bytes.Equal(dataset.fsKey, key) {
		return fmt.Errorf("Key load error: Incorrect key provided for '%s'", name)
	}
	return nil
}

// restoreHookAnswers is what a guest that did the restore handshake
// says: its clock as it now reads, and that its kernel has the VM
// Generation ID device. Now is the time the script carries (it steps
// the clock to that); a test that wants another answer supplies its own
// hook.
func restoreHookAnswers(script string, stdout io.Writer) {
	if strings.HasPrefix(script, restoreClockMark) {
		if at := strings.Index(script, "date -u -s @"); at >= 0 {
			rest := script[at+len("date -u -s @"):]
			if end := strings.IndexAny(rest, " \n"); end > 0 {
				fmt.Fprintln(stdout, rest[:end])
			}
		}
		fmt.Fprintln(stdout, "vmgenid")
	}
}
