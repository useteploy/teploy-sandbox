package vm

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// These tests run the whole off-host path on fakes: two or more daemons,
// each a manager on the VM driver with its own fake pool and its own
// golden image, sharing one in-memory bucket.

// remoteHost is one daemon with remote storage.
type remoteHost struct {
	*testRig
	name     string
	stateDir string
	bucket   *offhosttest.Memory
	store    *offhost.Store
	service  *offhost.Service
}

type hostOption func(*offhost.Config, *run.Manager)

// newHost starts a daemon called name on bucket. With previous it is
// that daemon restarted: the same pool, state directory and identity,
// after the startup sweep.
func newHost(t *testing.T, bucket *offhosttest.Memory, name string, previous *remoteHost, options ...hostOption) *remoteHost {
	t.Helper()
	h := &remoteHost{name: name, bucket: bucket, stateDir: t.TempDir()}
	var rig *testRig
	if previous != nil {
		rig = newRig(t, previous.testRig)
		h.stateDir = previous.stateDir
	} else {
		rig = newRig(t, nil)
		// Its own golden image: no two hosts' have the same identity
		// unless one was copied from the other.
		rig.zfs.guidBase = 100000 * (1 + int(name[len(name)-1]))
		rig.zfs.snapshots[testGolden].guid = rig.zfs.newGUID()
	}
	h.testRig = rig
	keys, err := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	h.store = offhost.NewStore(bucket, "fleet", keys, quietLog())
	h.store.ChunkBytes = 96
	h.store.Parallel = 3
	if err := h.store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	config := offhost.Config{Daemon: name, MaxChain: 3}
	for _, option := range options {
		option(&config, rig.manager)
	}
	h.service = offhost.NewService(h.store, rig.driver.Transfer(), config, quietLog())
	rig.manager.OffHost = h.service
	if previous != nil {
		if _, _, err := rig.driver.Sweep(bg); err != nil {
			t.Fatalf("sweep: %v", err)
		}
	}
	if _, err := rig.manager.LoadState(bg, h.stateDir); err != nil {
		t.Fatalf("load state: %v", err)
	}
	return h
}

func (h *remoteHost) sync(t *testing.T) {
	t.Helper()
	if _, err := h.manager.SyncRemote(bg); err != nil {
		t.Fatalf("%s: sync: %v", h.name, err)
	}
}

// startRun creates a run with data in its disk.
func (h *remoteHost) startRun(t *testing.T, data []byte) *run.Run {
	t.Helper()
	created, err := h.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Env: map[string]string{"TOKEN": "t"}, Labels: map[string]string{"job": "a"}})
	if err != nil {
		t.Fatalf("%s: create: %v", h.name, err)
	}
	h.write(t, created.ID, data)
	return created
}

func (h *remoteHost) write(t *testing.T, id string, data []byte) {
	t.Helper()
	if err := h.manager.WriteFile(bg, id, run.LeaseCredential{}, "/work/data.bin", bytes.NewReader(data)); err != nil {
		t.Fatalf("%s: write: %v", h.name, err)
	}
}

func (h *remoteHost) read(t *testing.T, id string) []byte {
	t.Helper()
	data, err := h.manager.ReadFile(bg, id, "/work/data.bin")
	if err != nil {
		t.Fatalf("%s: read: %v", h.name, err)
	}
	return data
}

// stop stops a run and requires the stop to be durable.
func (h *remoteHost) stop(t *testing.T, id string) *run.Run {
	t.Helper()
	stopped, err := h.manager.Stop(bg, id)
	if err != nil {
		t.Fatalf("%s: stop: %v", h.name, err)
	}
	if stopped.Remote == nil || stopped.Remote.State != run.RemoteDurable {
		t.Fatalf("%s: stop is not durable: %+v", h.name, stopped.Remote)
	}
	return stopped
}

func (h *remoteHost) get(t *testing.T, id string) *run.Run {
	t.Helper()
	current, err := h.manager.Get(id)
	if err != nil {
		t.Fatalf("%s: run %s: %v", h.name, id, err)
	}
	return current
}

// staged lists what in the pool is still marked as a restore.
func (h *remoteHost) staged() []string {
	h.zfs.mu.Lock()
	defer h.zfs.mu.Unlock()
	var names []string
	for name, dataset := range h.zfs.datasets {
		if dataset.props[propKind] == kindRestore {
			names = append(names, name)
		}
	}
	return names
}

func payload(t *testing.T, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAStoppedRunResumesOnAnotherHost(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 700)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	if !stopped.Remote.Local || stopped.Remote.Generation != 1 || stopped.Remote.StoredBytes == 0 {
		t.Fatalf("remote after the first stop: %+v", stopped.Remote)
	}
	// Nothing in the bucket is readable without the key.
	for _, key := range bucket.Keys("") {
		if raw := bucket.Raw(key); bytes.Contains(raw, data[:24]) || bytes.Contains(raw, []byte("TOKEN")) {
			t.Fatalf("%s holds run data in the clear", key)
		}
	}

	// The other daemon learns of the run from the bucket alone.
	b.sync(t)
	seen := b.get(t, created.ID)
	if seen.State != run.StateStopped || seen.Remote == nil || seen.Remote.State != run.RemoteDurable || seen.Remote.Local {
		t.Fatalf("host-b sees %+v remote %+v", seen, seen.Remote)
	}
	if seen.Labels["job"] != "a" || seen.Image != GoldenImage {
		t.Fatalf("the adopted run lost its settings: %+v", seen)
	}
	resumed, err := b.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("resume on host-b: %v", err)
	}
	if resumed.State != run.StateRunning || !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("the run on host-b does not have the bytes it was stopped with")
	}
	if machine := b.hypervisor.machine(containerName(created.ID)); machine == nil {
		t.Fatal("no VM on host-b")
	}
	if left := b.staged(); len(left) != 0 {
		t.Fatalf("a finished restore left staged volumes: %v", left)
	}
	// host-b's golden image is another one, so it received host-a's.
	foundBase := false
	for _, name := range b.zfs.names() {
		foundBase = foundBase || strings.HasPrefix(name, testPool+"/"+baseVolumePrefix)
	}
	if !foundBase {
		t.Fatalf("host-b has no base image of host-a's: %v", b.zfs.names())
	}
	// It is in use, so asking for unused ones back leaves it.
	if err := b.driver.Transfer().Reclaim(bg); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.driver.Transfer().Stat(bg, "base-"+a.zfs.snapshots[testGolden].guid); !ok {
		t.Fatal("a base image a running run descends from was reclaimed")
	}

	// host-a learns that the run moved, and lets go of its copy.
	a.sync(t)
	if _, err := a.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("host-a still lists a run that runs on host-b: %v", err)
	}
	assertPool(t, a.zfs, pristine...)

	// A second stop, on host-b, is sent against the first; host-a can
	// take the run back, with what host-b wrote.
	changed := payload(t, 700)
	b.write(t, created.ID, changed)
	if again := b.stop(t, created.ID); !again.Remote.Incremental || again.Remote.Generation != 3 {
		t.Fatalf("second stop: %+v", again.Remote)
	}
	a.sync(t)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume back on host-a: %v", err)
	}
	if !bytes.Equal(a.read(t, created.ID), changed) {
		t.Fatal("host-a does not have what host-b wrote")
	}
	if left := a.staged(); len(left) != 0 {
		t.Fatalf("staged volumes left on host-a: %v", left)
	}
	if touched := a.zfs.callsTouching(testPool + "/golden"); len(touched) > 0 {
		t.Fatalf("the golden image was changed: %v", touched)
	}
	// host-b no longer has the run. The base image it received stays for
	// the next restore, until it is asked for back.
	b.sync(t)
	if _, ok, _ := b.driver.Transfer().Stat(bg, "base-"+a.zfs.snapshots[testGolden].guid); !ok {
		t.Fatal("a received base image went with the run")
	}
	if err := b.driver.Transfer().Reclaim(bg); err != nil {
		t.Fatal(err)
	}
	assertPool(t, b.zfs, pristine...)
}

func TestTheChainIsCapped(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil)
	created := a.startRun(t, payload(t, 300))
	var incremental []bool
	for cycle := 0; cycle < 6; cycle++ {
		stopped := a.stop(t, created.ID)
		incremental = append(incremental, stopped.Remote.Incremental)
		if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
			t.Fatal(err)
		}
		a.write(t, created.ID, payload(t, 300))
	}
	// MaxChain is 3: a stream against the base image, three against one
	// another, and again.
	if want := []bool{false, true, true, true, false, true}; !slices.Equal(incremental, want) {
		t.Fatalf("incremental uploads: %v, want %v", incremental, want)
	}
	// One snapshot held at a time on the host: the one the next upload
	// builds on. The rest went as each stop became durable.
	holders := 0
	for _, name := range a.zfs.names() {
		if strings.Contains(name, snapshotPrefix) && !strings.Contains(name, "@") {
			holders++
		}
	}
	if holders != 1 {
		t.Fatalf("%d snapshot holders on the host, want 1: %v", holders, a.zfs.names())
	}
	// And a host that has nothing restores the newest through its chain.
	final := payload(t, 300)
	a.write(t, created.ID, final)
	a.stop(t, created.ID)
	b := newHost(t, bucket, "host-b", nil)
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume through a chain: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), final) {
		t.Fatal("bytes after a chained restore differ")
	}
}

func TestADamagedRestoreLeavesNothing(t *testing.T) {
	snapshotKeys := func(bucket *offhosttest.Memory, base bool) []string {
		var keys []string
		for _, key := range bucket.Keys("fleet/v1/snap/") {
			if strings.Contains(key, "/snap/base-") == base && !strings.HasSuffix(key, "/manifest") {
				keys = append(keys, key)
			}
		}
		return keys
	}
	cases := map[string]func(t *testing.T, bucket *offhosttest.Memory){
		"a flipped bit in a chunk": func(t *testing.T, bucket *offhosttest.Memory) {
			key := snapshotKeys(bucket, false)[1]
			raw := bucket.Raw(key)
			raw[len(raw)-3] ^= 0x40
			bucket.SetRaw(key, raw)
		},
		"a truncated chunk": func(t *testing.T, bucket *offhosttest.Memory) {
			key := snapshotKeys(bucket, false)[0]
			bucket.SetRaw(key, bucket.Raw(key)[:20])
		},
		"a deleted chunk": func(t *testing.T, bucket *offhosttest.Memory) {
			keys := snapshotKeys(bucket, false)
			bucket.Remove(keys[len(keys)-1])
		},
		"two chunks swapped": func(t *testing.T, bucket *offhosttest.Memory) {
			keys := snapshotKeys(bucket, false)
			first, second := bucket.Raw(keys[0]), bucket.Raw(keys[1])
			bucket.SetRaw(keys[0], second)
			bucket.SetRaw(keys[1], first)
		},
		"a damaged chunk of the base image": func(t *testing.T, bucket *offhosttest.Memory) {
			key := snapshotKeys(bucket, true)[0]
			raw := bucket.Raw(key)
			raw[len(raw)/2] ^= 1
			bucket.SetRaw(key, raw)
		},
		"a deleted manifest": func(t *testing.T, bucket *offhosttest.Memory) {
			for _, key := range bucket.Keys("fleet/v1/snap/") {
				if strings.HasSuffix(key, "/manifest") && !strings.Contains(key, "base-") {
					bucket.Remove(key)
				}
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			bucket := offhosttest.NewMemory()
			a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
			data := payload(t, 900)
			created := a.startRun(t, data)
			a.stop(t, created.ID)
			b.sync(t)
			pristineBucket := map[string][]byte{}
			for _, key := range bucket.Keys("") {
				pristineBucket[key] = bucket.Raw(key)
			}
			damage(t, bucket)

			if _, err := b.manager.Resume(bg, created.ID, 0); err == nil {
				t.Fatal("a resume from damaged storage succeeded")
			}
			// Nothing half-received: the pool is as it was before.
			assertPool(t, b.zfs, pristine...)
			if running := b.hypervisor.running(); len(running) != 0 {
				t.Fatalf("a VM runs after a failed restore: %v", running)
			}
			// The run is still stopped, here and in the bucket, and the
			// claim the resume had made was given back.
			if current := b.get(t, created.ID); current.State != run.StateStopped {
				t.Fatalf("after a failed resume the run is %s", current.State)
			}
			record, _, err := b.store.Latest(bg, created.ID)
			if err != nil || record.State != offhost.RecordStopped {
				t.Fatalf("remote record after a failed resume: %+v, %v", record, err)
			}

			// With the storage whole again the same run resumes.
			for key, raw := range pristineBucket {
				if bucket.Raw(key) == nil {
					bucket.SetRaw(key, raw)
					continue
				}
				if !strings.Contains(key, "/run/") {
					bucket.SetRaw(key, raw)
				}
			}
			if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
				t.Fatalf("resume after the storage was repaired: %v", err)
			}
			if !bytes.Equal(b.read(t, created.ID), data) {
				t.Fatal("bytes differ after the repaired resume")
			}
		})
	}
}

func TestTwoDaemonsResumingOneRun(t *testing.T) {
	for round := 0; round < 8; round++ {
		bucket := offhosttest.NewMemory()
		a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
		created := a.startRun(t, payload(t, 200))
		a.stop(t, created.ID)
		b.sync(t)

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, h := range []*remoteHost{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = h.manager.Resume(bg, created.ID, 0)
			}()
		}
		wg.Wait()
		running := len(a.hypervisor.running()) + len(b.hypervisor.running())
		if running != 1 {
			t.Fatalf("round %d: %d copies of the run are running (%v, %v)", round, running, errs[0], errs[1])
		}
		won := 0
		for i, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, run.ErrRemoteConflict):
				t.Fatalf("round %d: daemon %d lost with %v, want a conflict", round, i, err)
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d daemons were told they resumed the run", round, won)
		}
		// The loser lets go once it looks; nothing of the run is left
		// on it.
		loser := a
		if errs[0] == nil {
			loser = b
		}
		loser.sync(t)
		if _, err := loser.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
			t.Fatalf("round %d: the loser still lists the run: %v", round, err)
		}
		assertPool(t, loser.zfs, pristine...)
	}
}

func TestAForkOfARunStoppedElsewhere(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 500)
	created := a.startRun(t, data)
	a.stop(t, created.ID)

	// host-b has never heard of the run: the fork looks it up.
	child, err := b.manager.Fork(bg, created.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork on host-b: %v", err)
	}
	if child.ForkedFrom != created.ID || !bytes.Equal(b.read(t, child.ID), data) {
		t.Fatal("the fork does not have its source's bytes")
	}
	// The source is still stopped, for anybody.
	if record, _, err := a.store.Latest(bg, created.ID); err != nil || record.State != offhost.RecordStopped {
		t.Fatalf("the source's record after a fork: %+v, %v", record, err)
	}
	// The child has a record that keeps the source's snapshot.
	record, _, err := b.store.Latest(bg, child.ID)
	if err != nil || record.State != offhost.RecordForked || record.Snapshot == "" {
		t.Fatalf("the child's record: %+v, %v", record, err)
	}

	// The source is destroyed and its objects collected: what the child
	// builds on stays, and the child's own stop is sent against it.
	if err := a.manager.Destroy(bg, created.ID); err != nil {
		t.Fatalf("destroy the source: %v", err)
	}
	if err := a.manager.CollectRemote(bg); err != nil {
		t.Fatal(err)
	}
	if has, _ := a.store.HasSnapshot(bg, record.Snapshot); !has {
		t.Fatal("the snapshot a fork builds on was collected with its source")
	}
	grown := append(bytes.Clone(data), payload(t, 100)...)
	b.write(t, child.ID, grown)
	if stopped := b.stop(t, child.ID); !stopped.Remote.Incremental {
		t.Fatalf("the fork's first stop was not sent against its source: %+v", stopped.Remote)
	}
	// A third host restores the child through the destroyed source's
	// snapshot.
	c := newHost(t, bucket, "host-c", nil)
	c.sync(t)
	if _, err := c.manager.Resume(bg, child.ID, 0); err != nil {
		t.Fatalf("resume of the fork on host-c: %v", err)
	}
	if !bytes.Equal(c.read(t, child.ID), grown) {
		t.Fatal("the fork's bytes differ on host-c")
	}

	// A fork that is destroyed without ever stopping leaves no record.
	second, err := c.manager.Fork(bg, child.ID, run.ForkRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.manager.Destroy(bg, second.ID); err != nil {
		t.Fatal(err)
	}
	if record, _, err := c.store.Latest(bg, second.ID); err == nil && record.State != offhost.RecordDestroyed {
		t.Fatalf("a destroyed fork's record: %+v", record)
	}
}

func TestDestroyedRunsAreCollected(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	keep := a.startRun(t, payload(t, 300))
	a.stop(t, keep.ID)
	gone := a.startRun(t, payload(t, 300))
	a.stop(t, gone.ID)
	b.sync(t)
	before := len(bucket.Keys("fleet/v1/snap/"))

	// Destroyed on the daemon that only knows it from the bucket.
	if err := b.manager.Destroy(bg, gone.ID); err != nil {
		t.Fatalf("destroy on host-b: %v", err)
	}
	if err := b.manager.CollectRemote(bg); err != nil {
		t.Fatal(err)
	}
	after := bucket.Keys("fleet/v1/snap/")
	if len(after) >= before {
		t.Fatalf("nothing was collected: %d objects before, %d after", before, len(after))
	}
	if left := bucket.Keys("fleet/v1/run/" + gone.ID); len(left) != 0 {
		t.Fatalf("the destroyed run's records were left: %v", left)
	}
	// host-a drops its copy when it looks, and the other run is whole.
	a.sync(t)
	if _, err := a.manager.Get(gone.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("host-a still lists a run destroyed on host-b: %v", err)
	}
	if _, err := b.manager.Resume(bg, keep.ID, 0); err != nil {
		t.Fatalf("the other run does not resume after a collection: %v", err)
	}

	// With every run gone the bucket ends empty: the base image too.
	if err := b.manager.Destroy(bg, keep.ID); err != nil {
		t.Fatal(err)
	}
	if err := b.manager.CollectRemote(bg); err != nil {
		t.Fatal(err)
	}
	if left := bucket.Keys(""); len(left) != 0 {
		t.Fatalf("left in the bucket with no run left: %v", left)
	}
}

func TestAStopThatCannotBeUploadedIsKeptAndRetried(t *testing.T) {
	cases := map[string]func(op, key string) error{
		"storage is down": func(op, key string) error { return errors.New("no route to host") },
		"chunks cannot be written": func(op, key string) error {
			if op == "put" && strings.Contains(key, "/snap/") && !strings.HasSuffix(key, "/manifest") {
				return errors.New("write refused")
			}
			return nil
		},
		"the manifest cannot be written": func(op, key string) error {
			if op == "put" && strings.HasSuffix(key, "/manifest") {
				return errors.New("write refused")
			}
			return nil
		},
		"the record cannot be written": func(op, key string) error {
			if op == "put" && strings.Contains(key, "/run/") {
				return errors.New("write refused")
			}
			return nil
		},
	}
	for name, failure := range cases {
		t.Run(name, func(t *testing.T) {
			bucket := offhosttest.NewMemory()
			a := newHost(t, bucket, "host-a", nil)
			data := payload(t, 400)
			created := a.startRun(t, data)
			bucket.SetFail(failure)
			stopped, err := a.manager.Stop(bg, created.ID)
			if err != nil {
				t.Fatalf("stop: %v", err)
			}
			// Stopped, said not to be durable, and the snapshot is here.
			if stopped.State != run.StateStopped || stopped.Remote == nil || stopped.Remote.State != run.RemoteFailed ||
				!stopped.Remote.Local || stopped.Remote.Error == "" {
				t.Fatalf("a stop that could not be uploaded: %+v remote %+v", stopped, stopped.Remote)
			}
			if records := bucket.Keys("fleet/v1/run/"); len(records) != 0 {
				t.Fatalf("a record was written for a stop that is not durable: %v", records)
			}
			// It resumes here regardless (nothing of it is remote yet).
			if name != "storage is down" {
				if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
					t.Fatalf("local resume of a stop that is not durable: %v", err)
				}
				if !bytes.Equal(a.read(t, created.ID), data) {
					t.Fatal("bytes differ")
				}
				if stopped, err = a.manager.Stop(bg, created.ID); err != nil || stopped.Remote.State != run.RemoteFailed {
					t.Fatalf("second stop: %+v %v", stopped, err)
				}
			}
			// The daemon restarts in between, and storage comes back. (A
			// daemon does not start at all while it cannot reach its
			// storage, so for that case it comes back first.)
			if name == "storage is down" {
				bucket.SetFail(nil)
			}
			a = newHost(t, bucket, "host-a", a)
			if current := a.get(t, created.ID); current.Remote == nil || current.Remote.State != run.RemoteFailed {
				t.Fatalf("after a restart: %+v", current.Remote)
			}
			bucket.SetFail(nil)
			a.manager.Maintain(bg)
			if current := a.get(t, created.ID); current.Remote.State != run.RemoteDurable || current.Remote.Error != "" {
				t.Fatalf("after storage came back: %+v", current.Remote)
			}
			b := newHost(t, bucket, "host-b", nil)
			b.sync(t)
			if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
				t.Fatalf("resume elsewhere: %v", err)
			}
			if !bytes.Equal(b.read(t, created.ID), data) {
				t.Fatal("bytes differ on the other host")
			}
		})
	}
}

func TestARunLostInARestartComesBackAtItsLastStop(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a := newHost(t, bucket, "host-a", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	a.write(t, created.ID, []byte("work since the stop, which the crash takes"))
	never := a.startRun(t, payload(t, 100))

	// The daemon dies and starts again: no VM survives.
	a = newHost(t, bucket, "host-a", a)
	a.sync(t)
	if _, err := a.manager.Get(never.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("a run that was never stopped came back: %v", err)
	}
	back := a.get(t, created.ID)
	if back.State != run.StateStopped || back.Remote == nil || !back.Remote.Local {
		t.Fatalf("the lost run came back as %+v remote %+v", back, back.Remote)
	}
	a.manager.Maintain(bg)
	if record, _, err := a.store.Latest(bg, created.ID); err != nil || record.State != offhost.RecordStopped {
		t.Fatalf("its record: %+v, %v", record, err)
	}
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume of the run that came back: %v", err)
	}
	if !bytes.Equal(a.read(t, created.ID), data) {
		t.Fatal("the run did not come back as it was at its last stop")
	}
	// Nothing leaked in the pool: the run's volume and the snapshot its
	// next upload builds on.
	for _, name := range a.zfs.names() {
		if strings.HasPrefix(name, testPool+"/"+runPrefix) && !strings.Contains(name, strings.ToLower(created.ID)) {
			t.Fatalf("a volume of another run is left: %s", name)
		}
	}
}

func TestTakeover(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	a.stop(t, created.ID)
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	a.write(t, created.ID, []byte("only on host-a"))

	// host-a holds the run. Another daemon is refused...
	if _, err := b.manager.Resume(bg, created.ID, 0); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("resume of a run held elsewhere = %v, want a conflict", err)
	}
	if len(b.hypervisor.running()) != 0 {
		t.Fatal("host-b booted a run host-a holds")
	}
	// ...unless it is told host-a is gone. It gets the last stop.
	taken, err := b.manager.ResumeWith(bg, created.ID, run.ResumeRequest{Takeover: true})
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if taken.State != run.StateRunning || !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("the run taken over is not the run as it was last stopped")
	}

	// host-a was not gone after all. Its copy can no longer become the
	// run: its stop is kept, said to be superseded, and cannot resume.
	stopped, err := a.manager.Stop(bg, created.ID)
	if err != nil {
		t.Fatalf("stop on the superseded host: %v", err)
	}
	if stopped.Remote == nil || stopped.Remote.State != run.RemoteSuperseded || !stopped.Remote.Local {
		t.Fatalf("superseded stop: %+v", stopped.Remote)
	}
	if record, _, err := b.store.Latest(bg, created.ID); err != nil || record.Owner != "host-b" || record.State != offhost.RecordRunning {
		t.Fatalf("the record after the old holder's stop: %+v, %v", record, err)
	}
	if _, err := a.manager.Resume(bg, created.ID, 0); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("resume of a superseded copy = %v, want a conflict", err)
	}
	// What only it had is not lost: it forks.
	rescued, err := a.manager.Fork(bg, created.ID, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork of a superseded copy: %v", err)
	}
	if string(a.read(t, rescued.ID)) != "only on host-a" {
		t.Fatal("the superseded copy's bytes are not in its fork")
	}
	// Deleting the superseded copy does not touch the run.
	if err := a.manager.Destroy(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	if record, _, err := b.store.Latest(bg, created.ID); err != nil || record.State != offhost.RecordRunning {
		t.Fatalf("the run's record after the superseded copy was deleted: %+v, %v", record, err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("the run on host-b was disturbed")
	}
}

func TestLocalCopiesAreDroppedWhenAskedOrUnderPressure(t *testing.T) {
	t.Run("drop", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		a := newHost(t, bucket, "host-a", nil, func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop })
		data := payload(t, 400)
		created := a.startRun(t, data)
		if stopped := a.stop(t, created.ID); stopped.Remote.Local {
			t.Fatalf("the local copy was kept: %+v", stopped.Remote)
		}
		assertPool(t, a.zfs, pristine...)
		if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
			t.Fatalf("resume from remote storage on the same host: %v", err)
		}
		if !bytes.Equal(a.read(t, created.ID), data) {
			t.Fatal("bytes differ")
		}
	})
	t.Run("a failed upload is never dropped", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		a := newHost(t, bucket, "host-a", nil, func(_ *offhost.Config, m *run.Manager) { m.LocalCache = run.LocalDrop })
		created := a.startRun(t, payload(t, 400))
		bucket.SetFail(func(op, key string) error {
			if op == "put" {
				return errors.New("write refused")
			}
			return nil
		})
		stopped, err := a.manager.Stop(bg, created.ID)
		if err != nil || stopped.Remote.State != run.RemoteFailed || !stopped.Remote.Local {
			t.Fatalf("stop: %+v %v", stopped.Remote, err)
		}
		if has, err := a.service.HasLocal(bg, a.zfs.liveRefs()[0]); err != nil || !has {
			t.Fatalf("the only copy of a stop that is not durable was dropped: %v", err)
		}
	})
	t.Run("pressure", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		a := newHost(t, bucket, "host-a", nil, func(c *offhost.Config, _ *run.Manager) { c.ReservePercent = 20 })
		a.zfs.available, a.zfs.used = 50, 50
		first, second := a.startRun(t, payload(t, 200)), a.startRun(t, payload(t, 200))
		a.stop(t, first.ID)
		a.stop(t, second.ID)
		a.manager.Maintain(bg)
		if !a.get(t, first.ID).Remote.Local || !a.get(t, second.ID).Remote.Local {
			t.Fatal("a local copy was dropped with space to spare")
		}
		a.zfs.mu.Lock()
		a.zfs.available, a.zfs.used = 10, 90
		a.zfs.mu.Unlock()
		a.manager.Maintain(bg)
		if a.get(t, first.ID).Remote.Local || a.get(t, second.ID).Remote.Local {
			t.Fatal("local copies were kept with the pool short of space")
		}
		assertPool(t, a.zfs, pristine...)
		if _, err := a.manager.Resume(bg, first.ID, 0); err != nil {
			t.Fatalf("resume after eviction: %v", err)
		}
	})
}

func TestRetentionReachesRemoteStorage(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 200))
	stopped := a.stop(t, created.ID)
	b.sync(t)
	// host-a is gone for good. host-b's reaper deletes the run when its
	// retention passes, in the bucket too.
	b.manager.SetClock(func() time.Time { return stopped.RetainUntil.Add(time.Minute) })
	if reaped := b.manager.Reap(bg); reaped != 1 {
		t.Fatalf("reaped %d runs, want 1", reaped)
	}
	record, _, err := b.store.Latest(bg, created.ID)
	if err != nil || record.State != offhost.RecordDestroyed {
		t.Fatalf("the record of a run past its retention: %+v, %v", record, err)
	}
}

func TestACallersSnapshotBootsOnAnotherHost(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	ref, remote, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || remote == nil || remote.State != run.RemoteDurable || remote.ID == "" {
		t.Fatalf("snapshot: %q %+v %v", ref, remote, err)
	}
	booted, err := b.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + remote.ID})
	if err != nil {
		t.Fatalf("create from a snapshot of another host: %v", err)
	}
	if !bytes.Equal(b.read(t, booted.ID), data) {
		t.Fatal("bytes differ")
	}
	if _, err := b.manager.Create(bg, run.CreateRequest{Image: "snapshot:../../etc"}); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("a snapshot image that is not an ID = %v", err)
	}
	// The run it was taken of is destroyed and collected: the snapshot is
	// the caller's and stays until the caller deletes it.
	if err := a.manager.Destroy(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.manager.CollectRemote(bg); err != nil {
		t.Fatal(err)
	}
	if has, _ := a.store.HasSnapshot(bg, remote.ID); !has {
		t.Fatal("a caller's snapshot was collected")
	}
	if err := a.manager.DeleteSnapshot(bg, ref); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if has, _ := a.store.HasSnapshot(bg, remote.ID); has {
		t.Fatal("a deleted snapshot is still in remote storage")
	}
	if has, _ := a.service.HasLocal(bg, ref); has {
		t.Fatal("a deleted snapshot is still on the host")
	}
}

// A snapshot fetched for a create is the run's to release: the registry
// would otherwise never name it, and nothing collects what the registry
// does not name.
func TestAFetchedSnapshotDoesNotOutliveItsRun(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 400)
	created := a.startRun(t, data)
	ref, remote, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || remote == nil || remote.ID == "" {
		t.Fatalf("snapshot: %q %+v %v", ref, remote, err)
	}
	snapshots := func(z *fakeZFS) []string {
		var out []string
		for _, name := range z.names() {
			// A volume, not the snapshot on it (names() lists both).
			if strings.Contains(name, snapshotPrefix) && !strings.Contains(name, "@") {
				out = append(out, name)
			}
		}
		return out
	}
	// A boot that fails gives back what the fetch materialized.
	b.zfs.blockClone = make(chan struct{})
	close(b.zfs.blockClone)
	if _, err := b.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + remote.ID}); err == nil {
		t.Fatal("a boot made to fail must fail")
	}
	if left := snapshots(b.zfs); len(left) != 0 {
		t.Fatalf("a snapshot fetched for a boot that failed stayed on the host: %v", left)
	}
	// A run that boots holds the copy for its lifetime, and no longer.
	booted, err := b.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + remote.ID})
	if err != nil {
		t.Fatal(err)
	}
	if left := snapshots(b.zfs); len(left) != 1 {
		t.Fatalf("the fetched copy is missing before its run ended: %v", left)
	}
	if err := b.manager.Destroy(bg, booted.ID); err != nil {
		t.Fatal(err)
	}
	if left := snapshots(b.zfs); len(left) != 0 {
		t.Fatalf("a snapshot fetched for a run outlived the run: %v", left)
	}
	if has, _ := a.store.HasSnapshot(bg, remote.ID); !has {
		t.Fatal("the caller's snapshot left remote storage")
	}
	if has, _ := a.service.HasLocal(bg, ref); !has {
		t.Fatal("the snapshot left the host that made it")
	}
}

// Runs stopped before remote storage was configured have no remote
// state at all. Once it is, they belong off the host like any other
// stopped run.
func TestRunsFromBeforeRemoteStorageAreUploaded(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 300)
	created := a.startRun(t, data)
	remote := a.manager.OffHost
	a.manager.OffHost = nil
	if _, err := a.manager.Stop(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	if view, _ := a.manager.Get(created.ID); view.Remote != nil {
		t.Fatalf("a stop without remote storage has remote state: %+v", view.Remote)
	}
	a.manager.OffHost = remote
	a.manager.Maintain(bg)
	view, _ := a.manager.Get(created.ID)
	if view.Remote == nil || view.Remote.State != run.RemoteDurable {
		t.Fatalf("a run stopped before remote storage was configured: %+v", view.Remote)
	}
	b.sync(t)
	resumed, err := b.manager.Resume(bg, created.ID, 0)
	if err != nil {
		t.Fatalf("resume on another host: %v", err)
	}
	if !bytes.Equal(b.read(t, resumed.ID), data) {
		t.Fatal("bytes differ")
	}
}

// A resume that claimed a run and then failed to boot it gives the run
// back. The caller that gave up on the resume is gone; publishing the
// run's stop must not go with it.
func TestAGivenBackRunIsPublishedAfterItsCallerIsGone(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	b.sync(t)

	block := make(chan struct{})
	b.zfs.blockClone = block
	ctx, cancel := context.WithCancel(bg)
	done := make(chan error, 1)
	go func() {
		_, err := b.manager.ResumeWith(ctx, created.ID, run.ResumeRequest{Takeover: true})
		done <- err
	}()
	for i := 0; ; i++ {
		if len(bucket.Keys("fleet/v1/run/"+created.ID)) >= 2 {
			break // the takeover's claim is written
		}
		if i > 1000 {
			t.Fatal("the takeover never claimed the run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	close(block)
	if err := <-done; err == nil {
		t.Fatal("a resume whose boot was cut off must fail")
	}
	for i := 0; ; i++ {
		view, _ := b.manager.Get(created.ID)
		if view.Remote != nil && view.Remote.State == run.RemoteDurable {
			return // published under its own deadline, caller or not
		}
		if i > 1000 {
			t.Fatalf("the given-back run was not published: %+v", view.Remote)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWithoutConditionalWritesOnlyTheWriterResumes(t *testing.T) {
	bucket := offhosttest.NewMemory()
	bucket.Unconditional = true
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	data := payload(t, 300)
	created := a.startRun(t, data)
	a.stop(t, created.ID)
	b.sync(t)
	if _, err := b.manager.Resume(bg, created.ID, 0); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("resume of another daemon's run without conditional writes = %v, want a conflict", err)
	}
	if len(b.hypervisor.running()) != 0 {
		t.Fatal("a VM was booted")
	}
	// Reading is safe: a fork works, and so does the writer's own resume.
	child, err := b.manager.Fork(bg, created.ID, run.ForkRequest{})
	if err != nil || !bytes.Equal(b.read(t, child.ID), data) {
		t.Fatalf("fork without conditional writes: %v", err)
	}
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("the writer's own resume: %v", err)
	}
	a.stop(t, created.ID)
	// A daemon told that something else serialises may.
	c := newHost(t, bucket, "host-c", nil, func(config *offhost.Config, _ *run.Manager) { config.Unfenced = true })
	c.sync(t)
	if _, err := c.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume with unfenced set: %v", err)
	}
}

func TestAnInterruptedRestoreIsSweptAtStart(t *testing.T) {
	bucket := offhosttest.NewMemory()
	a, b := newHost(t, bucket, "host-a", nil), newHost(t, bucket, "host-b", nil)
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)
	b.sync(t)
	// The daemon dies after the streams were received and before the
	// restore was committed.
	b.zfs.mu.Lock()
	guid := a.zfs.snapshots[testGolden].guid
	b.zfs.fail["set "+propKind+"="+kindBase+" "+testPool+"/"+baseVolumePrefix+guid] = errors.New("the daemon was killed here")
	b.zfs.mu.Unlock()
	if _, err := b.manager.Resume(bg, created.ID, 0); err == nil {
		t.Fatal("a restore that could not commit succeeded")
	}
	// Discard already removed it; put a staged volume back to stand for
	// a daemon that never got that far.
	b.zfs.mu.Lock()
	b.zfs.datasets[testPool+"/"+snapshotPrefix+refID(9)] = &fakeDataset{props: map[string]string{propOwner: testOwner, propKind: kindRestore}, files: map[string][]byte{}}
	b.zfs.snapshots[testPool+"/"+snapshotPrefix+refID(9)+"@"+refID(9)] = &fakeSnapshot{txg: b.zfs.tick(), guid: "1", props: map[string]string{}, files: map[string][]byte{}}
	b.zfs.mu.Unlock()
	b = newHost(t, bucket, "host-b", b)
	assertPool(t, b.zfs, pristine...)
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume after the restart: %v", err)
	}
}
