package vm

// Key custody K2, the driver's side: a base image is a dataset positively
// marked as one or it is nothing; and a snapshot's stream hash is its own
// property, never one inherited.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// clonedFrom makes this daemon's run volume name a clone of the snapshot
// origin, as a driver that cloned it would have, and captures reference
// n of it.
func clonedFrom(t *testing.T, z *fakeZFS, v *Volumes, name, origin string, n int) string {
	t.Helper()
	volume := testPool + "/" + name
	z.mu.Lock()
	z.datasets[volume] = &fakeDataset{origin: origin, props: map[string]string{propOwner: testOwner, propKind: kindRun}, files: map[string][]byte{}}
	z.mu.Unlock()
	return mustCapture(t, v, name, n)
}

// unmarked is a dataset on the pool that is nobody's, with one snapshot.
func unmarked(z *fakeZFS, name, kind string) string {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.datasets[name] = &fakeDataset{props: map[string]string{propKind: kind}, files: map[string][]byte{}}
	snapshot := name + "@v1"
	z.snapshots[snapshot] = &fakeSnapshot{txg: z.tick(), guid: z.newGUID(), props: map[string]string{}, files: map[string][]byte{}}
	return snapshot
}

// BaseOf answers a base image's ID for a snapshot that descends from the
// configured golden image, or from a base image this daemon received and
// committed — and for nothing else. Before, the first origin walking back
// that was not this daemon's was taken for a base image and could be
// uploaded as one, under a "base-" ID, for the whole fleet to boot from.
func TestBaseOfAllowsOnlyAPositivelyMarkedBase(t *testing.T) {
	t.Run("the configured golden image", func(t *testing.T) {
		z := newFakeZFS()
		v := newTestVolumes(z)
		clonedFrom(t, z, v, runName(1), testGolden, 1)
		base, err := (&Transfer{volumes: v}).BaseOf(bg, refID(1))
		if err != nil || base != baseIDPrefix+z.snapshots[testGolden].guid {
			t.Fatalf("BaseOf of a snapshot of the golden image: %q, %v", base, err)
		}
	})
	t.Run("a base image received and committed here", func(t *testing.T) {
		z := newFakeZFS()
		v := newTestVolumes(z)
		// What a restore's Commit leaves: the received volume marked as
		// a base by this daemon, with the stream's snapshot on it.
		received := testPool + "/" + baseVolumePrefix + "123456789"
		z.mu.Lock()
		z.datasets[received] = &fakeDataset{props: map[string]string{propOwner: testOwner, propKind: kindBase}, files: map[string][]byte{}}
		z.snapshots[received+"@base"] = &fakeSnapshot{txg: z.tick(), guid: "123456789", props: map[string]string{}, files: map[string][]byte{}}
		z.mu.Unlock()
		// A run created from it, two snapshots deep.
		clonedFrom(t, z, v, runName(1), received+"@base", 1)
		// The run volume becomes a clone of the reference's snapshot, as
		// a capture leaves it; a second reference descends from the first.
		volume := testPool + "/" + runName(1)
		z.mu.Lock()
		z.datasets[volume].origin = testPool + "/" + snapshotPrefix + refID(1) + "@" + refID(1)
		z.mu.Unlock()
		clonedFrom(t, z, v, runName(2), testPool+"/"+snapshotPrefix+refID(1)+"@"+refID(1), 2)
		for _, id := range []string{refID(1), refID(2)} {
			if base, err := (&Transfer{volumes: v}).BaseOf(bg, id); err != nil || base != baseIDPrefix+"123456789" {
				t.Fatalf("BaseOf of %s: %q, %v", id, base, err)
			}
		}
		// And the received base is found again by its ID.
		if _, ok, err := (&Transfer{volumes: v}).Stat(bg, baseIDPrefix+"123456789"); err != nil || !ok {
			t.Fatalf("Stat of the received base by its ID: %t, %v", ok, err)
		}
	})
	for name, origin := range map[string]func(z *fakeZFS) string{
		"a dataset nobody marked": func(z *fakeZFS) string { return unmarked(z, "tank/elsewhere", "") },
		"another daemon's base image": func(z *fakeZFS) string {
			z.mu.Lock()
			defer z.mu.Unlock()
			name := testPool + "/" + baseVolumePrefix + "987654321"
			z.datasets[name] = &fakeDataset{props: map[string]string{propOwner: "another-daemon", propKind: kindBase}, files: map[string][]byte{}}
			z.snapshots[name+"@base"] = &fakeSnapshot{txg: z.tick(), guid: "987654321", props: map[string]string{}, files: map[string][]byte{}}
			return name + "@base"
		},
		"a golden image no longer configured": func(z *fakeZFS) string { return unmarked(z, testPool+"/golden-old", "") },
		"this daemon's, and not a base": func(z *fakeZFS) string {
			return unmarked(z, testPool+"/"+baseVolumePrefix+"555555555", kindRestore)
		},
	} {
		t.Run(name, func(t *testing.T) {
			z := newFakeZFS()
			v := newTestVolumes(z)
			ref := clonedFrom(t, z, v, runName(1), origin(z), 1)
			tr := &Transfer{volumes: v}
			if base, err := tr.BaseOf(bg, refID(1)); err == nil || base != "" || !strings.Contains(err.Error(), "not a base image of this daemon") {
				t.Fatalf("BaseOf over a dataset that is not a marked base: %q, %v; want an error", base, err)
			}
			v.basesMu.Lock()
			bases := len(v.bases)
			v.basesMu.Unlock()
			if bases != 0 {
				t.Fatalf("%d base images are remembered from a dataset nobody marked", bases)
			}
			// So nothing of it is ever uploaded as a base image: an
			// upload of the snapshot is refused before a byte is sent.
			bucket := offhosttest.NewMemory()
			keys, err := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
			if err != nil {
				t.Fatal(err)
			}
			store := offhost.NewStore(bucket, "fleet", keys, quietLog())
			if err := store.Probe(bg); err != nil {
				t.Fatal(err)
			}
			service := offhost.NewService(store, tr, offhost.Config{Daemon: "a"}, quietLog())
			if _, err := service.Upload(bg, run.UploadRequest{Run: "01HZZZZZZZZZZZZZZZZZZZZZZA", Ref: ref, Purpose: run.PurposeStop}); err == nil || !strings.Contains(err.Error(), "not a base image of this daemon") {
				t.Fatalf("an upload of a snapshot of a dataset nobody marked: %v; want it refused", err)
			}
			if left := bucket.Keys(""); len(left) != 0 {
				t.Fatalf("the refused upload stored %v", left)
			}
			for _, id := range z.liveRefs() {
				if id != ref {
					t.Fatalf("another reference %s exists", id)
				}
			}
		})
	}
}

// LocalProperty answers only what is set on the name itself. ZFS lets a
// snapshot inherit its dataset's user properties, which is right for the
// driver's marks and wrong for a per-snapshot fact: a parent's value is
// never taken for its snapshot's.
func TestLocalPropertyIsOnlyWhatIsSetOnTheNameItself(t *testing.T) {
	if propStreamSHA256 != "teploy:stream-sha256" {
		t.Fatalf("the property is %q", propStreamSHA256)
	}
	for name, c := range map[string]struct {
		out     string
		want    string
		wantErr bool
	}{
		"set there":                   {"abcd1234\tlocal\n", "abcd1234", false},
		"inherited from the dataset":  {"abcd1234\tinherited from tank/sbx/x\n", "", false},
		"not set":                     {"-\t-\n", "", false},
		"a native property's default": {"on\tdefault\n", "", false},
		"received with a stream":      {"abcd1234\treceived\n", "", false},
		"two names answered":          {"a\tlocal\nb\tlocal\n", "", true},
		"one column":                  {"abcd1234\n", "", true},
		"nothing":                     {"", "", true},
	} {
		t.Run(name, func(t *testing.T) {
			commander := &scriptedCommander{answer: func(string) ([]byte, error) { return []byte(c.out), nil }}
			z := newZFSCLI("zfs", commander)
			got, err := z.LocalProperty(bg, "tank/sbx/x@s", propStreamSHA256)
			if (err != nil) != c.wantErr || got != c.want {
				t.Fatalf("LocalProperty = %q, %v; want %q, error %t", got, err, c.want, c.wantErr)
			}
			if len(commander.calls) != 1 || commander.calls[0] != "zfs get -H -p -o value,source "+propStreamSHA256+" tank/sbx/x@s" {
				t.Fatalf("the commands run: %v", commander.calls)
			}
		})
	}
	commander := &scriptedCommander{answer: func(string) ([]byte, error) {
		return nil, errors.New("cannot open 'tank/sbx/x@s': dataset does not exist")
	}}
	if _, err := newZFSCLI("zfs", commander).LocalProperty(bg, "tank/sbx/x@s", propStreamSHA256); err == nil {
		t.Fatal("a name that is nothing was not an error")
	}
	// The fake keeps the rule too: what a dataset says is not its
	// snapshot's, and what the pool says is not a dataset's.
	z := newFakeZFS()
	v := newTestVolumes(z)
	mustCreate(t, v, runName(1), "")
	ref := mustCapture(t, v, runName(1), 1)
	holder := testPool + "/" + snapshotPrefix + refID(1)
	must(t, z.SetProperty(bg, holder, propStreamSHA256, "on the holder"))
	z.mu.Lock()
	z.poolProps[propStreamSHA256] = "on the pool"
	z.mu.Unlock()
	for name, want := range map[string]string{ref: "", holder: "on the holder", testPool + "/" + runName(1): ""} {
		if got, err := z.LocalProperty(bg, name, propStreamSHA256); err != nil || got != want {
			t.Errorf("the fake's LocalProperty(%s) = %q, %v; want %q", name, got, err, want)
		}
	}
	if _, err := z.LocalProperty(bg, "tank/nothing", propStreamSHA256); err == nil {
		t.Error("the fake answered for a name that is nothing")
	}
}

// A snapshot's stream hash is recorded on the snapshot itself — never on
// its holder, never on the pool, never on the golden image — and is read
// back only from a live copy or one a restore received and has not
// committed.
func TestAStreamsHashIsRecordedOnTheSnapshotAndNowhereElse(t *testing.T) {
	z := newFakeZFS()
	v := newTestVolumes(z)
	tr := &Transfer{volumes: v}
	mustCreate(t, v, runName(1), "")
	ref := mustCapture(t, v, runName(1), 1)
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got, err := tr.StreamHash(bg, refID(1)); err != nil || got != "" {
		t.Fatalf("a copy nothing was recorded for says its stream is %q (%v)", got, err)
	}
	must(t, tr.SetStreamHash(bg, refID(1), hash))
	z.mu.Lock()
	onSnapshot := z.snapshots[ref].props[propStreamSHA256]
	onHolder := z.datasets[testPool+"/"+snapshotPrefix+refID(1)].props[propStreamSHA256]
	z.mu.Unlock()
	if onSnapshot != hash || onHolder != "" || z.poolProps[propStreamSHA256] != "" {
		t.Fatalf("the hash is on the snapshot (%q), the holder (%q) and the pool (%q); want the snapshot alone", onSnapshot, onHolder, z.poolProps[propStreamSHA256])
	}
	if got, err := tr.StreamHash(bg, refID(1)); err != nil || got != hash {
		t.Fatalf("StreamHash after it was recorded: %q, %v", got, err)
	}
	// Another snapshot, of another run, inherits nothing.
	mustCreate(t, v, runName(2), "")
	ref2 := mustCapture(t, v, runName(2), 2)
	if got, err := tr.StreamHash(bg, refID(2)); err != nil || got != "" {
		t.Fatalf("another snapshot says its stream is %q", got)
	}
	if ref2 != testPool+"/"+snapshotPrefix+refID(2)+"@"+refID(2) {
		t.Fatalf("the fixture's second reference is %q", ref2)
	}
	// What is not a SHA-256 as written is refused, and sets nothing.
	for name, bad := range map[string]string{"not hex": "not-a-hash", "short": hash[:63], "upper case": strings.ToUpper(hash)} {
		if err := tr.SetStreamHash(bg, refID(2), bad); err == nil {
			t.Errorf("%s was recorded", name)
		}
	}
	// The golden image is read and cloned, never marked, even when a
	// host's copy of a base image is the golden one.
	golden := baseIDPrefix + z.snapshots[testGolden].guid
	if _, ok, _ := tr.Stat(bg, golden); !ok {
		t.Fatal("the fixture: the golden image is not found by its ID")
	}
	if err := tr.SetStreamHash(bg, golden, hash); err == nil {
		t.Fatal("the golden image was marked")
	}
	if got, err := tr.StreamHash(bg, golden); err != nil || got != "" {
		t.Fatalf("the golden image says its stream is %q (%v)", got, err)
	}
	if touched := z.callsTouching(testPool + "/golden"); len(touched) > 0 {
		t.Fatalf("the golden image was changed: %v", touched)
	}
	// A snapshot this host does not have: nothing to say, nothing to mark.
	if got, err := tr.StreamHash(bg, refID(9)); err != nil || got != "" {
		t.Fatalf("a snapshot that is not here says its stream is %q (%v)", got, err)
	}
	if err := tr.SetStreamHash(bg, refID(9), hash); err == nil {
		t.Fatal("a snapshot that is not here was marked")
	}
	// A copy a restore received and has not committed counts as here for
	// the record, and is not a live copy.
	const stagedID = "00000000000000000000000007"
	staged := testPool + "/" + snapshotPrefix + stagedID
	z.mu.Lock()
	z.datasets[staged] = &fakeDataset{props: map[string]string{propOwner: testOwner, propKind: kindRestore}, files: map[string][]byte{}}
	z.snapshots[staged+"@"+stagedID] = &fakeSnapshot{txg: z.tick(), guid: z.newGUID(), props: map[string]string{}, files: map[string][]byte{}}
	z.mu.Unlock()
	must(t, tr.SetStreamHash(bg, stagedID, hash))
	if got, err := tr.StreamHash(bg, stagedID); err != nil || got != "" {
		t.Fatalf("a copy a restore has not committed is a live one: %q (%v)", got, err)
	}
	// A reference deleted is no copy: nothing to read, nothing to mark.
	if _, ok, _ := tr.Stat(bg, refID(1)); !ok {
		t.Fatal("the fixture: the reference is not here")
	}
	must(t, v.RemoveSnapshot(bg, ref))
	if got, err := tr.StreamHash(bg, refID(1)); err != nil || got != "" {
		t.Fatalf("a deleted reference still says its stream is %q (%v)", got, err)
	}
	if err := tr.SetStreamHash(bg, refID(1), hash); err == nil {
		t.Fatal("a deleted reference was marked")
	}
}

// Key custody through the manager, on a fleet that is its own KMS (local
// mode): a run stops on one daemon under a hold key that daemon minted,
// is adopted, restored, sent against incrementally and taken back on
// another, is rotated, destroyed and collected — as it was without key
// custody, with every envelope a v2 one.
func TestARunMovesBetweenHostsUnderHoldKeys(t *testing.T) {
	bucket := offhosttest.NewMemory()
	root := bytes.Repeat([]byte{0x5a}, offhost.KeySize)
	custody := func(store *offhost.Store) {
		source, err := offhost.NewLocalKeySource(root)
		if err != nil {
			t.Fatal(err)
		}
		store.SetKeySource(source)
	}
	a := newHostPrepared(t, bucket, bucket, "host-a", nil, nil, custody)
	if a.service.Pushed() {
		t.Fatal("a local key source is pushed mode")
	}
	data := payload(t, 700)
	created := a.startRun(t, data)
	stopped := a.stop(t, created.ID)
	if stopped.Remote == nil || stopped.Remote.State != run.RemoteDurable || stopped.Remote.Generation != 1 || stopped.Remote.Snapshot == "" {
		t.Fatalf("remote after the first stop: %+v", stopped.Remote)
	}
	record, err := a.service.Latest(bg, created.ID)
	if err != nil || record.Tenant != offhost.DefaultTenant || !offhost.ValidKID(record.KID) || !strings.HasPrefix(record.Key, "t2."+offhost.DefaultTenant+".1.") {
		t.Fatalf("the run's record: %+v, %v", record, err)
	}
	// Every envelope of the run in the bucket is a v2 one, sealed so that
	// nothing of the run is in the clear; the base image's is a v1 one.
	versions := map[string]int{}
	for _, key := range bucket.Keys("") {
		if strings.HasSuffix(key, "/manifest") || strings.Contains(key, "/run/") {
			version, err := offhost.InspectEnvelopeVersion(bucket.Raw(key))
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			versions[key] = version
			if strings.Contains(key, "/run/") || !strings.Contains(key, "/snap/base-") {
				if version != 2 {
					t.Errorf("%s is a v%d envelope; want v2", key, version)
				}
			} else if version != 1 {
				t.Errorf("the base image's manifest is a v%d envelope; base images stay in v1", version)
			}
			if raw := bucket.Raw(key); bytes.Contains(raw, data[:24]) || bytes.Contains(raw, []byte("TOKEN")) {
				t.Errorf("%s holds run data in the clear", key)
			}
		}
	}
	if len(versions) != 3 {
		t.Fatalf("the bucket holds %d envelopes; want the base's manifest, the snapshot's and the record's", len(versions))
	}
	if listed, err := a.service.ListSnapshots(bg); err != nil || len(listed) != 0 {
		t.Fatalf("the listing: %+v, %v", listed, err)
	}

	// The other daemon learns of the run from the bucket alone, with a
	// hold key of its own minting, and resumes it: the chain is checked
	// as it restores (tenant, pins, the base's stream).
	b := newHostPrepared(t, bucket, bucket, "host-b", nil, nil, custody)
	b.sync(t)
	seen := b.get(t, created.ID)
	if seen.Remote == nil || seen.Remote.State != run.RemoteDurable || seen.Remote.Local {
		t.Fatalf("host-b sees %+v remote %+v", seen, seen.Remote)
	}
	if _, err := b.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("resume on host-b: %v", err)
	}
	if !bytes.Equal(b.read(t, created.ID), data) {
		t.Fatal("the run on host-b does not have the bytes it was stopped with")
	}
	// What it restored says what its streams are, recorded before the
	// commit, on the snapshots themselves.
	for _, id := range []string{a.remoteID(t, created.ID), "base-" + a.zfs.snapshots[testGolden].guid} {
		if hash, err := b.driver.Transfer().StreamHash(bg, id); err != nil || hash == "" {
			t.Fatalf("host-b's copy of %s does not say what its stream is: %q, %v", id, hash, err)
		}
	}
	// A second stop, on host-b, is sent against the first, which host-b
	// restored and checked: the copy says what its stream is. (A hold
	// key is minted where the run is created, resumed or forked; that is
	// the daemon API's to ask for, and this daemon was not asked.)
	changed := payload(t, 700)
	b.write(t, created.ID, changed)
	if again := b.stop(t, created.ID); !again.Remote.Incremental || again.Remote.Generation != 3 {
		t.Fatalf("second stop: %+v", again.Remote)
	}
	if again, err := b.service.Latest(bg, created.ID); err != nil || !offhost.ValidKID(again.KID) || again.Tenant != offhost.DefaultTenant || again.Generation != 3 {
		t.Fatalf("the record after the second stop: %+v, %v", again, err)
	}
	// host-a learns that the run moved on without it, and takes it
	// back with what host-b wrote, through the chain: its own first stop,
	// then host-b's.
	a.sync(t)
	back := a.get(t, created.ID)
	if back.Remote == nil || back.Remote.State != run.RemoteDurable || back.Remote.Local || back.Remote.Generation != 3 {
		t.Fatalf("host-a's view after the run stopped on host-b: %+v", back.Remote)
	}
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatalf("take the run back on host-a: %v", err)
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
	// A caller's snapshot boots on a third daemon.
	ref, remote, err := a.manager.SnapshotRemote(bg, created.ID)
	if err != nil || remote == nil || remote.State != run.RemoteDurable {
		t.Fatalf("snapshot: %+v %v", remote, err)
	}
	_ = ref
	c := newHostPrepared(t, bucket, bucket, "host-c", nil, nil, custody)
	booted, err := c.manager.Create(bg, run.CreateRequest{Image: "snapshot:" + remote.ID})
	if err != nil {
		t.Fatalf("create from a snapshot of another host: %v", err)
	}
	if !bytes.Equal(c.read(t, booted.ID), changed) {
		t.Fatal("bytes differ")
	}
	// The fleet key's rotation and the daemon's own keys, as the manager
	// runs them.
	if stats, err := a.manager.RotateRemote(bg); err != nil || stats.LocalKeysFailed != 0 || stats.Records != 0 || stats.Manifests != 0 {
		t.Fatalf("rotate: %+v, %v", stats, err)
	}
	// Destroyed and collected: nothing of the run is left.
	if err := c.manager.Destroy(bg, booted.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.manager.DeleteSnapshot(bg, ref); err != nil {
		t.Fatal(err)
	}
	if err := a.manager.Destroy(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	for _, h := range []*remoteHost{a, b, c} {
		h.sync(t)
		if err := h.manager.CollectRemote(bg); err != nil {
			t.Fatal(err)
		}
	}
	if left := chunksOf(bucket); len(left) != 0 {
		t.Fatalf("left in the bucket with no run left: %v", left)
	}
}

// remoteID is the run's stop snapshot's name in remote storage.
func (h *remoteHost) remoteID(t *testing.T, id string) string {
	t.Helper()
	current, err := h.manager.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if current.Remote == nil || current.Remote.Snapshot == "" {
		t.Fatalf("the run's view names no remote snapshot: %+v", current.Remote)
	}
	return current.Remote.Snapshot
}

// chunksOf lists the chunk objects in the bucket.
func chunksOf(bucket *offhosttest.Memory) []string {
	var out []string
	for _, key := range bucket.Keys("fleet/v1/snap/") {
		if !strings.HasSuffix(key, "/manifest") && !strings.Contains(key, "/pin/") && !strings.HasSuffix(key, "/condemned") {
			out = append(out, key)
		}
	}
	return out
}

// A daemon in pushed mode adopts no run it does not know: it cannot open
// the record's payload, and a run arrives when Cloud resumes it there.
// What the fleet's stopped runs are is still known, from their records'
// public sections alone, with no tenant key at all — which is what
// capacity counts. And a run it knows whose record moved on under a hold
// key it was not given is reconciled as far as the public section goes:
// the sync does not fail for the key it lacks.
func TestAPushedHostAdoptsNoRunItDoesNotKnowAndCountsItStopped(t *testing.T) {
	bucket := offhosttest.NewMemory()
	root := bytes.Repeat([]byte{0x5a}, offhost.KeySize)
	// The daemon that stopped the run: a fleet that is its own KMS, so
	// it mints hold keys.
	var own *offhost.LocalKeySource
	local := func(store *offhost.Store) {
		source, err := offhost.NewLocalKeySource(root)
		if err != nil {
			t.Fatal(err)
		}
		own = source
		store.SetKeySource(source)
	}
	a := newHostPrepared(t, bucket, bucket, "host-a", nil, nil, local)
	created := a.startRun(t, payload(t, 300))
	a.stop(t, created.ID)

	pushed := offhost.NewPushedKeySource()
	b := newHostPrepared(t, bucket, bucket, "host-b", nil, nil, func(store *offhost.Store) {
		store.SetKeySource(pushed)
		store.SetPushed(true)
	})
	if !b.manager.OffHost.Pushed() {
		t.Fatal("host-b is not in pushed mode")
	}
	b.sync(t)
	if _, err := b.manager.Get(created.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("host-b adopted a run it does not know: %v", err)
	}
	capacity := b.manager.Capacity()
	if capacity.StoppedRemote != 1 || capacity.Stopped != 0 || capacity.Running != 0 {
		t.Fatalf("capacity with a stopped run remote storage has and this host does not know: %+v", capacity)
	}
	// Looked at once, it is not looked at again until it changes, and
	// the count keeps.
	b.sync(t)
	if capacity = b.manager.Capacity(); capacity.StoppedRemote != 1 {
		t.Fatalf("capacity after a second sync: %+v", capacity)
	}
	record, err := b.service.LatestPublic(bg, created.ID)
	if err != nil || record.State != run.RecordStopped || record.Tenant != offhost.DefaultTenant || record.KID == "" || record.Payload != nil {
		t.Fatalf("the record's public section on a host with no key: %+v, %v", record, err)
	}
	if _, err := b.service.Latest(bg, created.ID); !errors.Is(err, run.ErrRemoteNeedKey) {
		t.Fatalf("Latest on a host with no key: %v", err)
	}
	// Resumed on host-a, it is not a stopped run any more, and that is
	// known here from the public section alone.
	if _, err := a.manager.Resume(bg, created.ID, 0); err != nil {
		t.Fatal(err)
	}
	b.sync(t)
	if capacity = b.manager.Capacity(); capacity.StoppedRemote != 0 {
		t.Fatalf("capacity after the run was resumed elsewhere: %+v", capacity)
	}

	// A run host-b knows — it could read the record when it took the run
	// in — whose record then moves on under a hold key it holds no longer
	// (pushed mode now, nothing pushed). The sync goes by the record's
	// public section all the same: it does not fail for the key it lacks,
	// it reads no payload, and what the public section says is done.
	second := a.startRun(t, payload(t, 200))
	a.stop(t, second.ID)
	b.store.SetKeySource(own)
	b.store.SetPushed(false)
	b.sync(t)
	if seen := b.get(t, second.ID); seen.Remote == nil || seen.Remote.State != run.RemoteDurable || seen.Remote.Local {
		t.Fatalf("host-b did not take in the run while it could read it: %+v", seen.Remote)
	}
	// Pushed mode, and nothing pushed.
	b.store.SetKeySource(offhost.NewPushedKeySource())
	b.store.SetPushed(true)
	if !b.manager.OffHost.Pushed() {
		t.Fatal("host-b is not in pushed mode")
	}
	// Host-a mints a new hold for the run (a resume there, a re-key) and
	// stops it again: the record moves on under a key host-b lacks.
	later, err := own.Mint(offhost.DefaultTenant, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	const laterSnap = "01hzzzzzzzzzzzzzzzzzzzzzzk"
	payloadOf := []byte(`{"id":"` + second.ID + `"}`)
	if err := a.store.AdvanceV2(bg, offhost.Record{Run: second.ID, Generation: 2, State: offhost.RecordStopped, Snapshot: laterSnap, Payload: payloadOf, Tenant: offhost.DefaultTenant}, &later, "host-c", false); err != nil {
		t.Fatal(err)
	}
	stats, syncErr := b.manager.SyncRemote(bg)
	if syncErr != nil {
		t.Fatalf("a sync over a record under a key this host was not given: %v; want no failure", syncErr)
	}
	if seen := b.get(t, second.ID); seen.Remote == nil || seen.Remote.Generation != 1 || seen.Remote.State != run.RemoteDurable {
		t.Fatalf("a record this host could not read moved the run here: %+v", seen.Remote)
	}
	if _, err := b.service.Latest(bg, second.ID); !errors.Is(err, run.ErrRemoteNeedKey) {
		t.Fatalf("Latest under a key this host was not given: %v", err)
	}
	// Running on another daemon: that is the public section's word, and
	// it is enough to let the run go here. The payload is never read.
	if err := a.store.AdvanceV2(bg, offhost.Record{Run: second.ID, Generation: 3, State: offhost.RecordRunning, Snapshot: laterSnap, Payload: payloadOf, Tenant: offhost.DefaultTenant}, &later, "host-c", false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.manager.SyncRemote(bg); err != nil {
		t.Fatalf("a sync over a run resumed elsewhere under a key this host was not given: %v", err)
	}
	if _, err := b.manager.Get(second.ID); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("host-b still lists a run that runs elsewhere: %v", err)
	}
	if capacity = b.manager.Capacity(); capacity.StoppedRemote != 0 {
		t.Fatalf("capacity after the known run was let go: %+v", capacity)
	}
	if stats.Remote != 2 || stats.Changed != 0 {
		t.Fatalf("the sync: %+v", stats)
	}
}
