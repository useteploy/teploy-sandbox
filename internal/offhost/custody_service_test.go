package offhost

// Key custody K2: the service in the custody mode. Every host here is a
// PushedKeySource holding nothing but the keys the test says Cloud
// pushed; the fleet's work (a collection, a verify, a scrub, a rotation,
// the listing) runs on hosts holding no tenant key at all.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// custodyHost is one daemon in the custody mode (pushed): its store on a
// bucket the test can hook, its host pool, and the hold keys Cloud pushed
// to it — none until supplied.
type custodyHost struct {
	t      *testing.T
	memory *offhosttest.Memory
	bucket *offhosttest.Faulty
	cloud  *kms
	keys   *Keyring
	source *PushedKeySource
	store  *Store
	host   *pool
	logs   *bytes.Buffer
	*Service
}

// newCustodyBucket is a KMS and a fleet key shared by the hosts of a test.
type custodyBucket struct {
	cloud  *kms
	keys   *Keyring
	memory *offhosttest.Memory
}

func newCustodyBucket(t *testing.T) *custodyBucket {
	t.Helper()
	return &custodyBucket{cloud: newKMS(t), keys: testKeyring(t, 1), memory: offhosttest.NewMemory()}
}

// host is a daemon on the bucket, pushed mode, holding no tenant key.
func (b *custodyBucket) host(t *testing.T, name string) *custodyHost {
	t.Helper()
	bucket := offhosttest.NewFaulty(b.memory)
	source := NewPushedKeySource()
	store := NewStore(bucket, "fleet", b.keys, quiet())
	store.ChunkBytes, store.Parallel = 1000, 3
	store.SetKeySource(source)
	store.SetPushed(true)
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	host := newPool()
	service := NewService(store, host, Config{Daemon: name, MaxChain: 8}, slog.New(slog.NewTextHandler(logs, nil)))
	return &custodyHost{t: t, memory: b.memory, bucket: bucket, cloud: b.cloud, keys: b.keys, source: source, store: store, host: host, logs: logs, Service: service}
}

// hold mints a hold key for a run of tenant, as Cloud would, and pushes
// it to this host.
func (h *custodyHost) hold(tenant, runID string) HoldKey {
	h.t.Helper()
	key := h.cloud.hold(h.t, tenant, runID)
	h.supply(key)
	return key
}

// supply pushes hold keys to this host.
func (h *custodyHost) supply(keys ...HoldKey) {
	h.t.Helper()
	if err := h.source.Supply(keys...); err != nil {
		h.t.Fatal(err)
	}
}

// blessed is the blessing of the base image this host's copy of it sends.
func (h *custodyHost) blessed() map[string]string {
	h.t.Helper()
	return map[string]string{baseB: sha256Hex(h.host.data[baseB])}
}

// upload is this host's upload of one of its snapshots.
func (h *custodyHost) upload(t *testing.T, hold HoldKey, id, base, purpose string, bases map[string]string) run.UploadResult {
	t.Helper()
	result, err := h.Upload(bg, run.UploadRequest{Run: hold.Run, Ref: "snap:" + id, Base: base, Purpose: purpose, Key: hold.Wrapped, Tenant: hold.Tenant, Bases: bases})
	if err != nil {
		t.Fatalf("%s: upload %s: %v", h.config.Daemon, id, err)
	}
	return result
}

// stop is the whole of a stop on this host: the upload (which verifies),
// the record, and the check after the record.
func (h *custodyHost) stop(t *testing.T, hold HoldKey, id, purpose string, bases map[string]string) {
	h.t.Helper()
	uploaded := h.upload(t, hold, id, "", purpose, bases)
	if purpose != PurposeStop {
		return
	}
	if _, err := h.Advance(bg, run.RemoteRecord{Run: hold.Run, Generation: 1, State: RecordStopped, Snapshot: "snap:" + id, Key: uploaded.Key, Tenant: hold.Tenant, Payload: []byte(`{"id":"` + hold.Run + `"}`)}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := h.Verify(bg, "snap:"+id); err != nil {
		t.Fatalf("the check after the record: %v", err)
	}
}

// sealedHashes is, for each snapshot id, the stream hash its sealed
// section names and the one it pins its parent to, read as a holder of
// the run's key reads them.
func (h *custodyHost) sealedHashes(hold HoldKey, ids ...string) map[string][2]string {
	h.t.Helper()
	out := map[string][2]string{}
	for _, id := range ids {
		manifest, _, err := h.store.Manifest(bg, id)
		if err != nil {
			h.t.Fatalf("manifest of %s: %v", id, err)
		}
		if err := manifest.openSealed(hold); err != nil {
			h.t.Fatalf("the sealed section of %s: %v", id, err)
		}
		out[id] = [2]string{manifest.StreamSHA256, manifest.ParentStreamSHA256}
	}
	return out
}

// elsewhere is another daemon on the bucket, given exactly holds and
// nothing else.
func (b *custodyBucket) elsewhere(t *testing.T, holds ...HoldKey) (*Store, *pool, *Service) {
	t.Helper()
	host := newPool()
	store := NewStore(b.memory, "fleet", b.keys, quiet())
	store.ChunkBytes, store.Parallel = 1000, 3
	store.SetKeySource(pushedSource(t, holds...))
	store.SetPushed(true)
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	return store, host, NewService(store, host, Config{Daemon: "elsewhere", MaxChain: 8}, quiet())
}

// restores is a host holding exactly holds restoring id to want, the base
// images held to bases.
func (b *custodyBucket) restores(t *testing.T, holds []HoldKey, id string, want []byte, bases map[string]string) *pool {
	t.Helper()
	_, host, service := b.elsewhere(t, holds...)
	if err := service.EnsureFor(bg, "snap:"+id, EnsureOptions{Bases: bases}); err != nil {
		t.Fatalf("a snapshot reported durable does not restore on another host: %v", err)
	}
	if !bytes.Equal(host.data[id], want) {
		t.Fatal("the restored snapshot is not the bytes that were uploaded")
	}
	return host
}

// localHost is a daemon in local mode, a fleet that is its own KMS: every
// tenant's key derives from the root, and the daemon mints hold keys.
func localHost(t *testing.T, cloud *kms, memory *offhosttest.Memory) (*Store, *pool, *Service) {
	t.Helper()
	host := newPool()
	store := NewStore(memory, "fleet", testKeyring(t, 1), quiet())
	store.ChunkBytes, store.Parallel = 1000, 3
	store.SetKeySource(localSource(t, cloud.root))
	if err := store.Probe(bg); err != nil {
		t.Fatal(err)
	}
	if store.Pushed() {
		t.Fatal("a local key source is not pushed mode")
	}
	return store, host, NewService(store, host, Config{Daemon: "local", MaxChain: 8}, quiet())
}

const (
	custodySnapD = "01hzzzzzzzzzzzzzzzzzzzzzzd"
	custodySnapE = "01hzzzzzzzzzzzzzzzzzzzzzze"
	custodyRunQ  = "01hzzzzzzzzzzzzzzzzzzzzzzq"
)

// Upload, restore (full, incremental, multi-hop), the parent pins and the
// stream hashes recorded on each copy — in pushed mode, on hosts holding
// nothing but the run under test. The fleet's work runs on a host with
// no key at all.
func TestCustodyUploadPinsRestoresAndRecordsStreams(t *testing.T) {
	bucket := newCustodyBucket(t)
	uploader, fleet := bucket.host(t, "uploader"), bucket.host(t, "fleet")
	hold := uploader.hold(tenantOne, runR)
	uploader.host.data[baseB] = randomBytes(t, 2500)
	data := map[string][]byte{snapS: randomBytes(t, 1500), snapT: randomBytes(t, 1200), custodySnapD: randomBytes(t, 1800), custodySnapE: randomBytes(t, 900)}
	for id := range data {
		uploader.host.data[id] = data[id]
		uploader.host.base[id] = baseB
	}
	bases := uploader.blessed()
	if first := uploader.upload(t, hold, snapS, "", PurposeStop, bases); first.Incremental || first.Key != hold.Wrapped || first.StoredBytes == 0 {
		t.Fatalf("the first snapshot: %+v", first)
	}
	if second := uploader.upload(t, hold, snapT, "snap:"+snapS, PurposeStop, bases); !second.Incremental {
		t.Fatalf("the second snapshot was not sent against the first: %+v", second)
	}
	if third := uploader.upload(t, hold, custodySnapD, "snap:"+snapT, PurposeStop, bases); !third.Incremental {
		t.Fatalf("the third snapshot was not sent against the second: %+v", third)
	}
	// The pins: each link names its parent's stream, and the first names
	// the base's as it was blessed.
	hashes := uploader.sealedHashes(hold, snapS, snapT, custodySnapD)
	if hashes[snapS][1] != bases[baseB] || hashes[snapS][0] != sha256Hex(data[snapS]) {
		t.Fatalf("the first link pins %q and is a stream of %q", hashes[snapS][1], hashes[snapS][0])
	}
	if hashes[snapT][1] != hashes[snapS][0] || hashes[custodySnapD][1] != hashes[snapT][0] {
		t.Fatal("a link does not pin the stream of the one it builds on")
	}
	if base, _, err := uploader.store.Manifest(bg, baseB); err != nil || base.v2 || base.StreamSHA256 != bases[baseB] {
		t.Fatalf("the base image: %v", err)
	}
	// This host's copies say what their streams are, from its own send.
	for id, want := range data {
		if id == custodySnapE {
			continue
		}
		if got := uploader.host.hashes[id]; got != sha256Hex(want) {
			t.Fatalf("the copy of %s says its stream hashes to %q; it was sent as %q", id, got, sha256Hex(want))
		}
	}
	// A caller's snapshot, built on the last stop, says its tenant in the
	// listing; and the run's record, written under its hold key, says in
	// its public section what every host may read.
	uploader.upload(t, hold, custodySnapE, "snap:"+custodySnapD, PurposeSnapshot, bases)
	if _, err := uploader.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Snapshot: "snap:" + custodySnapD, Key: hold.Wrapped, Tenant: tenantOne, Payload: []byte(`{"env":{"TOKEN":"s3cr3t-env"}}`)}); err != nil {
		t.Fatal(err)
	}

	// The fleet's host holds no tenant key, and all of this is its work.
	if len(fleet.source.keys) != 0 || !fleet.Pushed() {
		t.Fatal("the fixture gave the fleet's host a tenant key, or it is not pushed")
	}
	if _, _, err := fleet.store.Verify(bg, custodySnapE); err != nil {
		t.Fatalf("Verify with no tenant key: %v", err)
	}
	if found, err := fleet.ScrubContent(bg, []string{"snap:" + custodySnapE}, 1<<20); err != nil || !found.Complete || found.Snapshots != 5 || len(found.Damaged) != 0 {
		t.Fatalf("ScrubContent with no tenant key: %+v, %v", found, err)
	}
	if listed, err := fleet.ListSnapshots(bg); err != nil || len(listed) != 1 || listed[0].ID != custodySnapE || listed[0].Tenant != tenantOne || listed[0].Run != runR {
		t.Fatalf("ListSnapshots: %+v, %v", listed, err)
	}
	if _, err := fleet.Latest(bg, runR); !errors.Is(err, run.ErrRemoteNeedKey) {
		t.Fatalf("Latest with no tenant key: %v", err)
	}
	if record, err := fleet.LatestPublic(bg, runR); err != nil || record.State != RecordStopped || record.Tenant != tenantOne || record.KID != hold.KID || record.Payload != nil {
		t.Fatalf("LatestPublic with no tenant key: %+v, %v", record, err)
	}
	if _, err := fleet.LatestPublic(bg, custodyRunQ); !errors.Is(err, run.ErrNotFound) {
		t.Fatalf("LatestPublic of a run with no record: %v", err)
	}

	// Another host, given the run's key and the blessing, and nothing
	// else, restores the newest through the whole chain: base, then each
	// increment. Its copies then say what their streams are.
	host := bucket.restores(t, []HoldKey{hold}, custodySnapE, data[custodySnapE], bases)
	for id, want := range map[string][]byte{baseB: uploader.host.data[baseB], snapS: data[snapS], snapT: data[snapT], custodySnapD: data[custodySnapD], custodySnapE: data[custodySnapE]} {
		if !bytes.Equal(host.data[id], want) {
			t.Fatalf("the restored %s is not what was uploaded", id)
		}
		if got := host.hashes[id]; got != sha256Hex(want) {
			t.Fatalf("the restored copy of %s does not say what its stream is (%q); it could never be sent against", id, got)
		}
	}
	// A host that already has a link of the chain restores only the rest,
	// and the check on the chain is made all the same: asked for as
	// another tenant, or as another run, it is refused.
	_, part, partService := bucket.elsewhere(t, hold)
	part.data[snapT] = data[snapT]
	part.hashes[snapT] = sha256Hex(data[snapT])
	if err := partService.EnsureFor(bg, "snap:"+custodySnapD, EnsureOptions{Tenant: tenantTwo, Bases: bases}); !errors.Is(err, ErrCorrupt) || len(part.data) != 1 {
		t.Fatalf("a restore asked for as another tenant: %v (%d on the host)", err, len(part.data))
	}
	if err := partService.EnsureFor(bg, "snap:"+custodySnapD, EnsureOptions{Run: custodyRunQ, Bases: bases}); !errors.Is(err, ErrCorrupt) || len(part.data) != 1 {
		t.Fatalf("a restore asked for as another run: %v (%d on the host)", err, len(part.data))
	}
	if err := partService.EnsureFor(bg, "snap:"+custodySnapD, EnsureOptions{Tenant: tenantOne, Run: runR, Bases: bases}); err != nil || len(part.data) != 2 {
		t.Fatalf("a restore onto a verified local parent: %v (%d on the host)", err, len(part.data))
	}
}

// A restore asks for every hold key its chain needs in one answer —
// deduplicated by kid — and receives nothing until it has them all.
func TestCustodyARestoreAsksForEveryMissingKeyAtOnce(t *testing.T) {
	bucket := newCustodyBucket(t)
	uploader := bucket.host(t, "uploader")
	// A chain re-keyed along its length: each link under a hold of its
	// own, as a run handed between hosts is.
	first := uploader.hold(tenantOne, runR)
	second := uploader.hold(tenantOne, runR)
	third := uploader.hold(tenantOne, runR)
	uploader.supply(first, second, third)
	baseData := randomBytes(t, 2500)
	if _, err := uploader.store.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "b"}, uploader.store.Keys().mustNewKey(t, baseB), bytes.NewReader(baseData)); err != nil {
		t.Fatal(err)
	}
	streams := map[string][]byte{snapS: randomBytes(t, 1500), snapT: randomBytes(t, 1200), custodySnapD: randomBytes(t, 1800), custodySnapE: randomBytes(t, 900)}
	putV2(t, uploader.store, first, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "s", Parent: baseB, ParentGUID: "b", Depth: 1, ParentStreamSHA256: sha256Hex(baseData)}, streams[snapS])
	hashes := uploader.sealedHashes(first, snapS)
	putV2(t, uploader.store, second, Manifest{ID: snapT, Purpose: PurposeStop, Run: runR, GUID: "t", Parent: snapS, ParentGUID: "s", Depth: 2, ParentStreamSHA256: hashes[snapS][0]}, streams[snapT])
	hashes = uploader.sealedHashes(second, snapT)
	putV2(t, uploader.store, third, Manifest{ID: custodySnapD, Purpose: PurposeStop, Run: runR, GUID: "d", Parent: snapT, ParentGUID: "t", Depth: 3, ParentStreamSHA256: hashes[snapT][0]}, streams[custodySnapD])
	// A fourth link under the first hold again.
	hashes = uploader.sealedHashes(third, custodySnapD)
	putV2(t, uploader.store, first, Manifest{ID: custodySnapE, Purpose: PurposeStop, Run: runR, GUID: "e", Parent: custodySnapD, ParentGUID: "d", Depth: 4, ParentStreamSHA256: hashes[custodySnapD][0]}, streams[custodySnapE])

	missing := func(holds ...HoldKey) []string {
		t.Helper()
		_, host, service := bucket.elsewhere(t, holds...)
		err := service.EnsureFor(bg, "snap:"+custodySnapE, EnsureOptions{})
		var need *NeedKeyError
		if !errors.As(err, &need) || !errors.Is(err, ErrNeedKey) {
			t.Fatalf("a restore without the chain's keys: %v, want ErrNeedKey", err)
		}
		if len(host.data) != 0 {
			t.Fatalf("a restore that lacks keys received %d snapshots", len(host.data))
		}
		var kids []string
		for _, one := range need.Missing {
			kids = append(kids, one.KID)
			if one.Tenant != tenantOne || one.Run != runR || one.Wrapped == "" {
				t.Fatalf("a missing key is not named: %+v", one)
			}
		}
		return kids
	}
	if got := missing(); len(got) != 3 || !containsAll(got, first.KID, second.KID, third.KID) {
		t.Fatalf("with no key, the restore asked for %v; want all three", got)
	}
	if got := missing(third); len(got) != 2 || !containsAll(got, first.KID, second.KID) {
		t.Fatalf("with the newest key alone, the restore asked for %v; want the two older ones", got)
	}
	if got := missing(second, third); len(got) != 1 || got[0] != first.KID {
		t.Fatalf("with the two newest keys, the restore asked for %v; want the oldest, once for the two links under it", got)
	}
	// With them all, the chain restores.
	bucket.restores(t, []HoldKey{first, second, third}, custodySnapE, streams[custodySnapE], map[string]string{baseB: sha256Hex(baseData)})
}

func containsAll(have []string, want ...string) bool {
	for _, one := range want {
		found := false
		for _, h := range have {
			found = found || h == one
		}
		if !found {
			return false
		}
	}
	return true
}

// A chain is of one tenant. One tenant's snapshot never builds on
// another's, whoever says so: with every tenant's key at hand (a fleet
// that is its own KMS), only the check on the chain stands between one
// tenant's run and another's snapshot. A chain with a link of another
// tenant is refused before anything is received, with a tenant asked for
// or without one.
func TestCustodyACrossTenantChainIsRefused(t *testing.T) {
	cloud := newKMS(t)
	store, host, service := localHost(t, cloud, offhosttest.NewMemory())
	ours := cloud.hold(t, tenantOne, runA)
	theirs := cloud.hold(t, tenantTwo, runB)
	sSplice := randomBytes(t, 1500)
	putV2(t, store, ours, Manifest{ID: snapS, Purpose: PurposeStop, Run: runA, GUID: "1"}, sSplice)
	pins := func(id string, hold HoldKey) string {
		t.Helper()
		manifest, _, err := store.Manifest(bg, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := manifest.openSealed(hold); err != nil {
			t.Fatal(err)
		}
		return manifest.StreamSHA256
	}
	// Tenant two's snapshot builds on tenant one's: a splice.
	putV2(t, store, theirs, Manifest{ID: snapT, Purpose: PurposeStop, Run: runB, GUID: "2", Parent: snapS, ParentGUID: "1", Depth: 1, ParentStreamSHA256: pins(snapS, ours)}, randomBytes(t, 1500))
	putV2(t, store, theirs, Manifest{ID: custodySnapD, Purpose: PurposeStop, Run: runB, GUID: "3", Parent: snapT, ParentGUID: "2", Depth: 2, ParentStreamSHA256: pins(snapT, theirs)}, randomBytes(t, 1500))
	// The splice is sound as far as sizes and even pins go: only the
	// tenant says it is wrong.
	if _, _, err := store.Verify(bg, custodySnapD); err != nil {
		t.Fatalf("by sizes the spliced chain is whole: %v", err)
	}
	for name, opts := range map[string]EnsureOptions{
		"nothing asked":            {},
		"the splicing tenant":      {Tenant: tenantTwo},
		"the tenant spliced in":    {Tenant: tenantOne},
		"the run asked for, wrong": {Run: runA},
	} {
		if err := service.EnsureFor(bg, "snap:"+custodySnapD, opts); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: a restore of a chain of two tenants = %v, want ErrCorrupt", name, err)
		}
		if len(host.data) != 0 {
			t.Errorf("%s: a refused restore received %d snapshots", name, len(host.data))
		}
	}
	// The tenant's own chain restores, and only as its tenant.
	putV2(t, store, ours, Manifest{ID: custodySnapE, Purpose: PurposeStop, Run: runA, GUID: "4", Parent: snapS, ParentGUID: "1", Depth: 1, ParentStreamSHA256: pins(snapS, ours)}, randomBytes(t, 1500))
	if err := service.EnsureFor(bg, "snap:"+custodySnapE, EnsureOptions{Tenant: tenantTwo}); !errors.Is(err, ErrCorrupt) || len(host.data) != 0 {
		t.Fatalf("a restore asked for as another tenant: %v (%d received)", err, len(host.data))
	}
	if err := service.EnsureFor(bg, "snap:"+custodySnapE, EnsureOptions{Tenant: "Org"}); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("a tenant that is not one: %v, want ErrBadRequest", err)
	}
	if err := service.EnsureFor(bg, "snap:"+custodySnapE, EnsureOptions{Tenant: tenantOne, Run: runA}); err != nil || len(host.data) != 2 || !bytes.Equal(host.data[snapS], sSplice) {
		t.Fatalf("the tenant's own chain, asked for as its tenant: %v (%d received)", err, len(host.data))
	}
}

// Adversarial test 4, the restore: a base image replaced by a valid base
// image with another stream. Every child refuses it — with the blessing
// to compare against, and with only the pin to go by — before a third
// host receives anything, and a host with the child does not upload
// against the replacement.
func TestCustodyABaseReplacedByAnotherStreamIsRefusedByEveryChild(t *testing.T) {
	// replace uploads another valid base image under the base's ID, with
	// the fleet key alone.
	replace := func(t *testing.T, memory *offhosttest.Memory, keys *Keyring) {
		t.Helper()
		for _, key := range memory.Keys("fleet/v1/snap/" + baseB + "/") {
			if !strings.Contains(key, "/pin/") {
				memory.Remove(key)
			}
		}
		plain := NewStore(memory, "fleet", keys, quiet())
		if _, err := plain.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "1234"}, plain.Keys().mustNewKey(t, baseB), bytes.NewReader(randomBytes(t, 2500))); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("with the blessing", func(t *testing.T) {
		bucket := newCustodyBucket(t)
		uploader := bucket.host(t, "uploader")
		hold := uploader.hold(tenantOne, runR)
		uploader.host.data[baseB] = randomBytes(t, 2500)
		uploader.host.data[snapS], uploader.host.data[snapT] = randomBytes(t, 1500), randomBytes(t, 900)
		uploader.host.base[snapS], uploader.host.base[snapT] = baseB, baseB
		bases := uploader.blessed()
		uploader.stop(t, hold, snapS, PurposeStop, bases)
		replace(t, bucket.memory, bucket.keys)
		// The child, by itself, still looks whole.
		if _, _, err := uploader.store.Verify(bg, snapS); err != nil {
			t.Fatalf("by sizes the child is whole: %v", err)
		}
		_, host, service := bucket.elsewhere(t, hold)
		if err := service.EnsureFor(bg, "snap:"+snapS, EnsureOptions{Bases: bases}); !errors.Is(err, ErrCorrupt) || len(host.data) != 0 {
			t.Fatalf("a restore over a replaced base image: %v (%d received), want ErrCorrupt and nothing received", err, len(host.data))
		}
		// A host that has another snapshot of the run does not upload
		// against the replacement either.
		if _, err := uploader.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: bases}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("an upload against a replaced base image: %v, want ErrCorrupt", err)
		}
		if has, _ := uploader.store.HasSnapshot(bg, snapT); has {
			t.Fatal("a snapshot was uploaded against a replaced base image")
		}
		if !strings.Contains(uploader.logs.String(), "AT RISK") {
			t.Fatalf("the base image at risk was not said in the log: %s", uploader.logs.String())
		}
	})
	t.Run("by the pin alone", func(t *testing.T) {
		// A fleet that is its own KMS, nothing blessed: the pin in the
		// child's sealed section is all a host has, and it is enough.
		cloud := newKMS(t)
		memory := offhosttest.NewMemory()
		store, host, service := localHost(t, cloud, memory)
		host.data[baseB], host.data[snapS] = randomBytes(t, 2500), randomBytes(t, 1500)
		host.base[snapS] = baseB
		if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Tenant: tenantOne}); err != nil {
			t.Fatal(err)
		}
		replace(t, memory, store.Keys())
		// A third host, with nothing local.
		_, elsewhere, restoring := localHost(t, cloud, memory)
		if err := restoring.EnsureFor(bg, "snap:"+snapS, EnsureOptions{}); !errors.Is(err, ErrCorrupt) || len(elsewhere.data) != 0 {
			t.Fatalf("a restore over a replaced base image, by the pin alone: %v (%d received)", err, len(elsewhere.data))
		}
		// And one that has the base already, with its stream recorded: the
		// local copy is held to the pin, and passes it — the base on this
		// host is still the stream the child was built on.
		elsewhere.data[baseB] = host.data[baseB]
		// A local base whose recorded stream is not the pinned one is
		// not built on either, GUID or no GUID.
		elsewhere.hashes[baseB] = sha256Hex([]byte("another base image, under the same ID"))
		if err := restoring.EnsureFor(bg, "snap:"+snapS, EnsureOptions{}); !errors.Is(err, ErrCorrupt) || len(elsewhere.data) != 1 {
			t.Fatalf("a restore onto a local base that is not the pinned stream: %v (%d on the host)", err, len(elsewhere.data))
		}
		elsewhere.hashes[baseB] = sha256Hex(host.data[baseB])
		if err := restoring.EnsureFor(bg, "snap:"+snapS, EnsureOptions{}); err != nil || !bytes.Equal(elsewhere.data[snapS], host.data[snapS]) {
			t.Fatalf("a restore onto a local base that is the pinned stream: %v", err)
		}
	})
}

// Adversarial test 5: a local parent with the right GUID and another
// stream hash — or none recorded — is not built on, by a restore or by
// an upload. GUID equality is not content equality.
func TestCustodyALocalParentIsHeldToItsStreamHash(t *testing.T) {
	arrange := func(t *testing.T) (*custodyBucket, *custodyHost, HoldKey, map[string]string) {
		t.Helper()
		bucket := newCustodyBucket(t)
		uploader := bucket.host(t, "uploader")
		hold := uploader.hold(tenantOne, runR)
		uploader.host.data[baseB] = randomBytes(t, 2500)
		uploader.host.data[snapS], uploader.host.data[snapT] = randomBytes(t, 1500), randomBytes(t, 1200)
		uploader.host.base[snapS], uploader.host.base[snapT] = baseB, baseB
		bases := uploader.blessed()
		uploader.stop(t, hold, snapS, PurposeStop, bases)
		uploader.upload(t, hold, snapT, "snap:"+snapS, PurposeStop, bases)
		return bucket, uploader, hold, bases
	}
	for name, localHash := range map[string]func() string{
		"another stream hash": func() string { return sha256Hex([]byte("another stream, with the same GUID")) },
		"no hash recorded":    func() string { return "" },
	} {
		t.Run("restore, "+name, func(t *testing.T) {
			bucket, uploader, hold, bases := arrange(t)
			// A host that has the parent: the same snapshot by GUID, but
			// not known to be the stream the child was built on.
			_, host, service := bucket.elsewhere(t, hold)
			host.data[snapS] = uploader.host.data[snapS]
			host.hashes[snapS] = localHash()
			if err := service.EnsureFor(bg, "snap:"+snapT, EnsureOptions{Bases: bases}); !errors.Is(err, ErrCorrupt) || len(host.data) != 1 {
				t.Fatalf("a restore onto an unverified local parent: %v (%d snapshots on the host), want ErrCorrupt and nothing received", err, len(host.data))
			}
			// With the stream verified and recorded, it is built on.
			host.hashes[snapS] = sha256Hex(host.data[snapS])
			if err := service.EnsureFor(bg, "snap:"+snapT, EnsureOptions{Bases: bases}); err != nil || !bytes.Equal(host.data[snapT], uploader.host.data[snapT]) {
				t.Fatalf("a restore onto a verified local parent: %v", err)
			}
		})
		t.Run("upload, "+name, func(t *testing.T) {
			bucket, uploader, hold, bases := arrange(t)
			// Another host with a copy of the parent — the same GUID —
			// and a new snapshot to upload against it.
			other := bucket.host(t, "other")
			other.supply(hold)
			other.host.data[snapS] = uploader.host.data[snapS]
			other.host.hashes[snapS] = localHash()
			other.host.data[baseB] = uploader.host.data[baseB]
			other.host.data[custodySnapD] = randomBytes(t, 900)
			other.host.base[custodySnapD] = baseB
			result := other.upload(t, hold, custodySnapD, "snap:"+snapS, PurposeStop, bases)
			if result.Incremental {
				t.Fatalf("an upload was sent against an unverified local parent: %+v", result)
			}
			if sends := other.host.sent(); sends[len(sends)-1] != baseB+" "+custodySnapD {
				t.Fatalf("the driver sent %v; want the stream against the base image", sends)
			}
			// The parent pin is read from the bucket's manifest never:
			// what was uploaded is pinned to the base's blessed stream,
			// and restores on a third host.
			bucket.restores(t, []HoldKey{hold}, custodySnapD, other.host.data[custodySnapD], bases)
			// With the copy verified, the same host sends against it.
			other.host.hashes[snapS] = sha256Hex(other.host.data[snapS])
			other.host.data[custodySnapE] = randomBytes(t, 700)
			if result := other.upload(t, hold, custodySnapE, "snap:"+snapS, PurposeStop, bases); !result.Incremental {
				t.Fatalf("an upload against a verified local parent: %+v", result)
			}
		})
	}
}

// Adversarial test 4, the upload: a base image is what Cloud blessed and
// nothing else. In the bucket it must hash to its blessing, or nothing is
// uploaded against it (and the log says the fleet is at risk); this
// host's own send must hash to it, or no manifest is written and the
// chunks are cleaned up; and in pushed mode a base image that was not
// blessed is refused, for an upload and for a restore.
func TestCustodyABaseImageIsWhatCloudBlessed(t *testing.T) {
	t.Run("the base in the bucket is not the blessed one", func(t *testing.T) {
		bucket := newCustodyBucket(t)
		host := bucket.host(t, "host")
		hold := host.hold(tenantOne, runR)
		host.host.data[baseB] = randomBytes(t, 2500)
		host.host.data[snapS] = randomBytes(t, 1500)
		host.host.base[snapS] = baseB
		blessed := map[string]string{baseB: hashCD}
		if _, err := host.store.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "1234"}, host.store.Keys().mustNewKey(t, baseB), bytes.NewReader(host.host.data[baseB])); err != nil {
			t.Fatal(err)
		}
		if _, _, err := host.ensureBaseAs(bg, baseB, blessed); !errors.Is(err, ErrCorrupt) || !strings.Contains(host.logs.String(), "AT RISK") {
			t.Fatalf("ensureBase against a base that is not the blessed stream: %v (logged: %s)", err, host.logs.String())
		}
		if _, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: blessed}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("an upload against a base that is not the blessed stream: %v, want ErrCorrupt", err)
		}
		if has, _ := host.store.HasSnapshot(bg, snapS); has {
			t.Fatal("a snapshot was uploaded against a base that is not the blessed one")
		}
		if sends := host.host.sent(); len(sends) != 0 {
			t.Fatalf("a snapshot was sent against a base that is not the blessed one: %v", sends)
		}
	})
	t.Run("this host's copy sends another stream than the blessed one", func(t *testing.T) {
		bucket := newCustodyBucket(t)
		host := bucket.host(t, "host")
		hold := host.hold(tenantOne, runR)
		host.host.data[baseB] = randomBytes(t, 2500)
		host.host.data[snapS] = randomBytes(t, 1500)
		host.host.base[snapS] = baseB
		blessed := map[string]string{baseB: hashCD}
		_, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: blessed})
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("an upload of a base image that sends another stream than blessed: %v, want ErrCorrupt", err)
		}
		// No manifest of the base, and no chunks: nothing is stored.
		if has, _ := host.store.HasSnapshot(bg, baseB); has {
			t.Fatal("a base image with another stream than the blessed one has a manifest")
		}
		if left := chunksUnder(bucket.memory, "fleet/v1/snap/"+baseB+"/"); len(left) != 0 {
			t.Fatalf("a refused base upload left %v", left)
		}
		if has, _ := host.store.HasSnapshot(bg, snapS); has {
			t.Fatal("the run's snapshot was uploaded against a refused base")
		}
	})
	t.Run("a base image that was not blessed", func(t *testing.T) {
		bucket := newCustodyBucket(t)
		host := bucket.host(t, "host")
		hold := host.hold(tenantOne, runR)
		host.host.data[custodySnapD] = randomBytes(t, 900)
		host.host.base[custodySnapD] = "base-99"
		host.host.data["base-99"] = randomBytes(t, 900)
		for name, bases := range map[string]map[string]string{
			"nothing pushed":   nil,
			"another one only": {baseB: hashCD},
		} {
			_, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + custodySnapD, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: bases})
			if err == nil || !strings.Contains(err.Error(), "not blessed") {
				t.Errorf("%s: an upload on an unblessed base image = %v, want it refused as not blessed", name, err)
			}
			if has, _ := host.store.HasSnapshot(bg, custodySnapD); has {
				t.Errorf("%s: a snapshot on an unblessed base image was uploaded", name)
			}
		}
		if _, _, err := host.ensureBaseAs(bg, "base-99", nil); err == nil || !strings.Contains(err.Error(), "not blessed") {
			t.Fatalf("ensureBase of an unblessed base image in pushed mode: %v", err)
		}
		// A restore in pushed mode is held to it as well.
		if _, err := host.store.Upload(bg, Manifest{ID: "base-99", Purpose: PurposeBase, GUID: "99"}, host.store.Keys().mustNewKey(t, "base-99"), bytes.NewReader(randomBytes(t, 900))); err != nil {
			t.Fatal(err)
		}
		putV2(t, host.store, hold, Manifest{ID: custodySnapD, Purpose: PurposeStop, Run: runR, GUID: "d", Parent: "base-99", ParentGUID: "99", Depth: 1, ParentStreamSHA256: sha256Hex(host.host.data[custodySnapD])}, host.host.data[custodySnapD])
		_, elsewhere, service := bucket.elsewhere(t, hold)
		if err := service.EnsureFor(bg, "snap:"+custodySnapD, EnsureOptions{}); err == nil || !strings.Contains(err.Error(), "not blessed") || len(elsewhere.data) != 0 {
			t.Fatalf("a restore with nothing blessed: %v (%d received)", err, len(elsewhere.data))
		}
	})
	t.Run("not a blessing", func(t *testing.T) {
		bucket := newCustodyBucket(t)
		host := bucket.host(t, "host")
		hold := host.hold(tenantOne, runR)
		host.host.data[baseB] = randomBytes(t, 2500)
		host.host.data[snapS] = randomBytes(t, 1500)
		host.host.base[snapS] = baseB
		sent := sha256Hex(host.host.data[baseB])
		for name, bases := range map[string]map[string]string{
			"not a hash":     {baseB: "blessed"},
			"not a base ID":  {snapS: sent},
			"upper-case hex": {baseB: strings.ToUpper(sent)},
		} {
			if _, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: bases}); !errors.Is(err, ErrCorrupt) {
				t.Errorf("%s: %v, want ErrCorrupt", name, err)
			}
		}
	})
}

// Without a blessed table — a fleet that is its own KMS — a base image's
// pin comes from the host's own send, and the upload, the pin and the
// restore are as with one.
func TestCustodyALocalFleetPinsABaseFromItsOwnSend(t *testing.T) {
	cloud := newKMS(t)
	memory := offhosttest.NewMemory()
	store, host, service := localHost(t, cloud, memory)
	base, snap := randomBytes(t, 2500), randomBytes(t, 1500)
	host.data[baseB], host.data[snapS] = base, snap
	host.base[snapS] = baseB
	// No key named: the local source mints one, for this hold.
	result, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Tenant: tenantOne})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Key, "t2."+tenantOne+".1.") {
		t.Fatalf("the key reported is not a wrapped hold key: %q", result.Key)
	}
	manifest, _, _ := store.Manifest(bg, snapS)
	hold, err := store.source().Unwrap(tenantOne, runR, result.Key)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Zero()
	if err := manifest.openSealed(hold); err != nil {
		t.Fatal(err)
	}
	if manifest.ParentStreamSHA256 != sha256Hex(base) || manifest.StreamSHA256 != sha256Hex(snap) {
		t.Fatal("the pin is not the base's stream as this host sent it")
	}
	if host.hashes[snapS] != sha256Hex(snap) {
		t.Fatal("the copy does not say what its stream is")
	}
	// A record under the minted key, and another local host restores.
	if _, err := service.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Snapshot: "snap:" + snapS, Payload: []byte(`{"id":"a"}`), Key: result.Key}); err != nil {
		t.Fatal(err)
	}
	_, elsewhere, other := localHost(t, cloud, memory)
	if err := other.EnsureFor(bg, "snap:"+snapS, EnsureOptions{Tenant: tenantOne, Run: runR}); err != nil || !bytes.Equal(elsewhere.data[snapS], snap) || !bytes.Equal(elsewhere.data[baseB], base) {
		t.Fatalf("a restore on another local host: %v", err)
	}
	if record, err := other.Latest(bg, runR); err != nil || record.Generation != 1 || record.Tenant != tenantOne || string(record.Payload) != `{"id":"a"}` {
		t.Fatalf("the record on another local host: %+v, %v", record, err)
	}
	// A stream against the verified local copy is sent incrementally,
	// and pinned to the copy's recorded stream.
	host.data[snapT] = randomBytes(t, 900)
	if result, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapT, Base: "snap:" + snapS, Purpose: PurposeStop, Key: result.Key, Tenant: tenantOne}); err != nil || !result.Incremental {
		t.Fatalf("an upload against a verified local parent: %+v, %v", result, err)
	}
}

// A snapshot found already in remote storage is never taken as uploaded
// on its sizes. In the custody mode the manifest that stands is opened
// under the run's hold key, and it must be this run's, this tenant's and
// this very snapshot's — or the upload is refused, and the manifest is
// left alone: it is somebody's, and not this host's to take back.
func TestCustodyAlreadyThereOpensTheSealedSection(t *testing.T) {
	arrange := func(t *testing.T) (*custodyBucket, *custodyHost, HoldKey) {
		t.Helper()
		bucket := newCustodyBucket(t)
		host := bucket.host(t, "host")
		hold := host.hold(tenantOne, runR)
		host.host.data[baseB] = randomBytes(t, 2500)
		host.host.data[snapS] = randomBytes(t, 3500)
		host.host.base[snapS] = baseB
		host.upload(t, hold, snapS, "", PurposeStop, host.blessed())
		delete(host.host.hashes, snapS)
		host.host.mu.Lock()
		host.host.sends = nil
		host.host.mu.Unlock()
		return bucket, host, hold
	}
	// again uploads the same snapshot again, as the upkeep would.
	again := func(t *testing.T, host *custodyHost, hold HoldKey) run.UploadResult {
		t.Helper()
		result, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: host.blessed()})
		if err != nil {
			t.Fatalf("the upload again: %v", err)
		}
		return result
	}
	refused := func(t *testing.T, host *custodyHost, hold HoldKey, want error) {
		t.Helper()
		before := host.memory.Raw(host.store.manifestKey(snapS))
		_, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: host.blessed()})
		if !errors.Is(err, want) {
			t.Fatalf("the upload again over a manifest that is not this run's: %v, want %v", err, want)
		}
		if got := host.memory.Raw(host.store.manifestKey(snapS)); !bytes.Equal(got, before) {
			t.Fatal("a manifest this host could not vouch for was taken back or written over")
		}
		if sends := host.host.sent(); len(sends) != 0 {
			t.Fatalf("a snapshot was sent over a manifest this host could not vouch for: %v", sends)
		}
	}
	t.Run("this run's own", func(t *testing.T) {
		_, host, hold := arrange(t)
		manifest := host.memory.Raw(host.store.manifestKey(snapS))
		if result := again(t, host, hold); !result.Already || result.StoredBytes != 0 || result.Key != hold.Wrapped {
			t.Fatalf("a snapshot that is there: %+v", result)
		}
		if got := host.memory.Raw(host.store.manifestKey(snapS)); !bytes.Equal(got, manifest) {
			t.Fatal("the manifest that stands was written over")
		}
		if got := host.host.hashes[snapS]; got != sha256Hex(host.host.data[snapS]) {
			t.Fatalf("the copy does not say what its stream is: %q", got)
		}
		if sends := host.host.sent(); len(sends) != 0 {
			t.Fatalf("a snapshot that is there was sent again: %v", sends)
		}
	})
	// stand puts another's manifest under the snapshot's ID, naming
	// chunks that are all there with the sizes it says.
	stand := func(t *testing.T, host *custodyHost, other HoldKey) {
		t.Helper()
		host.memory.Remove(host.store.manifestKey(snapS))
		putV2(t, host.store, other, Manifest{ID: snapS, Purpose: PurposeStop, Run: other.Run, GUID: "guid-" + snapS}, host.host.data[snapS])
		if _, _, err := host.store.Verify(bg, snapS); err != nil {
			t.Fatalf("by sizes it is whole: %v", err)
		}
	}
	t.Run("another run's manifest, sizes whole", func(t *testing.T) {
		bucket, host, hold := arrange(t)
		stand(t, host, bucket.cloud.hold(t, tenantOne, runB))
		refused(t, host, hold, ErrCorrupt)
	})
	t.Run("another tenant's manifest, sizes whole", func(t *testing.T) {
		bucket, host, hold := arrange(t)
		stand(t, host, bucket.cloud.hold(t, tenantTwo, runR))
		refused(t, host, hold, ErrCorrupt)
	})
	t.Run("the public section written again under the fleet key", func(t *testing.T) {
		_, host, hold := arrange(t)
		stored := host.memory.Raw(host.store.manifestKey(snapS))
		public := openPublic(t, host.keys, kindManifest, snapS, stored).PublicBytes
		envelope := envelopeOf(t, stored)
		// The graph as it was but for when, sealed as anyone with the
		// fleet key can seal it, with the sealed section carried over.
		host.memory.SetRaw(host.store.manifestKey(snapS), handSealed(t, host.keys, kindManifest, snapS, editJSON(t, public, func(d map[string]any) { d["createdAt"] = "2020-01-01T00:00:00Z" }), envelope.Key, envelope.SealedNonce, envelope.Sealed))
		if _, _, err := host.store.Verify(bg, snapS); err != nil {
			t.Fatalf("by sizes it is whole: %v", err)
		}
		refused(t, host, hold, ErrCorrupt)
		if got := host.host.hashes[snapS]; got != "" {
			t.Fatalf("a forged manifest's stream hash was recorded on the copy: %q", got)
		}
	})
	t.Run("a sealed section made with the fleet key alone", func(t *testing.T) {
		_, host, hold := arrange(t)
		stored := host.memory.Raw(host.store.manifestKey(snapS))
		public := openPublic(t, host.keys, kindManifest, snapS, stored).PublicBytes
		envelope := envelopeOf(t, stored)
		// The public section as it was and the run's hold key named on
		// it — and a sealed section no hold key made.
		host.memory.SetRaw(host.store.manifestKey(snapS), handSealed(t, host.keys, kindManifest, snapS, public, envelope.Key, randomBytes(t, nonceSizeV2), randomBytes(t, 80)))
		refused(t, host, hold, ErrCorrupt)
	})
	t.Run("this host's copy is another snapshot by GUID", func(t *testing.T) {
		_, host, hold := arrange(t)
		host.Service = NewService(host.store, &otherGUID{host.host, "another-snapshot"}, host.config, quiet())
		refused(t, host, hold, ErrCorrupt)
	})
	t.Run("this host's copy is another stream", func(t *testing.T) {
		_, host, hold := arrange(t)
		host.host.hashes[snapS] = sha256Hex([]byte("another stream"))
		refused(t, host, hold, ErrCorrupt)
	})
	t.Run("no key for the hold that sealed it", func(t *testing.T) {
		bucket, uploader, hold := arrange(t)
		stranger := bucket.host(t, "stranger")
		stranger.host.data[baseB], stranger.host.data[snapS] = uploader.host.data[baseB], uploader.host.data[snapS]
		stranger.host.base[snapS] = baseB
		if len(stranger.source.keys) != 0 {
			t.Fatal("the stranger was given a key")
		}
		refused(t, stranger, hold, ErrNeedKey)
	})
	t.Run("the tenant is the key's when none is named", func(t *testing.T) {
		bucket, host, _ := arrange(t)
		// The snapshot is another tenant's, uploaded by a host of that
		// tenant: this host holds that tenant's key for the run, and
		// names no tenant. The key says which tenant the run is of.
		theirs := bucket.cloud.hold(t, tenantTwo, runR)
		host.supply(theirs)
		host.memory.Remove(host.store.manifestKey(snapS))
		putV2(t, host.store, theirs, Manifest{ID: snapS, Purpose: PurposeStop, Run: runR, GUID: "guid-" + snapS, Parent: baseB, ParentGUID: "guid-" + baseB, Depth: 1, ParentStreamSHA256: sha256Hex(host.host.data[baseB])}, host.host.data[snapS])
		result, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: theirs.Wrapped, Bases: host.blessed()})
		if err != nil || !result.Already || result.Key != theirs.Wrapped {
			t.Fatalf("the upload again, with the tenant taken from the key: %+v, %v", result, err)
		}
		// Named as another tenant than the key's, it is refused before
		// anything is looked at.
		if _, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: theirs.Wrapped, Tenant: tenantOne, Bases: host.blessed()}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("a tenant named against its key's: %v, want ErrCorrupt", err)
		}
	})
	t.Run("the key named is newer than the manifest's hold", func(t *testing.T) {
		// The manifest is under an older hold of the same run, which
		// this host still holds; the caller names the current one. It is
		// already there, and the key to go on with is the current one.
		_, host, _ := arrange(t)
		current := host.hold(tenantOne, runR)
		if result := again(t, host, current); !result.Already || result.Key != current.Wrapped {
			t.Fatalf("a snapshot under an older hold of the run: %+v", result)
		}
	})
}

// otherGUID is a host pool whose copies have the GUID the test says.
type otherGUID struct {
	*pool
	guid string
}

func (o *otherGUID) Stat(_ context.Context, id string) (string, bool, error) {
	o.pool.mu.Lock()
	defer o.pool.mu.Unlock()
	if _, ok := o.pool.data[id]; !ok {
		return "", false, nil
	}
	return o.guid, true, nil
}

// The service's records in the custody mode: tenant and key travel with
// them, a destroyed record needs no key, and a record under a key this
// host was not given is said so (run.ErrRemoteNeedKey), never read wrong.
func TestCustodyRecordsThroughTheService(t *testing.T) {
	bucket := newCustodyBucket(t)
	host, other := bucket.host(t, "host"), bucket.host(t, "other")
	hold := host.hold(tenantOne, runR)
	payload := []byte(`{"id":"` + runR + `","env":{"TOKEN":"s3cr3t-env"}}`)
	if _, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Payload: payload, Key: "not-a-hold-key"}); err == nil {
		t.Fatal("a key that is not a wrapped hold key was taken")
	}
	if _, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Payload: payload, Tenant: "Org"}); !errors.Is(err, run.ErrBadRequest) {
		t.Errorf("a tenant that is not one: %v, want ErrBadRequest", err)
	}
	if _, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: "Org"}); !errors.Is(err, run.ErrBadRequest) {
		t.Errorf("an upload for a tenant that is not one: %v, want ErrBadRequest", err)
	}
	if _, err := host.Upload(bg, run.UploadRequest{Run: "a/b", Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne}); !errors.Is(err, run.ErrBadRequest) {
		t.Errorf("an upload for a run that is not an ID: %v, want ErrBadRequest", err)
	}
	if _, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: "checkpoint", Key: hold.Wrapped, Tenant: tenantOne}); !errors.Is(err, run.ErrBadRequest) {
		t.Errorf("an upload with a purpose there is not: %v, want ErrBadRequest", err)
	}
	foreign := bucket.cloud.hold(t, tenantTwo, runR)
	if _, err := host.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: foreign.Wrapped, Tenant: tenantOne}); !errors.Is(err, ErrCorrupt) {
		t.Errorf("an upload with a key of another tenant: %v, want ErrCorrupt", err)
	}
	if _, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Payload: payload, Key: foreign.Wrapped, Tenant: tenantOne}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a tenant named against its key's: %v, want ErrCorrupt", err)
	}
	if _, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Payload: payload, Tenant: tenantOne}); !errors.Is(err, ErrNeedKey) {
		t.Fatalf("a live record with no key named, in pushed mode: %v, want ErrNeedKey", err)
	}
	if records := bucket.memory.Keys("fleet/v1/run/"); len(records) != 0 {
		t.Fatalf("refused records left %v", records)
	}
	// No tenant named: the run's key says it.
	key, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 1, State: RecordStopped, Payload: payload, Key: hold.Wrapped})
	if err != nil || key != hold.Wrapped {
		t.Fatalf("Advance: %q, %v", key, err)
	}
	if key, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 2, State: RecordStopped, Payload: payload, Key: hold.Wrapped, Snapshot: "snap:" + snapS, Tenant: tenantOne}); err != nil || key != hold.Wrapped {
		t.Fatalf("Advance: %q, %v", key, err)
	}
	record, err := host.Latest(bg, runR)
	if err != nil || record.Generation != 2 || record.Tenant != tenantOne || record.KID != hold.KID || record.Key != hold.Wrapped || string(record.Payload) != string(payload) || record.SnapshotID != snapS || !record.Mine {
		t.Fatalf("Latest: %+v, %v", record, err)
	}
	public, err := host.LatestPublic(bg, runR)
	if err != nil || public.Generation != 2 || public.Tenant != tenantOne || public.KID != hold.KID || public.Payload != nil || public.Key != hold.Wrapped || public.State != RecordStopped {
		t.Fatalf("LatestPublic: %+v, %v", public, err)
	}
	// Another host, given nothing: the record says what it is, and who
	// wrote it; the payload is not to be had.
	if public, err := other.LatestPublic(bg, runR); err != nil || public.Generation != 2 || public.Owner != "host" || public.Mine || public.Tenant != tenantOne {
		t.Fatalf("LatestPublic on a host with no key: %+v, %v", public, err)
	}
	if _, err := other.Latest(bg, runR); !errors.Is(err, run.ErrRemoteNeedKey) || !errors.Is(err, ErrNeedKey) {
		t.Fatalf("Latest on a host with no key: %v, want run.ErrRemoteNeedKey", err)
	}
	// Destroyed: no key needed, on a host that has none.
	if key, err := other.Advance(bg, run.RemoteRecord{Run: runR, Generation: 3, State: RecordDestroyed}); err != nil || key != "" {
		t.Fatalf("a destroyed record on a host with no key: %q, %v", key, err)
	}
	if record, err := host.Latest(bg, runR); err != nil || record.State != RecordDestroyed || record.Payload != nil || record.Tenant != DefaultTenant {
		t.Fatalf("the destroyed record: %+v, %v", record, err)
	}
	// A key named for a destroyed record names the tenant, and is not
	// used: the record is under the fleet key alone.
	if key, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 4, State: RecordDestroyed, Key: hold.Wrapped}); err != nil || key != hold.Wrapped {
		t.Fatalf("a destroyed record with a key named: %q, %v", key, err)
	}
	if record, _, err := host.store.LatestPublic(bg, runR); err != nil || record.Generation != 4 || record.KID != "" || record.WrappedKey != "" || record.Tenant != tenantOne {
		t.Fatalf("the destroyed record: %+v, %v", record, err)
	}
	// A record that does not write is not reported written.
	if _, err := host.Advance(bg, run.RemoteRecord{Run: runR, Generation: 5, State: RecordStopped, Key: hold.Wrapped, Tenant: tenantOne}); err == nil {
		t.Fatal("a live record with no payload was reported written")
	}
	if record, _, err := host.store.LatestPublic(bg, runR); err != nil || record.Generation != 4 {
		t.Fatalf("a record that did not write stands: %+v, %v", record, err)
	}
}

// A restore under the custody mode, told which run is legacy, reads that
// run's v1 envelopes and no others'; without it they are refused.
func TestCustodyARestoreReadsV1OnlyAsTheLegacyRunItWasToldOf(t *testing.T) {
	bucket := newCustodyBucket(t)
	old := integrityStore(t, bucket.memory, bucket.keys)
	stream := randomBytes(t, 2500)
	runKey, _ := old.Keys().NewKey(runA)
	if _, err := old.Upload(bg, Manifest{ID: snapA, Purpose: PurposeStop, Run: runA, GUID: "1"}, runKey, bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	host := bucket.host(t, "host")
	if err := host.Ensure(bg, "snap:"+snapA); !errors.Is(err, ErrV1Refused) {
		t.Fatalf("a v1 snapshot of a run not marked legacy: %v, want ErrV1Refused", err)
	}
	if err := host.EnsureFor(bg, "snap:"+snapA, EnsureOptions{LegacyRun: runB}); !errors.Is(err, ErrV1Refused) || len(host.host.data) != 0 {
		t.Fatalf("a v1 snapshot with another run said legacy: %v, want ErrV1Refused", err)
	}
	if err := host.EnsureFor(bg, "snap:"+snapA, EnsureOptions{LegacyRun: runA}); err != nil || !bytes.Equal(host.host.data[snapA], stream) {
		t.Fatalf("a v1 snapshot with its run said legacy: %v", err)
	}
	// Marked at the store, it restores with nothing said.
	delete(host.host.data, snapA)
	host.store.SetLegacyRuns(map[string]bool{runA: true})
	if err := host.Ensure(bg, "snap:"+snapA); err != nil || !bytes.Equal(host.host.data[snapA], stream) {
		t.Fatalf("a legacy run's snapshot, marked at the store: %v", err)
	}
}

// The two-phase delete in the custody mode: a collector that holds no
// tenant key at all, and an uploader that holds only its run's.
type custodyA4 struct {
	bucket   *custodyBucket
	uploader *custodyHost
	collecto *custodyHost
	second   *custodyHost
	hold     HoldKey
	bases    map[string]string
	clock    *time.Time
}

// newCustodyA4 is the position of review A4's open window: a base image
// in the bucket that nothing has referred to for two days, a collector
// that has watched it for that long, and a host about to stop a run whose
// stream builds on it.
func newCustodyA4(t *testing.T) *custodyA4 {
	t.Helper()
	bucket := newCustodyBucket(t)
	uploader, collector, second := bucket.host(t, "uploader"), bucket.host(t, "collector"), bucket.host(t, "second")
	hold := uploader.hold(tenantOne, runR)
	uploader.host.data[baseB], uploader.host.data[snapS], uploader.host.data[snapT] = randomBytes(t, 2500), randomBytes(t, 1500), randomBytes(t, 3500)
	uploader.host.base[snapS], uploader.host.base[snapT] = baseB, baseB
	bases := uploader.blessed()
	uploader.upload(t, hold, snapS, "", PurposeStop, bases)
	if err := uploader.store.DeleteSnapshot(bg, snapS); err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	now := func() time.Time { return clock }
	bucket.memory.Now = now
	uploader.store.now, collector.store.now, second.store.now = now, now, now
	for _, store := range []*Store{collector.store, second.store} {
		if _, err := store.Collect(bg, twoPhaseGrace); err != nil {
			t.Fatal(err)
		}
	}
	clock = clock.Add(48 * time.Hour)
	return &custodyA4{bucket: bucket, uploader: uploader, collecto: collector, second: second, hold: hold, bases: bases, clock: &clock}
}

func (w *custodyA4) stop(t *testing.T, purpose string) {
	t.Helper()
	w.uploader.stop(t, w.hold, snapT, purpose, w.bases)
}

func (w *custodyA4) restores(t *testing.T) {
	t.Helper()
	data := w.uploader.host.data[snapT]
	w.bucket.restores(t, []HoldKey{w.hold}, snapT, data, w.bases)
}

func (w *custodyA4) advance(d time.Duration) {
	*w.clock = w.clock.Add(d)
}

// Row 1: the upload pins the base and checks it (and writes its manifest
// and record and checks again) after the collector decided and before it
// deleted the manifest. The collector's listing sees the pin and puts the
// manifest back. Before the two-phase delete this was A4's open window.
func TestCustodyTwoPhaseAnUploadThatCheckedBeforeTheCondemnationIsSeen(t *testing.T) {
	for _, purpose := range []string{PurposeStop, PurposeSnapshot} {
		t.Run(purpose, func(t *testing.T) {
			w := newCustodyA4(t)
			w.collecto.bucket.Set(func(f *offhosttest.Faulty) {
				f.BeforeDelete = once(w.collecto.store.manifestKey(baseB), func() { w.stop(t, purpose) })
			})
			stats, err := w.collecto.store.Collect(bg, twoPhaseGrace)
			if err != nil {
				t.Fatal(err)
			}
			if stats.Restored != 1 || stats.Snapshots != 0 {
				t.Fatalf("a condemnation the upload had pinned first: %+v", stats)
			}
			if w.bucket.memory.Raw(w.collecto.store.condemnedKey(baseB)) != nil {
				t.Fatal("the condemned copy is still there after the manifest was put back")
			}
			w.restores(t)
			// The next round keeps the base: something builds on it now.
			if stats, err := w.collecto.store.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 0 {
				t.Fatalf("the round after: %+v, %v", stats, err)
			}
			if len(w.collecto.source.keys) != 0 {
				t.Fatal("the collector was given a tenant key")
			}
		})
	}
}

// Row 5: a listing after the condemnation that is behind decides nothing.
func TestCustodyTwoPhaseABehindListingDecidesNothing(t *testing.T) {
	w := newCustodyA4(t)
	var frozen *offhosttest.Frozen
	w.collecto.bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = once(w.collecto.store.condemnedKey(baseB), func() {
			frozen = w.bucket.memory.Freeze() // what a lagging replica answers
			w.stop(t, PurposeStop)
		})
		f.Listed = func(prefix string, listed []s3.Object) []s3.Object {
			if prefix == w.collecto.store.snapshotPrefix(baseB) && frozen != nil {
				return frozen.Listing(prefix, listed)
			}
			return listed
		}
	})
	stats, err := w.collecto.store.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Restored != 1 || stats.Snapshots != 0 {
		t.Fatalf("collect on a listing that is behind: %+v, %v", stats, err)
	}
	w.restores(t)
}

// A snapshot nothing refers to goes by the two-phase delete, on a
// collector with no tenant key; what a record names, and what that
// builds on, stays; and a run destroyed — which needs no key — takes its
// snapshots with it.
func TestCustodyCollectTwoPhaseWithNoTenantKey(t *testing.T) {
	bucket := newCustodyBucket(t)
	uploader, collector := bucket.host(t, "uploader"), bucket.host(t, "collector")
	hold := uploader.hold(tenantOne, runR)
	uploader.host.data[baseB] = randomBytes(t, 2500)
	uploader.host.data[snapS], uploader.host.data[snapT] = randomBytes(t, 1500), randomBytes(t, 1200)
	uploader.host.base[snapS], uploader.host.base[snapT] = baseB, baseB
	bases := uploader.blessed()
	uploader.stop(t, hold, snapS, PurposeStop, bases)                  // named by the run's record
	uploader.upload(t, hold, snapT, "snap:"+snapS, PurposeStop, bases) // nothing names it
	clock := time.Now()
	now := func() time.Time { return clock }
	bucket.memory.Now = now
	collector.store.now = now
	if rec, _, err := collector.store.LatestPublic(bg, runR); err != nil || rec.State != RecordStopped || rec.Snapshot != snapS {
		t.Fatalf("the record the collector reads: %+v, %v", rec, err)
	}
	if _, err := collector.store.Collect(bg, twoPhaseGrace); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(25 * time.Hour)
	stats, err := collector.store.Collect(bg, twoPhaseGrace)
	if err != nil || stats.Snapshots != 1 || len(collector.source.keys) != 0 {
		t.Fatalf("a collection with no tenant key: %+v, %v", stats, err)
	}
	if has, _ := collector.store.HasSnapshot(bg, snapT); has {
		t.Fatal("the snapshot nothing names is still there")
	}
	for _, id := range []string{baseB, snapS} {
		if has, _ := collector.store.HasSnapshot(bg, id); !has {
			t.Fatalf("%s, which a record names or a named snapshot builds on, was collected", id)
		}
	}
	bucket.restores(t, []HoldKey{hold}, snapS, uploader.host.data[snapS], bases)
	if _, err := collector.Advance(bg, run.RemoteRecord{Run: runR, Generation: 2, State: RecordDestroyed}); err != nil {
		t.Fatal(err)
	}
	if _, err := collector.store.Collect(bg, twoPhaseGrace); err != nil { // first sees them unreferenced
		t.Fatal(err)
	}
	clock = clock.Add(25 * time.Hour)
	if stats, err := collector.store.Collect(bg, twoPhaseGrace); err != nil || stats.Snapshots != 2 {
		t.Fatalf("a destroyed run's snapshots: %+v, %v", stats, err)
	}
	// The record that says "destroyed" outlives them.
	if record, _, err := collector.store.LatestPublic(bg, runR); err != nil || record.State != RecordDestroyed {
		t.Fatalf("the destroyed run's record: %+v, %v", record, err)
	}
	if left := chunksUnder(bucket.memory, "fleet/v1/snap/"); len(left) != 0 {
		t.Fatalf("left: %v", left)
	}
}

// A manifest whose public section was written again verifies by sizes
// and does not restore: the sealed section does not open, so the restore
// refuses before it receives anything.
func TestCustodyARestoreRefusesAPublicSectionWrittenAgain(t *testing.T) {
	bucket := newCustodyBucket(t)
	uploader := bucket.host(t, "uploader")
	hold := uploader.hold(tenantOne, runR)
	uploader.host.data[baseB] = randomBytes(t, 2500)
	uploader.host.data[snapS] = randomBytes(t, 1500)
	uploader.host.base[snapS] = baseB
	bases := uploader.blessed()
	uploader.upload(t, hold, snapS, "", PurposeStop, bases)
	stored := bucket.memory.Raw(uploader.store.manifestKey(snapS))
	public := openPublic(t, bucket.keys, kindManifest, snapS, stored).PublicBytes
	envelope := envelopeOf(t, stored)
	bucket.memory.SetRaw(uploader.store.manifestKey(snapS), handSealed(t, bucket.keys, kindManifest, snapS, editJSON(t, public, func(d map[string]any) { d["createdAt"] = "2020-01-01T00:00:00Z" }), envelope.Key, envelope.SealedNonce, envelope.Sealed))
	if err := uploader.Verify(bg, "snap:"+snapS); err != nil {
		t.Fatalf("by sizes the snapshot is whole: %v", err)
	}
	_, host, service := bucket.elsewhere(t, hold)
	if err := service.EnsureFor(bg, "snap:"+snapS, EnsureOptions{Bases: bases}); !errors.Is(err, ErrCorrupt) || len(host.data) != 0 {
		t.Fatalf("a restore of a manifest whose public section was written again: %v (%d received)", err, len(host.data))
	}
}
