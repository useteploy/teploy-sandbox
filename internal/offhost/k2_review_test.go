package offhost

// K2 review regression tests (R1, R2, R4, R5, R6, and custody nits).

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

// lostDeleteAnswer is a bucket whose first conditional delete of key
// lands and then answers 404: the client's retry of a delete whose first
// attempt reached the service (internal/s3 DeleteIfMatch documents it).
type lostDeleteAnswer struct {
	*offhosttest.Faulty
	key  string
	once sync.Once
}

func (l *lostDeleteAnswer) DeleteIfMatch(ctx context.Context, key, etag string) error {
	err := l.Faulty.DeleteIfMatch(ctx, key, etag)
	if err == nil && key == l.key {
		lost := false
		l.once.Do(func() { lost = true })
		if lost {
			return s3.ErrNotFound
		}
	}
	return err
}

// K2 review R1. A retried DeleteIfMatch whose first attempt landed returns
// 404. condemn must treat 404 as deleted (not surpassed) so step 2's pin
// check puts a pinned manifest back.
func TestK2ReviewCondemnLostDeleteAnswerLosesAPinnedSnapshot(t *testing.T) {
	w := newA4World(t)
	w.collector.objects = &lostDeleteAnswer{Faulty: w.collectorBucket, key: w.baseManifest()}
	w.collectorBucket.Set(func(f *offhosttest.Faulty) {
		f.BeforeDelete = once(w.baseManifest(), func() { w.stop(t, PurposeStop) })
	})
	stats, err := w.collector.Collect(bg, twoPhaseGrace)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Restored != 1 {
		t.Errorf("an upload pinned the base before the delete; the manifest must be put back: %+v", stats)
	}
	if w.memory.Raw(w.baseManifest()) == nil && w.memory.Raw(w.collector.condemnedKey(baseB)) == nil {
		t.Fatal("the base image has neither a manifest nor a condemned copy: a stopped run's snapshot built on it is lost")
	}
	restores(t, w.uploader, snapT, w.host.data[snapT])
}

// K2 review R2 (adversarial test 4, second half). A host with the fleet
// key alone writes another valid base image under the base's ID in the
// window between the uploader's chunk uploads and its manifest write.
// The uploader must refuse and must not stamp the forged hash on its copy.
func TestK2ReviewABaseSwappedDuringTheUploadersOwnWriteIsNotBlessed(t *testing.T) {
	bucket := newCustodyBucket(t)
	uploader := bucket.host(t, "uploader")
	hold := uploader.hold(tenantOne, runR)
	uploader.host.data[baseB] = randomBytes(t, 2500)
	uploader.host.data[snapS] = randomBytes(t, 1500)
	uploader.host.base[snapS] = baseB
	bases := uploader.blessed()
	forged := randomBytes(t, 2600)
	var swapped bool
	uploader.bucket.Set(func(f *offhosttest.Faulty) {
		f.BeforePut = func(key string) {
			if key == uploader.store.manifestKey(baseB) && !swapped {
				swapped = true
				plain := NewStore(bucket.memory, "fleet", bucket.keys, quiet())
				plain.ChunkBytes = 1000
				if _, err := plain.Upload(bg, Manifest{ID: baseB, Purpose: PurposeBase, GUID: "1234"}, plain.Keys().mustNewKey(t, baseB), bytes.NewReader(forged)); err != nil {
					t.Error(err)
				}
			}
		}
	})
	_, err := uploader.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop, Key: hold.Wrapped, Tenant: tenantOne, Bases: bases})
	if !swapped {
		t.Fatal("the fixture did not swap the base")
	}
	if err == nil {
		t.Errorf("an upload over a base image that is not the blessed one was accepted (pinned to %s, blessed %s)",
			uploader.sealedHashes(hold, snapS)[snapS][1], bases[baseB])
	}
	if got := uploader.host.hashes[baseB]; got == sha256Hex(forged) {
		t.Errorf("the uploader recorded the forged base's stream hash on its own copy of the base")
	}
}

// K2 review R4 (design §3). Host B resumed the run under a new hold key HK2,
// has the parent restored and its stream hash recorded, and holds only HK2
// afterwards. Uploads against that parent must remain incremental using the
// restore-verified local stream hash without needing HK1.
func TestK2ReviewACrossHostResumeUploadsIncrementallyWithTheNewHoldKeyAlone(t *testing.T) {
	bucket := newCustodyBucket(t)
	a := bucket.host(t, "a")
	hk1 := a.hold(tenantOne, runR)
	a.host.data[baseB] = randomBytes(t, 2500)
	a.host.data[snapS] = randomBytes(t, 1500)
	a.host.base[snapS] = baseB
	bases := a.blessed()
	a.stop(t, hk1, snapS, PurposeStop, bases)

	b := bucket.host(t, "b")
	hk2 := bucket.cloud.hold(t, tenantOne, runR)
	b.supply(hk2) // HK1 was given for the restore only, and dropped since
	b.host.data[baseB] = a.host.data[baseB]
	b.host.data[snapS] = a.host.data[snapS]
	b.host.hashes[snapS] = sha256Hex(b.host.data[snapS]) // recorded by the restore
	b.host.data[custodySnapD] = randomBytes(t, 900)
	b.host.base[custodySnapD] = baseB
	result, err := b.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + custodySnapD, Base: "snap:" + snapS, Purpose: PurposeStop, Key: hk2.Wrapped, Tenant: tenantOne, Bases: bases})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Incremental {
		t.Errorf("an upload after a cross-host resume, against a parent this host restored and verified, went in full: the parent's sealed section was opened under a hold key pushed mode no longer holds")
	}
}

// K2 review nits:
//   - usableParent refuses a cross-tenant local parent
//   - UploadV2 refuses a child with Parent != "" and empty ParentStreamSHA256
//   - Advance with RecordDestroyed succeeds even when record.Key is a legacy v1 key
func TestK2ReviewCustodyHardeningNits(t *testing.T) {
	bucket := newCustodyBucket(t)
	host := bucket.host(t, "a")
	hk1 := host.hold(tenantOne, runR)
	hk2 := host.hold(tenantTwo, custodyRunQ)
	host.host.data[baseB] = randomBytes(t, 2500)
	host.host.data[snapS] = randomBytes(t, 1500)
	host.host.base[snapS] = baseB
	bases := host.blessed()
	host.stop(t, hk1, snapS, PurposeStop, bases)

	// Cross-tenant local parent must not be built on incrementally.
	host.host.data[custodySnapD] = randomBytes(t, 900)
	host.host.base[custodySnapD] = baseB
	res, err := host.Upload(bg, run.UploadRequest{Run: custodyRunQ, Ref: "snap:" + custodySnapD, Base: "snap:" + snapS, Purpose: PurposeStop, Key: hk2.Wrapped, Tenant: tenantTwo, Bases: bases})
	if err != nil {
		t.Fatal(err)
	}
	if res.Incremental {
		t.Fatalf("cross-tenant local parent was built on incrementally")
	}

	// UploadV2 refuses Parent != "" without a valid ParentStreamSHA256.
	if _, err := host.store.UploadV2(bg, Manifest{
		ID: custodySnapE, Purpose: PurposeStop, Run: runR, Tenant: tenantOne,
		GUID: "99", Parent: snapS, ParentGUID: "1", Depth: 1,
	}, &hk1, bytes.NewReader(randomBytes(t, 500))); !errors.Is(err, ErrCorrupt) {
		t.Errorf("UploadV2 with Parent and empty ParentStreamSHA256: %v, want ErrCorrupt", err)
	}

	// Destroyed record succeeds even if record.Key is still a legacy v1 key.
	v1Key, err := host.store.Keys().NewKey(runR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.Advance(bg, run.RemoteRecord{
		Run: runR, Generation: 2, State: RecordDestroyed, Key: v1Key.Wrapped, Tenant: tenantOne,
	}); err != nil {
		t.Fatalf("Advance(RecordDestroyed) with legacy v1 key: %v", err)
	}
}
