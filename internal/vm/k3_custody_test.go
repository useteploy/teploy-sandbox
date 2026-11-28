package vm

// Key Custody K3 end-to-end and adversarial tests:
// - Cross-host resume in pushed mode (428 -> key push -> retry, ephemeral keys.open drop, incremental upload under HK2)
// - Fork in pushed mode (cross-tenant refusal + cross-run fork chain 428 with ancestor run key)
// - Adversarial #6: expect rollback & superseded kid refusal (stopped exact generation/snapshot, takeover >= generation)
// - Adversarial #7: v1 downgrade refused for non-legacy run; allowed only with expect.kid == "v1"
// - Adversarial #10: forged destroyed / running record fences without erasing local copy or cached hold key
// - Adversarial #15: cloned state dir refused (ErrClonedCache); single damaged cache entry -> needs-key -> repaired by PushRunKeys
// - Adversarial #19: Cloud unreachable: stop, restart, pending upload, collection succeed

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/hostsecret"
	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
)

type k3FailingObjects struct {
	inner offhost.Objects
	fail  atomic.Bool
}

func (f *k3FailingObjects) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	if f.fail.Load() {
		return errors.New("simulated s3 outage")
	}
	return f.inner.Put(ctx, key, body, opts)
}
func (f *k3FailingObjects) Get(ctx context.Context, key string, limit int64) ([]byte, error) {
	if f.fail.Load() {
		return nil, errors.New("simulated s3 outage")
	}
	return f.inner.Get(ctx, key, limit)
}
func (f *k3FailingObjects) GetWithETag(ctx context.Context, key string, limit int64) ([]byte, string, error) {
	if f.fail.Load() {
		return nil, "", errors.New("simulated s3 outage")
	}
	return f.inner.GetWithETag(ctx, key, limit)
}
func (f *k3FailingObjects) Head(ctx context.Context, key string) (s3.Object, error) {
	if f.fail.Load() {
		return s3.Object{}, errors.New("simulated s3 outage")
	}
	return f.inner.Head(ctx, key)
}
func (f *k3FailingObjects) Delete(ctx context.Context, key string) error {
	if f.fail.Load() {
		return errors.New("simulated s3 outage")
	}
	return f.inner.Delete(ctx, key)
}
func (f *k3FailingObjects) DeleteIfMatch(ctx context.Context, key, etag string) error {
	if f.fail.Load() {
		return errors.New("simulated s3 outage")
	}
	return f.inner.DeleteIfMatch(ctx, key, etag)
}
func (f *k3FailingObjects) Walk(ctx context.Context, prefix string, each func(s3.Object) error) error {
	if f.fail.Load() {
		return errors.New("simulated s3 outage")
	}
	return f.inner.Walk(ctx, prefix, each)
}

type fakeCloudKMS struct {
	tks map[string][]byte // tenant -> 32-byte TK
}

func newFakeCloudKMS() *fakeCloudKMS {
	return &fakeCloudKMS{tks: map[string][]byte{}}
}

func (k *fakeCloudKMS) tk(tenant string) []byte {
	if existing, ok := k.tks[tenant]; ok {
		return existing
	}
	tk := make([]byte, offhost.KeySize)
	_, _ = rand.Read(tk)
	k.tks[tenant] = tk
	return tk
}

func (k *fakeCloudKMS) mint(t *testing.T, tenant, runID string) (run.PushedKey, offhost.HoldKey) {
	t.Helper()
	raw := make([]byte, offhost.KeySize)
	kidBytes := make([]byte, 16)
	_, _ = rand.Read(raw)
	_, _ = rand.Read(kidBytes)
	kid := hex.EncodeToString(kidBytes)
	wrapped, err := offhost.WrapHoldKey(k.tk(tenant), raw, tenant, runID, kid, 1)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := offhost.NewHoldKey(tenant, runID, kid, wrapped, raw)
	if err != nil {
		t.Fatal(err)
	}
	return run.PushedKey{
		Run:     runID,
		KID:     kid,
		Wrapped: wrapped,
		Raw:     base64.StdEncoding.EncodeToString(raw),
	}, hk
}

func (k *fakeCloudKMS) unwrap(t *testing.T, need run.KeyNeed) run.PushedKey {
	t.Helper()
	hk, err := offhost.UnwrapHoldKey(k.tk(need.Tenant), need.Run, need.Wrapped)
	if err != nil {
		t.Fatalf("Cloud KMS unwrap(%+v): %v", need, err)
	}
	// Extract raw bytes via Seal/Marshal? Better: unwrap directly using a tiny helper:
	// We know the key bytes from our own minted map — store raw by kid!
	hk.Zero()
	t.Fatalf("use trackedCloudKMS.unwrap")
	return run.PushedKey{}
}

type trackedCloudKMS struct {
	*fakeCloudKMS
	byKID map[string]run.PushedKey
}

func newTrackedCloudKMS() *trackedCloudKMS {
	return &trackedCloudKMS{fakeCloudKMS: newFakeCloudKMS(), byKID: map[string]run.PushedKey{}}
}

func (k *trackedCloudKMS) mint(t *testing.T, tenant, runID string) (run.PushedKey, offhost.HoldKey) {
	pk, hk := k.fakeCloudKMS.mint(t, tenant, runID)
	k.byKID[pk.KID] = pk
	return pk, hk
}

func (k *trackedCloudKMS) unwrapNeeds(t *testing.T, needs []run.KeyNeed) []run.PushedKey {
	t.Helper()
	out := make([]run.PushedKey, 0, len(needs))
	for _, n := range needs {
		// Verify authentication under tenant's TK first (like Cloud KMS does).
		hk, err := offhost.UnwrapHoldKey(k.tk(n.Tenant), n.Run, n.Wrapped)
		if err != nil {
			t.Fatalf("Cloud KMS refused unwrap for %+v: %v", n, err)
		}
		hk.Zero()
		pk, ok := k.byKID[n.KID]
		if !ok {
			t.Fatalf("unknown kid %s", n.KID)
		}
		pk.Run = n.Run
		out = append(out, pk)
	}
	return out
}

type pushedHost struct {
	*remoteHost
	source     *offhost.PushedKeySource
	cache      *offhost.HoldCache
	stateDir   string
	secretPath string
	blessed    map[string]string
}

func mergeBlessed(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func blessedGoldenHash(t *testing.T, tr *Transfer, z *fakeZFS) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	guid := z.snapshots[testGolden].guid
	baseID := offhost.BaseID(guid)
	if err := tr.Send(bg, baseID, "", &buf); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return map[string]string{baseID: hex.EncodeToString(sum[:])}
}

func newPushedHost(t *testing.T, bucket *offhosttest.Memory, objects offhost.Objects, daemon string, previous *pushedHost, secretPath string) *pushedHost {
	t.Helper()
	if secretPath == "" {
		if previous != nil {
			secretPath = previous.secretPath
		} else {
			secretPath = filepath.Join(t.TempDir(), "host-secret")
		}
	}
	var prevRemote *remoteHost
	if previous != nil {
		prevRemote = previous.remoteHost
	}

	source := offhost.NewPushedKeySource()
	var cache *offhost.HoldCache
	host := newHostPrepared(t, bucket, objects, daemon, prevRemote, nil, func(store *offhost.Store) {
		store.SetKeySource(source)
		store.SetPushed(true)
	}, func(cfg *offhost.Config, _ *run.Manager) {
		cfg.GCGrace = time.Hour
		cfg.PushedSource = source
		if prevRemote != nil {
			hs, err := hostsecret.Load(secretPath)
			if err != nil {
				t.Fatal(err)
			}
			c, err := offhost.OpenHoldCache(filepath.Join(prevRemote.stateDir, offhost.HoldCacheFileName), hs)
			clear(hs)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			cached, err := c.All()
			if err != nil {
				t.Fatal(err)
			}
			if err := source.Supply(cached...); err != nil {
				t.Fatal(err)
			}
			for i := range cached {
				cached[i].Zero()
			}
			cache = c
			cfg.HoldCache = c
		}
	})
	if cache == nil {
		hs, err := hostsecret.Load(secretPath)
		if err != nil {
			t.Fatal(err)
		}
		c, err := offhost.OpenHoldCache(filepath.Join(host.stateDir, offhost.HoldCacheFileName), hs)
		clear(hs)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		cache = c
		host.service = offhost.NewService(host.store, host.driver.Transfer(), offhost.Config{
			Daemon:       daemon,
			MaxChain:     3,
			GCGrace:      time.Hour,
			HoldCache:    cache,
			PushedSource: source,
		}, quietLog())
		host.manager.OffHost = host.service
	}
	host.manager.ReconcileHoldKeys()

	return &pushedHost{
		remoteHost: host,
		source:     source,
		cache:      cache,
		stateDir:   host.stateDir,
		secretPath: secretPath,
		blessed:    blessedGoldenHash(t, host.driver.Transfer(), host.zfs),
	}
}

func copyKey(k run.PushedKey) *run.PushedKey { c := k; return &c }

func copyKeys(ks ...run.PushedKey) []run.PushedKey {
	out := make([]run.PushedKey, len(ks))
	copy(out, ks)
	return out
}

func TestK3CrossHostResume428AndEphemeralOpenDrop(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
	b := newPushedHost(t, bucket, bucket, "host-b", nil, "")
	allBases := mergeBlessed(a.blessed, b.blessed)
	a.blessed, b.blessed = allBases, allBases

	const tenant = "org-acme"
	runID := run.NewULID(time.Now())
	hk1, _ := kms.mint(t, tenant, runID)

	created, err := a.manager.Create(bg, run.CreateRequest{
		ID:     runID,
		Image:  "golden",
		Tenant: tenant,
		Keys:   &run.KeyBundle{Hold: &hk1},
		Bases:  a.blessed,
	})
	if err != nil {
		t.Fatalf("create on host-a: %v", err)
	}
	data1 := payload(t, 200)
	a.write(t, created.ID, data1)
	stopped, err := a.manager.Stop(bg, created.ID)
	if err != nil {
		t.Fatalf("stop on host-a: %v", err)
	}
	if stopped.Remote == nil || stopped.Remote.State != run.RemoteDurable || stopped.Remote.Tenant != tenant || stopped.Remote.KID != hk1.KID || stopped.Remote.Legacy {
		t.Fatalf("host-a stopped remote state: %+v", stopped.Remote)
	}
	snap1 := stopped.Remote.Snapshot

	// Host B tries to resume without keys.open -> must return 428 NeedKeyError
	// naming hk1 and must NOT bump S3 generation!
	hk2, _ := kms.mint(t, tenant, runID)
	expect1 := &run.RemoteExpect{Generation: 1, Snapshot: snap1, KID: hk1.KID}
	_, err = b.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk2)},
		Bases:  b.blessed,
		Expect: expect1,
	})
	var needErr *run.NeedKeyError
	if !errors.As(err, &needErr) || len(needErr.Missing) == 0 || needErr.Missing[0].KID != hk1.KID {
		t.Fatalf("resume without keys.open: got %v, want NeedKeyError for %s", err, hk1.KID)
	}
	if rec, err := b.service.LatestPublic(bg, runID); err != nil || rec.Generation != 1 {
		t.Fatalf("428 mutated S3 generation: %+v, %v", rec, err)
	}

	// Cloud unwraps the needed keys and retries -> succeeds!
	openKeys := kms.unwrapNeeds(t, needErr.Missing)
	resumed, err := b.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk2), Open: openKeys},
		Bases:  b.blessed,
		Expect: expect1,
	})
	if err != nil {
		t.Fatalf("resume on host-b with keys.open: %v", err)
	}
	if !bytes.Equal(b.read(t, resumed.ID), data1) {
		t.Fatal("host-b bytes differ after cross-host resume")
	}
	// keys.open (hk1) MUST be dropped from host-b's PushedKeySource immediately!
	if _, err := b.source.Unwrap(tenant, runID, hk1.Wrapped); !errors.Is(err, offhost.ErrNeedKey) {
		t.Fatalf("keys.open (%s) stayed in host-b PushedKeySource after resume: %v", hk1.KID, err)
	}
	// Host B holds hk2 persistently and stops incrementally under hk2.
	data2 := payload(t, 240)
	b.write(t, runID, data2)
	stopped2, err := b.manager.Stop(bg, runID)
	if err != nil {
		t.Fatalf("stop on host-b: %v", err)
	}
	if stopped2.Remote == nil || stopped2.Remote.State != run.RemoteDurable || !stopped2.Remote.Incremental || stopped2.Remote.KID != hk2.KID || stopped2.Remote.Generation != 3 {
		t.Fatalf("host-b stop remote state: %+v", stopped2.Remote)
	}
}

func TestK3ForkCrossTenantRefusalAndCrossRunChain428(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
	c := newPushedHost(t, bucket, bucket, "host-c", nil, "")
	allBases := mergeBlessed(a.blessed, c.blessed)
	a.blessed, c.blessed = allBases, allBases

	const tenant = "org-one"
	parentID := run.NewULID(time.Now())
	hkParent, _ := kms.mint(t, tenant, parentID)
	if _, err := a.manager.Create(bg, run.CreateRequest{
		ID:     parentID,
		Image:  "golden",
		Tenant: tenant,
		Keys:   &run.KeyBundle{Hold: &hkParent},
		Bases:  a.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	a.write(t, parentID, payload(t, 128))
	if _, err := a.manager.Stop(bg, parentID); err != nil {
		t.Fatal(err)
	}

	// Cross-tenant fork refused (explicit tenant mismatch and key tenant mismatch).
	childID := run.NewULID(time.Now().Add(time.Millisecond))
	hkOtherTenant, _ := kms.mint(t, "org-two", childID)
	if _, err := a.manager.Fork(bg, parentID, run.ForkRequest{
		ID:     childID,
		Tenant: "org-two",
		Keys:   &run.KeyBundle{Hold: &hkOtherTenant},
		Bases:  a.blessed,
	}); !errors.Is(err, run.ErrBadRequest) {
		t.Fatalf("cross-tenant fork: got %v, want ErrBadRequest", err)
	}

	// Valid fork in same tenant with its own distinct hold key.
	hkChild, _ := kms.mint(t, tenant, childID)
	child, err := a.manager.Fork(bg, parentID, run.ForkRequest{
		ID:    childID,
		Keys:  &run.KeyBundle{Hold: copyKey(hkChild)},
		Bases: a.blessed,
	})
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	childData := payload(t, 160)
	a.write(t, child.ID, childData)
	childStopped, err := a.manager.Stop(bg, child.ID)
	if err != nil {
		t.Fatalf("stop child: %v", err)
	}
	if !childStopped.Remote.Incremental || childStopped.Remote.KID != hkChild.KID {
		t.Fatalf("child stopped remote: %+v", childStopped.Remote)
	}

	// Host C resumes child: first with child's key only -> 428 asks for parent's ancestor key!
	hkChild2, _ := kms.mint(t, tenant, childID)
	expectChild := &run.RemoteExpect{Generation: childStopped.Remote.Generation, Snapshot: childStopped.Remote.Snapshot, KID: hkChild.KID}
	_, err = c.manager.ResumeWith(bg, childID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hkChild2), Open: copyKeys(hkChild)},
		Bases:  c.blessed,
		Expect: expectChild,
	})
	var needErr *run.NeedKeyError
	if !errors.As(err, &needErr) || len(needErr.Missing) != 1 || needErr.Missing[0].Run != parentID || needErr.Missing[0].KID != hkParent.KID {
		t.Fatalf("cross-run chain resume without parent key: got %v, want NeedKeyError for parent %s (%s)", err, parentID, hkParent.KID)
	}
	// Retry with both child key and unwrapped ancestor key (carrying parentID) -> succeeds!
	ancestorOpen := kms.unwrapNeeds(t, needErr.Missing)
	if _, err := c.manager.ResumeWith(bg, childID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hkChild2), Open: append(copyKeys(hkChild), ancestorOpen...)},
		Bases:  c.blessed,
		Expect: expectChild,
	}); err != nil {
		t.Fatalf("cross-run chain resume with ancestor open key: %v", err)
	}
	if !bytes.Equal(c.read(t, childID), childData) {
		t.Fatal("child bytes differ on host-c")
	}
	// Both ephemeral open keys dropped after restore.
	for _, k := range []run.PushedKey{hkChild, hkParent} {
		if _, err := c.source.Unwrap(tenant, k.Run, k.Wrapped); !errors.Is(err, offhost.ErrNeedKey) {
			t.Fatalf("open key %s still present after restore: %v", k.KID, err)
		}
	}
}

// Adversarial test #6: superseded hold key at higher generation, and forged
// generation+1 under current kid for a stopped run, are both refused by expect.
func TestK3Adversarial6ExpectRollbackAndSupersededKID(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
	b := newPushedHost(t, bucket, bucket, "host-b", nil, "")
	allBases := mergeBlessed(a.blessed, b.blessed)
	a.blessed, b.blessed = allBases, allBases

	const tenant = "org-sec"
	runID := run.NewULID(time.Now())
	hk1, rawHK1 := kms.mint(t, tenant, runID)
	defer rawHK1.Zero()
	if _, err := a.manager.Create(bg, run.CreateRequest{
		ID: runID, Image: "golden", Tenant: tenant,
		Keys: &run.KeyBundle{Hold: copyKey(hk1)}, Bases: a.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	a.write(t, runID, payload(t, 120))
	stop1, err := a.manager.Stop(bg, runID)
	if err != nil {
		t.Fatal(err)
	}

	// Move run to host-b under hk2 (gen 2 running, gen 3 stopped).
	hk2, rawHK2 := kms.mint(t, tenant, runID)
	defer rawHK2.Zero()
	if _, err := b.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk2), Open: copyKeys(hk1)},
		Bases:  b.blessed,
		Expect: &run.RemoteExpect{Generation: 1, Snapshot: stop1.Remote.Snapshot, KID: hk1.KID},
	}); err != nil {
		t.Fatal(err)
	}
	b.write(t, runID, payload(t, 130))
	stop2, err := b.manager.Stop(bg, runID)
	if err != nil {
		t.Fatal(err)
	}

	// Subcase A: compromised past holder (with hk1) forges gen 4 under superseded hk1.
	forgedPayload, _ := json.Marshal(map[string]any{"id": runID, "state": "stopped", "image": "golden", "network": "none", "user": "root", "onExpire": "destroy", "limits": map[string]any{"memoryMb": 1024, "cpus": 1, "pids": 256}, "stoppedAt": time.Now(), "retainUntil": time.Now().Add(time.Hour)})
	if err := a.store.AdvanceV2(bg, offhost.Record{
		Run: runID, Generation: 4, State: offhost.RecordStopped,
		Snapshot: stop1.Remote.Snapshot, Payload: forgedPayload, Tenant: tenant,
	}, &rawHK1, "compromised-a", false); err != nil {
		t.Fatal(err)
	}
	c := newPushedHost(t, bucket, bucket, "host-c", nil, "")
	c.blessed = mergeBlessed(a.blessed, b.blessed, c.blessed)
	hk3, _ := kms.mint(t, tenant, runID)
	// Cloud expects hk2 at gen 3 -> MUST REFUSE forged gen 4 under hk1!
	if _, err := c.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk3), Open: copyKeys(hk2, hk1)},
		Bases:  c.blessed,
		Expect: &run.RemoteExpect{Generation: 3, Snapshot: stop2.Remote.Snapshot, KID: hk2.KID},
	}); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("superseded kid at gen+1: got %v, want ErrRemoteConflict", err)
	}

	// Subcase B: stopped run forged at generation+1 under the CURRENT kid (hk2) -> MUST REFUSE!
	run2ID := run.NewULID(time.Now().Add(2 * time.Millisecond))
	hkCur, rawCur := kms.mint(t, tenant, run2ID)
	defer rawCur.Zero()
	if _, err := b.manager.Create(bg, run.CreateRequest{
		ID: run2ID, Image: "golden", Tenant: tenant,
		Keys: &run.KeyBundle{Hold: copyKey(hkCur)}, Bases: b.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	b.write(t, run2ID, payload(t, 120))
	stopCur, err := b.manager.Stop(bg, run2ID)
	if err != nil {
		t.Fatal(err)
	}
	// Forge gen 2 under the same current kid hkCur.
	if err := b.store.AdvanceV2(bg, offhost.Record{
		Run: run2ID, Generation: 2, State: offhost.RecordStopped,
		Snapshot: stopCur.Remote.Snapshot, Payload: forgedPayload, Tenant: tenant,
	}, &rawCur, "compromised-b", false); err != nil {
		t.Fatal(err)
	}
	hkNext, _ := kms.mint(t, tenant, run2ID)
	if _, err := c.manager.ResumeWith(bg, run2ID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hkNext), Open: copyKeys(hkCur)},
		Bases:  c.blessed,
		Expect: &run.RemoteExpect{Generation: 1, Snapshot: stopCur.Remote.Snapshot, KID: hkCur.KID},
	}); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("stopped run forged at gen+1 under current kid: got %v, want ErrRemoteConflict", err)
	}

	// Subcase C: takeover accepts generation >= expect.generation and refuses behind.
	if _, err := b.manager.ResumeWith(bg, run2ID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hkNext), Open: copyKeys(hkCur)},
		Bases:  b.blessed,
		Expect: &run.RemoteExpect{Generation: 2, Snapshot: stopCur.Remote.Snapshot, KID: hkCur.KID},
	}); err != nil {
		t.Fatalf("setup running run2 for takeover: %v", err)
	}
	// Now gen is 3 (running under hkNext). Takeover expecting gen 4 (ahead) -> refused!
	hkTake, _ := kms.mint(t, tenant, run2ID)
	if _, err := c.manager.ResumeWith(bg, run2ID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(hkTake), Open: copyKeys(hkNext, hkCur)},
		Bases:    c.blessed,
		Expect:   &run.RemoteExpect{Generation: 4, KID: hkNext.KID},
	}); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("takeover behind expect.generation: got %v, want ErrRemoteConflict", err)
	}
	// Takeover expecting gen 2 (<= 3) under hkNext -> accepted!
	if _, err := c.manager.ResumeWith(bg, run2ID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(hkTake), Open: copyKeys(hkNext, hkCur)},
		Bases:    c.blessed,
		Expect:   &run.RemoteExpect{Generation: 2, KID: hkNext.KID},
	}); err != nil {
		t.Fatalf("takeover at gen >= expect.generation: %v", err)
	}
}

// Adversarial test #7: v1 record and snapshot forged with FMK only for a
// non-legacy run are refused; a legacy run with expect.kid == "v1" succeeds.
func TestK3Adversarial7V1DowngradeRefusedUnlessLegacyExpect(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	// A v1 daemon (flags off, FMK only) stops a run -> writes v1 manifest + v1 record.
	v1Host := newHostPrepared(t, bucket, bucket, "host-v1", nil, nil, nil)
	v1Run := v1Host.startRun(t, payload(t, 128))
	v1Host.stop(t, v1Run.ID)
	v1Stop := v1Host.get(t, v1Run.ID)

	// Pushed host B tries to resume expecting a v2 kid -> MUST REFUSE v1 downgrade!
	b := newPushedHost(t, bucket, bucket, "host-b", nil, "")
	b.blessed = mergeBlessed(b.blessed, blessedGoldenHash(t, v1Host.driver.Transfer(), v1Host.zfs))
	const tenant = "org-mig"
	hk2, _ := kms.mint(t, tenant, v1Run.ID)
	fakeV2KID := strings.Repeat("a", 32)
	if _, err := b.manager.ResumeWith(bg, v1Run.ID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk2)},
		Bases:  b.blessed,
		Expect: &run.RemoteExpect{Generation: 1, Snapshot: v1Stop.Remote.Snapshot, KID: fakeV2KID},
	}); err == nil {
		t.Fatal("forged v1 record/snapshot was accepted for a non-legacy run")
	}

	// With expect.kid == "v1", legacy resume succeeds and moves the run onto hk2!
	if _, err := b.manager.ResumeWith(bg, v1Run.ID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(hk2)},
		Bases:  b.blessed,
		Expect: &run.RemoteExpect{Generation: 1, Snapshot: v1Stop.Remote.Snapshot, KID: run.LegacyKID},
	}); err != nil {
		t.Fatalf("legacy resume with expect.kid=v1 failed: %v", err)
	}
	stoppedV2, err := b.manager.Stop(bg, v1Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stoppedV2.Remote.KID != hk2.KID || stoppedV2.Remote.Legacy {
		t.Fatalf("post-migration stop should be v2 under %s: %+v", hk2.KID, stoppedV2.Remote)
	}
}

// Adversarial test #10: a forged running/destroyed record for a held run in
// pushed mode fences it (superseded) while keeping BOTH its local copy and its
// cached hold key intact; explicit Destroy erases both.
func TestK3Adversarial10ForgedRecordFencesWithoutErasingKeyOrCopy(t *testing.T) {
	for _, forgedState := range []string{offhost.RecordDestroyed, offhost.RecordRunning} {
		t.Run("forged_"+forgedState, func(t *testing.T) {
			bucket := offhosttest.NewMemory()
			kms := newTrackedCloudKMS()
			a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
			const tenant = "org-hold"
			runID := run.NewULID(time.Now())
			hk1, _ := kms.mint(t, tenant, runID)
			if _, err := a.manager.Create(bg, run.CreateRequest{
				ID: runID, Image: "golden", Tenant: tenant,
				Keys: &run.KeyBundle{Hold: &hk1}, Bases: a.blessed,
			}); err != nil {
				t.Fatal(err)
			}
			a.write(t, runID, payload(t, 128))
			stopped, err := a.manager.Stop(bg, runID)
			if err != nil {
				t.Fatal(err)
			}
			snapRef, _ := a.service.Ref(stopped.Remote.Snapshot)

			// Attacker with FMK + bucket writes a forged record at gen 2.
			attackerKeys, _ := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
			attackerStore := offhost.NewStore(bucket, "fleet", attackerKeys, quietLog())
			attackerStore.SetKeySource(offhost.NewPushedKeySource())
			attackerStore.SetPushed(true)
			if err := attackerStore.Probe(bg); err != nil {
				t.Fatal(err)
			}
			if forgedState == offhost.RecordDestroyed {
				if err := attackerStore.AdvanceV2(bg, offhost.Record{
					Run: runID, Generation: 2, State: offhost.RecordDestroyed, Tenant: tenant,
				}, nil, "attacker", false); err != nil {
					t.Fatal(err)
				}
			} else {
				// Forged running record using a bogus hold key minted by attacker.
				_, bogusHK := kms.mint(t, tenant, runID)
				defer bogusHK.Zero()
				if err := attackerStore.AdvanceV2(bg, offhost.Record{
					Run: runID, Generation: 2, State: offhost.RecordRunning, Snapshot: stopped.Remote.Snapshot,
					Payload: []byte(`{}`), Tenant: tenant,
				}, &bogusHK, "attacker", false); err != nil {
					t.Fatal(err)
				}
			}

			// Host A syncs: MUST fence (superseded) and KEEP local snapshot + cached hold key!
			if _, err := a.manager.SyncRemote(bg); err != nil {
				t.Fatal(err)
			}
			after := a.get(t, runID)
			if after.Remote == nil || after.Remote.State != run.RemoteSuperseded || !after.Remote.Local {
				t.Fatalf("after forged %s sync: remote = %+v, want superseded+local", forgedState, after.Remote)
			}
			if has, err := a.service.HasLocal(bg, snapRef); err != nil || !has {
				t.Fatalf("local snapshot was erased on forged %s record! has=%t err=%v", forgedState, has, err)
			}
			if present, _ := a.service.HoldKeyStatus(runID); !present {
				t.Fatalf("cached hold key was erased on forged %s record!", forgedState)
			}
			// Fenced: resume refused!
			hk2, _ := kms.mint(t, tenant, runID)
			if _, err := a.manager.ResumeWith(bg, runID, run.ResumeRequest{
				Keys:   &run.KeyBundle{Hold: &hk2},
				Bases:  a.blessed,
				Expect: &run.RemoteExpect{Generation: 1, Snapshot: stopped.Remote.Snapshot, KID: hk1.KID},
			}); !errors.Is(err, run.ErrRemoteConflict) {
				t.Fatalf("resuming fenced run: got %v, want ErrRemoteConflict", err)
			}

			// Explicit DELETE /v1/runs/{id} DOES erase both local copy and cached hold key!
			if err := a.manager.Destroy(bg, runID); err != nil {
				t.Fatalf("explicit destroy: %v", err)
			}
			if has, err := a.service.HasLocal(bg, snapRef); err != nil || has {
				t.Fatalf("local snapshot survived explicit destroy: has=%t err=%v", has, err)
			}
			if present, _ := a.service.HoldKeyStatus(runID); present {
				t.Fatal("cached hold key survived explicit destroy")
			}
			if _, err := a.source.Unwrap(tenant, runID, hk1.Wrapped); !errors.Is(err, offhost.ErrNeedKey) {
				t.Fatalf("in-memory hold key survived explicit destroy: %v", err)
			}
		})
	}
}

// Adversarial test #15: cloned state dir refuses start (ErrClonedCache); single
// damaged cache entry puts only that run in needs-key and is repaired by PushRunKeys.
func TestK3Adversarial15ClonedCacheRefusedAndDamagedEntryRepaired(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	secretPath := filepath.Join(t.TempDir(), "host-secret")

	a := newPushedHost(t, bucket, bucket, "host-a", nil, secretPath)
	stateDir := a.stateDir
	const tenant = "org-cache"
	r1 := run.NewULID(time.Now())
	r2 := run.NewULID(time.Now().Add(time.Millisecond))
	hk1, _ := kms.mint(t, tenant, r1)
	hk2, _ := kms.mint(t, tenant, r2)

	for _, pair := range []struct {
		id string
		hk run.PushedKey
	}{{r1, hk1}, {r2, hk2}} {
		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: pair.id, Image: "golden", Tenant: tenant,
			Keys: &run.KeyBundle{Hold: copyKey(pair.hk)}, Bases: a.blessed,
		}); err != nil {
			t.Fatal(err)
		}
		a.write(t, pair.id, payload(t, 128))
		if _, err := a.manager.Stop(bg, pair.id); err != nil {
			t.Fatal(err)
		}
	}
	a.cache.Close()

	// 1. Cloned state dir with another host's secret -> ErrClonedCache!
	otherSecret := make([]byte, hostsecret.Size)
	_, _ = rand.Read(otherSecret)
	if _, err := offhost.OpenHoldCache(filepath.Join(stateDir, offhost.HoldCacheFileName), otherSecret); !errors.Is(err, offhost.ErrClonedCache) {
		t.Fatalf("cloned state dir: got %v, want ErrClonedCache", err)
	}

	// 2. Corrupt ONLY r1's entry in hold-keys.json.
	cachePath := filepath.Join(stateDir, offhost.HoldCacheFileName)
	rawFile, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(rawFile, &doc); err != nil {
		t.Fatal(err)
	}
	entries := doc["entries"].(map[string]any)
	entries[r1] = map[string]any{"tenant": tenant, "kid": hk1.KID, "wrapped": hk1.Wrapped, "sealed": "corrupted-ciphertext"}
	edited, _ := json.Marshal(doc)
	if err := os.WriteFile(cachePath, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	// Restart daemon with original host secret -> starts, r2 intact, r1 is needs-key!
	a2 := newPushedHost(t, bucket, bucket, "host-a", a, secretPath)
	v1 := a2.get(t, r1)
	v2 := a2.get(t, r2)
	if v1.Remote == nil || v1.Remote.State != run.RemoteNeedsKey || !v1.Remote.Local {
		t.Fatalf("damaged run r1 after restart: %+v, want needs-key+local", v1.Remote)
	}
	if v2.Remote == nil || v2.Remote.State != run.RemoteDurable {
		t.Fatalf("intact run r2 after restart: %+v, want durable", v2.Remote)
	}

	// Repair r1 by pushing its hold key via PushRunKeys -> clears needs-key and
	// restores RemoteDurable WITHOUT bumping remote generation (S3)!
	genBeforeRepair := v1.Remote.Generation
	durableAtBefore := v1.Remote.DurableAt
	if durableAtBefore == nil {
		t.Fatal("needs-key lost DurableAt from prior durable state")
	}
	repaired, err := a2.manager.PushRunKeys(bg, r1, run.PushKeysRequest{Hold: &hk1})
	if err != nil {
		t.Fatalf("PushRunKeys repair: %v", err)
	}
	if repaired.Remote == nil || repaired.Remote.State != run.RemoteDurable || repaired.Remote.KID != hk1.KID {
		t.Fatalf("repaired r1 remote state: %+v, want durable", repaired.Remote)
	}
	if repaired.Remote.Generation != genBeforeRepair {
		t.Fatalf("repairing already-durable run bumped generation from %d to %d", genBeforeRepair, repaired.Remote.Generation)
	}
	if present, damaged := a2.service.HoldKeyStatus(r1); !present || damaged {
		t.Fatalf("r1 cache status after repair: present=%t damaged=%t", present, damaged)
	}
}

// Adversarial test #19: Cloud unreachable — stop, restart, pending upload, and
// collection all succeed using HoldCache + persisted RemoteBases with zero Cloud calls.
func TestK3Adversarial19CloudUnreachableStopRestartPendingUploadCollect(t *testing.T) {
	bucket := offhosttest.NewMemory()
	flaky := &k3FailingObjects{inner: bucket}
	kms := newTrackedCloudKMS()
	secretPath := filepath.Join(t.TempDir(), "host-secret")

	a := newPushedHost(t, bucket, flaky, "host-a", nil, secretPath)
	const tenant = "org-offline"
	runID := run.NewULID(time.Now())
	hk1, _ := kms.mint(t, tenant, runID)
	if _, err := a.manager.Create(bg, run.CreateRequest{
		ID: runID, Image: "golden", Tenant: tenant,
		Keys: &run.KeyBundle{Hold: &hk1}, Bases: a.blessed,
	}); err != nil {
		t.Fatal(err)
	}
	a.write(t, runID, payload(t, 144))

	// S3 fails during stop so the stop stays local/failed (pending retry).
	flaky.fail.Store(true)
	stopped, err := a.manager.Stop(bg, runID)
	if err != nil {
		t.Fatalf("stop during outage: %v", err)
	}
	if stopped.Remote == nil || stopped.Remote.State != run.RemoteFailed || !stopped.Remote.Local {
		t.Fatalf("stopped during outage: %+v", stopped.Remote)
	}
	a.cache.Close()

	// Daemon restarts with Cloud completely absent (zero keys pushed after restart!),
	// S3 comes back, and Maintain finishes the pending upload + collection succeeds!
	flaky.fail.Store(false)
	restarted := newPushedHost(t, bucket, flaky, "host-a", a, secretPath)
	restarted.manager.Maintain(bg)
	after := restarted.get(t, runID)
	if after.Remote == nil || after.Remote.State != run.RemoteDurable || after.Remote.KID != hk1.KID || after.Remote.Tenant != tenant {
		t.Fatalf("after restart + maintain with Cloud absent: %+v, want durable", after.Remote)
	}
	if err := restarted.manager.CollectRemote(bg); err != nil {
		t.Fatalf("collection with Cloud absent: %v", err)
	}
}

// B1 regression test: H1 held run under K1, H2 stopped it at S2 under K2,
// H3 resumed under K3 (writing RecordRunning pinning K2 + S2 stream hash) and
// died. H1 still has K1 and bucket access and rewrites S2's manifest+chunks
// under K1. H4 takes over with expect.kid=K3 (even if Cloud supplies K1+K3 in
// keys.open): H4 MUST refuse the forged S2 because the authenticated pin in
// RecordRunning requires K2 and S2's original stream hash!
func TestK3TakeoverFromRunningRefusesForgedTipSnapshot(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	h1 := newPushedHost(t, bucket, bucket, "host-1", nil, "")
	h2 := newPushedHost(t, bucket, bucket, "host-2", nil, "")
	h3 := newPushedHost(t, bucket, bucket, "host-3", nil, "")
	h4 := newPushedHost(t, bucket, bucket, "host-4", nil, "")
	allBases := mergeBlessed(h1.blessed, h2.blessed, h3.blessed, h4.blessed)
	h1.blessed, h2.blessed, h3.blessed, h4.blessed = allBases, allBases, allBases, allBases

	const tenant = "org-b1"
	runID := run.NewULID(time.Now())
	k1, hk1 := kms.mint(t, tenant, runID)
	defer hk1.Zero()
	k2, _ := kms.mint(t, tenant, runID)
	k3, _ := kms.mint(t, tenant, runID)
	k4, _ := kms.mint(t, tenant, runID)

	// 1. H1 creates and stops under K1 (gen 1).
	if _, err := h1.manager.Create(bg, run.CreateRequest{
		ID: runID, Image: "golden", Tenant: tenant,
		Keys: &run.KeyBundle{Hold: copyKey(k1)}, Bases: allBases,
	}); err != nil {
		t.Fatal(err)
	}
	h1.write(t, runID, payload(t, 128))
	s1, err := h1.manager.Stop(bg, runID)
	if err != nil {
		t.Fatal(err)
	}

	// 2. H2 resumes under K2 (passing K1 to open S1), writes real data, stops at S2 under K2 (gen 3).
	if _, err := h2.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(k2), Open: copyKeys(k1)},
		Bases:  allBases,
		Expect: &run.RemoteExpect{Generation: s1.Remote.Generation, Snapshot: s1.Remote.Snapshot, KID: k1.KID},
	}); err != nil {
		t.Fatalf("H2 resume: %v", err)
	}
	realData := payload(t, 160)
	h2.write(t, runID, realData)
	s2, err := h2.manager.Stop(bg, runID)
	if err != nil {
		t.Fatal(err)
	}

	// 3. H3 resumes under K3 (passing K1+K2 to open S2 chain), writing RecordRunning at gen 4, then "dies".
	if _, err := h3.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(k3), Open: copyKeys(k2, k1)},
		Bases:  allBases,
		Expect: &run.RemoteExpect{Generation: s2.Remote.Generation, Snapshot: s2.Remote.Snapshot, KID: k2.KID},
	}); err != nil {
		t.Fatalf("H3 resume: %v", err)
	}

	// S9 sub-check: takeover at equal generation with wrong expect.snapshot is refused!
	if _, err := h4.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(k4), Open: copyKeys(k3, k2, k1)},
		Bases:    allBases,
		Expect:   &run.RemoteExpect{Generation: 4, Snapshot: "wrong-snapshot-id", KID: k3.KID},
	}); !errors.Is(err, run.ErrRemoteConflict) {
		t.Fatalf("takeover at equal gen with wrong snapshot: got %v, want ErrRemoteConflict", err)
	}

	// Save S2's legitimate manifest bytes so we can also test legitimate takeover after the attack test.
	s2ManifestKey := "fleet/v1/snap/" + s2.Remote.Snapshot + "/manifest"
	realS2Manifest, err := bucket.Get(bg, s2ManifestKey, 1<<20)
	if err != nil {
		t.Fatalf("read legitimate S2 manifest: %v", err)
	}

	// 4. ATTACK: H1 still has K1 + bucket access and overwrites S2's manifest+chunks under K1!
	attackerKeys, _ := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
	attackerStore := offhost.NewStore(bucket, "fleet", attackerKeys, quietLog())
	attackerSrc := offhost.NewPushedKeySource()
	if err := attackerSrc.Supply(hk1); err != nil {
		t.Fatal(err)
	}
	attackerStore.SetKeySource(attackerSrc)
	attackerStore.SetPushed(true)
	if err := attackerStore.Probe(bg); err != nil {
		t.Fatal(err)
	}
	if err := bucket.Delete(bg, s2ManifestKey); err != nil {
		t.Fatal(err)
	}
	forgedStream := bytes.NewReader([]byte("forged-disk-stream-payload-from-past-holder-h1"))
	if _, err := attackerStore.UploadV2(bg, offhost.Manifest{
		ID:      s2.Remote.Snapshot,
		Purpose: offhost.PurposeStop,
		Run:     runID,
		Tenant:  tenant,
		GUID:    "forged-guid-1234",
	}, &hk1, forgedStream); err != nil {
		t.Fatalf("attacker UploadV2 forged S2: %v", err)
	}

	// 5. H4 attempts takeover with expect.kid=K3 (and even passes K1+K2+K3 in keys.open).
	// MUST BE REFUSED with ErrCorrupt (kid mismatch) because RecordRunning's authenticated pin requires K2 + real stream hash!
	if _, err := h4.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(k4), Open: copyKeys(k3, k2, k1)},
		Bases:    allBases,
		Expect:   &run.RemoteExpect{Generation: 4, KID: k3.KID},
	}); !errors.Is(err, offhost.ErrCorrupt) || !strings.Contains(err.Error(), k2.KID) {
		t.Fatalf("B1: H4 takeover with forged S2: got %v, want ErrCorrupt naming expected kid %s", err, k2.KID)
	}

	// 5b. Also check when H4 ALREADY has S2 locally (e.g. H2 itself takes over from H3 while S2 is forged in bucket):
	// checkLocalTipExpect MUST ALSO refuse the forged manifest!
	k2b, _ := kms.mint(t, tenant, runID)
	if _, err := h2.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(k2b), Open: copyKeys(k3, k2, k1)},
		Bases:    allBases,
		Expect:   &run.RemoteExpect{Generation: 4, KID: k3.KID},
	}); !errors.Is(err, offhost.ErrCorrupt) || !strings.Contains(err.Error(), k2.KID) {
		t.Fatalf("B1 (local S2 copy): H2 takeover with forged S2 in bucket: got %v, want ErrCorrupt naming %s", err, k2.KID)
	}

	// 6. Restore legitimate S2 manifest -> legitimate H4 takeover SUCCEEDS and boots realData!
	if err := bucket.Put(bg, s2ManifestKey, realS2Manifest, s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h4.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(k4), Open: copyKeys(k3, k2, k1)},
		Bases:    allBases,
		Expect:   &run.RemoteExpect{Generation: 4, Snapshot: s2.Remote.Snapshot, KID: k3.KID},
	}); err != nil {
		t.Fatalf("legitimate H4 takeover from running record failed: %v", err)
	}
	if got := h4.read(t, runID); !bytes.Equal(got, realData) {
		t.Fatalf("H4 takeover restored wrong bytes")
	}

	// 7. Unpinned v2 RecordRunning (no RemotePinKID/RemotePinSHA256 in sealed payload):
	// takeover MUST fail closed with ErrRemoteConflict!
	kUnpinned, hkUnpinned := kms.mint(t, tenant, runID)
	defer hkUnpinned.Zero()
	if err := attackerStore.AdvanceV2(bg, offhost.Record{
		Run: runID, Generation: 6, State: offhost.RecordRunning, Snapshot: s2.Remote.Snapshot,
		Payload: []byte(`{"id":"` + runID + `","state":"stopped","image":"golden","network":"none","user":"root","onExpire":"destroy","limits":{"memoryMb":1024,"cpus":1,"pids":256}}`),
		Tenant:  tenant,
	}, &hkUnpinned, "host-unpinned", false); err != nil {
		t.Fatalf("write unpinned RecordRunning: %v", err)
	}
	h5 := newPushedHost(t, bucket, bucket, "host-5", nil, "")
	h5.blessed = allBases
	k5, _ := kms.mint(t, tenant, runID)
	if _, err := h5.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(k5), Open: copyKeys(kUnpinned, k2, k1)},
		Bases:    allBases,
		Expect:   &run.RemoteExpect{Generation: 6, KID: kUnpinned.KID},
	}); !errors.Is(err, run.ErrRemoteConflict) || !strings.Contains(err.Error(), "snapshot pin") {
		t.Fatalf("takeover from unpinned v2 RecordRunning: got %v, want ErrRemoteConflict mentioning snapshot pin", err)
	}
}

// M1 regression test: attacker swaps S2's manifest in S3 to a forged manifest
// under K1 AFTER H3 finishes reading S2's manifest and starts pulling its
// chunks (before H3 seals RecordRunning under K3). Because H3 seals the pin
// returned by the single verified EnsureCustody call (no second manifest read),
// H3's RecordRunning STILL pins (K2, realSHA) and H4's takeover STILL refuses
// the forged S2!
func TestK3M1ManifestSwapRaceDuringPullCannotPoisonRunningPin(t *testing.T) {
	bucket := offhosttest.NewMemory()
	kms := newTrackedCloudKMS()
	h1 := newPushedHost(t, bucket, bucket, "host-1", nil, "")
	h2 := newPushedHost(t, bucket, bucket, "host-2", nil, "")
	h4 := newPushedHost(t, bucket, bucket, "host-4", nil, "")

	const tenant = "org-m1"
	runID := run.NewULID(time.Now())
	k1, hk1 := kms.mint(t, tenant, runID)
	defer hk1.Zero()
	k2, _ := kms.mint(t, tenant, runID)
	k3, _ := kms.mint(t, tenant, runID)
	k4, _ := kms.mint(t, tenant, runID)

	// Prepare H3 with a swap-on-chunk-read Objects wrapper.
	swapper := &swapManifestOnChunkRead{inner: bucket}
	h3 := newPushedHost(t, bucket, swapper, "host-3", nil, "")
	allBases := mergeBlessed(h1.blessed, h2.blessed, h3.blessed, h4.blessed)
	h1.blessed, h2.blessed, h3.blessed, h4.blessed = allBases, allBases, allBases, allBases

	// H1 creates + stops at S1 under K1.
	if _, err := h1.manager.Create(bg, run.CreateRequest{
		ID: runID, Image: "golden", Tenant: tenant,
		Keys: &run.KeyBundle{Hold: copyKey(k1)}, Bases: allBases,
	}); err != nil {
		t.Fatal(err)
	}
	h1.write(t, runID, payload(t, 128))
	s1, err := h1.manager.Stop(bg, runID)
	if err != nil {
		t.Fatal(err)
	}

	// H2 resumes under K2, writes real data, stops at S2 under K2.
	if _, err := h2.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(k2), Open: copyKeys(k1)},
		Bases:  allBases,
		Expect: &run.RemoteExpect{Generation: s1.Remote.Generation, Snapshot: s1.Remote.Snapshot, KID: k1.KID},
	}); err != nil {
		t.Fatal(err)
	}
	h2.write(t, runID, payload(t, 160))
	s2, err := h2.manager.Stop(bg, runID)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker pre-uploads forged S2 chunks under a new attempt and prepares forged manifest bytes.
	s2ManifestKey := "fleet/v1/snap/" + s2.Remote.Snapshot + "/manifest"
	realS2Manifest, err := bucket.Get(bg, s2ManifestKey, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	attackerKeys, _ := offhost.NewKeyring(bytes.Repeat([]byte{7}, offhost.KeySize))
	attackerStore := offhost.NewStore(bucket, "fleet", attackerKeys, quietLog())
	attackerSrc := offhost.NewPushedKeySource()
	if err := attackerSrc.Supply(hk1); err != nil {
		t.Fatal(err)
	}
	attackerStore.SetKeySource(attackerSrc)
	attackerStore.SetPushed(true)
	if err := attackerStore.Probe(bg); err != nil {
		t.Fatal(err)
	}
	if err := bucket.Delete(bg, s2ManifestKey); err != nil {
		t.Fatal(err)
	}
	if _, err := attackerStore.UploadV2(bg, offhost.Manifest{
		ID: s2.Remote.Snapshot, Purpose: offhost.PurposeStop, Run: runID, Tenant: tenant, GUID: "forged-m1-guid",
	}, &hk1, bytes.NewReader([]byte("forged-m1-stream"))); err != nil {
		t.Fatal(err)
	}
	forgedS2Manifest, err := bucket.Get(bg, s2ManifestKey, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the real S2 manifest before H3 begins its resume, and arm the swapper
	// so the manifest is swapped to forgedS2Manifest the instant H3 reads an S2 chunk!
	if err := bucket.Put(bg, s2ManifestKey, realS2Manifest, s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	swapper.chunkPrefix = "fleet/v1/snap/" + s2.Remote.Snapshot + "/"
	swapper.manifestKey = s2ManifestKey
	swapper.forgedManifest = forgedS2Manifest

	// H3 resumes under K3 (with K2, K1 in keys.open). During chunk pull, swapper
	// overwrites S2's manifest with forgedS2Manifest!
	if _, err := h3.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Keys:   &run.KeyBundle{Hold: copyKey(k3), Open: copyKeys(k2, k1)},
		Bases:  allBases,
		Expect: &run.RemoteExpect{Generation: s2.Remote.Generation, Snapshot: s2.Remote.Snapshot, KID: k2.KID},
	}); err != nil {
		t.Fatalf("H3 resume: %v", err)
	}
	if !swapper.swapped.Load() {
		t.Fatal("test setup bug: manifest swap did not fire during H3's chunk pull")
	}

	// Now S2's manifest in S3 IS forgedS2Manifest (under K1). H4 takes over from H3's
	// RecordRunning (gen 4, under K3) passing K3, K2, K1 in keys.open: MUST BE REFUSED
	// because H3 sealed the real K2 pin from its single verified EnsureCustody read!
	if _, err := h4.manager.ResumeWith(bg, runID, run.ResumeRequest{
		Takeover: true,
		Keys:     &run.KeyBundle{Hold: copyKey(k4), Open: copyKeys(k3, k2, k1)},
		Bases:    allBases,
		Expect:   &run.RemoteExpect{Generation: 4, KID: k3.KID},
	}); !errors.Is(err, offhost.ErrCorrupt) || !strings.Contains(err.Error(), k2.KID) {
		t.Fatalf("M1 race: H4 takeover with swapped manifest got %v, want ErrCorrupt naming %s", err, k2.KID)
	}
}

type swapManifestOnChunkRead struct {
	inner          offhost.Objects
	chunkPrefix    string
	manifestKey    string
	forgedManifest []byte
	swapped        atomic.Bool
}

func (s *swapManifestOnChunkRead) maybeSwap(ctx context.Context, key string) {
	if s.chunkPrefix != "" && strings.HasPrefix(key, s.chunkPrefix) && key != s.manifestKey {
		if s.swapped.CompareAndSwap(false, true) {
			_ = s.inner.Put(ctx, s.manifestKey, s.forgedManifest, s3.PutOptions{})
		}
	}
}
func (s *swapManifestOnChunkRead) Put(ctx context.Context, key string, body []byte, opts s3.PutOptions) error {
	return s.inner.Put(ctx, key, body, opts)
}
func (s *swapManifestOnChunkRead) Get(ctx context.Context, key string, limit int64) ([]byte, error) {
	s.maybeSwap(ctx, key)
	return s.inner.Get(ctx, key, limit)
}
func (s *swapManifestOnChunkRead) GetWithETag(ctx context.Context, key string, limit int64) ([]byte, string, error) {
	s.maybeSwap(ctx, key)
	return s.inner.GetWithETag(ctx, key, limit)
}
func (s *swapManifestOnChunkRead) Head(ctx context.Context, key string) (s3.Object, error) {
	return s.inner.Head(ctx, key)
}
func (s *swapManifestOnChunkRead) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}
func (s *swapManifestOnChunkRead) DeleteIfMatch(ctx context.Context, key, etag string) error {
	return s.inner.DeleteIfMatch(ctx, key, etag)
}
func (s *swapManifestOnChunkRead) Walk(ctx context.Context, prefix string, each func(s3.Object) error) error {
	return s.inner.Walk(ctx, prefix, each)
}

// S1, S2, S4, S5, S6 regression tests for K3 review fixes.
func TestK3ReviewFixesS1ToS6(t *testing.T) {
	t.Run("S1_PushRunKeys_guards_and_raw_verification", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		kms := newTrackedCloudKMS()
		a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
		const tenant = "org-s1"
		runID := run.NewULID(time.Now())
		k1, _ := kms.mint(t, tenant, runID)
		kOther, _ := kms.mint(t, tenant, runID)

		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: runID, Image: "golden", Tenant: tenant,
			Keys: &run.KeyBundle{Hold: copyKey(k1)}, Bases: a.blessed,
		}); err != nil {
			t.Fatal(err)
		}
		// Running run with mode="repair" -> refused with ErrRunning!
		if _, err := a.manager.PushRunKeys(bg, runID, run.PushKeysRequest{Hold: copyKey(k1), Mode: "repair"}); !errors.Is(err, run.ErrRunning) {
			t.Fatalf("PushRunKeys repair on running run: got %v, want ErrRunning", err)
		}
		if _, err := a.manager.Stop(bg, runID); err != nil {
			t.Fatal(err)
		}
		// Different kid on stopped run -> refused with ErrRemoteConflict!
		if _, err := a.manager.PushRunKeys(bg, runID, run.PushKeysRequest{Hold: copyKey(kOther)}); !errors.Is(err, run.ErrRemoteConflict) {
			t.Fatalf("PushRunKeys with different kid: got %v, want ErrRemoteConflict", err)
		}
		// Right kid + wrapped blob, WRONG raw bytes -> refused with ErrBadRequest!
		wrongRaw := k1
		wrongRaw.Raw = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
		if _, err := a.manager.PushRunKeys(bg, runID, run.PushKeysRequest{Hold: &wrongRaw}); !errors.Is(err, run.ErrBadRequest) {
			t.Fatalf("PushRunKeys with wrong raw bytes: got %v, want ErrBadRequest", err)
		}
	})

	t.Run("S2_FailedSameHostResume_rolls_back_hold_key", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		flaky := &k3FailingObjects{inner: bucket}
		kms := newTrackedCloudKMS()
		a := newPushedHost(t, bucket, flaky, "host-a", nil, "")
		const tenant = "org-s2"
		runID := run.NewULID(time.Now())
		k1, _ := kms.mint(t, tenant, runID)
		k2, _ := kms.mint(t, tenant, runID)

		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: runID, Image: "golden", Tenant: tenant,
			Keys: &run.KeyBundle{Hold: copyKey(k1)}, Bases: a.blessed,
		}); err != nil {
			t.Fatal(err)
		}
		stopped, err := a.manager.Stop(bg, runID)
		if err != nil {
			t.Fatal(err)
		}
		// Fail S3 Advance during claimHeld by making bucket fail? Wait: refreshRemote also calls S3.
		// Simulate a claim conflict by advancing gen 2 in the bucket AFTER stopped, Wait: refreshRemote sees gen 2!
		// Instead, supply a wrong key? No, resume with a read-only cache or simulate conflict on Advance:
		// Use a wrapper that fails only Put (Advance) while allowing Get/Head/Walk (reconcile + checkLocalTipExpect)!
		a.manager.OffHost = &putFailCustodyService{Service: a.service}
		if _, err := a.manager.ResumeWith(bg, runID, run.ResumeRequest{
			Keys:   &run.KeyBundle{Hold: copyKey(k2)},
			Bases:  a.blessed,
			Expect: &run.RemoteExpect{Generation: stopped.Remote.Generation, Snapshot: stopped.Remote.Snapshot, KID: k1.KID},
		}); err == nil {
			t.Fatal("expected resume to fail when Advance fails")
		}
		// Old key K1 MUST still be in HoldCache and on live run, and K2 must be gone!
		after := a.get(t, runID)
		if after.Remote.KID != k1.KID {
			t.Fatalf("live remoteKID after failed resume = %s, want rolled back to %s", after.Remote.KID, k1.KID)
		}
		cached, ok := a.cache.Get(runID)
		if !ok {
			t.Fatal("HoldCache lost key after failed resume")
		}
		defer cached.Zero()
		if cached.KID != k1.KID {
			t.Fatalf("HoldCache KID after failed resume = %s, want rolled back to %s", cached.KID, k1.KID)
		}
		if _, err := a.source.Unwrap(tenant, runID, k2.Wrapped); !errors.Is(err, offhost.ErrNeedKey) {
			t.Fatalf("new key K2 leaked into PushedKeySource after failed resume: %v", err)
		}
		if hk, err := a.source.Unwrap(tenant, runID, k1.Wrapped); err != nil {
			t.Fatalf("old key K1 missing from PushedKeySource after rollback: %v", err)
		} else {
			hk.Zero()
		}
	})

	t.Run("S4_PutHoldKey_atomic_and_ReconcileHoldKeys_prunes_orphans", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		kms := newTrackedCloudKMS()
		secretPath := filepath.Join(t.TempDir(), "host-secret")
		a := newPushedHost(t, bucket, bucket, "host-a", nil, secretPath)
		const tenant = "org-s4"
		orphanID := run.NewULID(time.Now())
		kOrphan, _ := kms.mint(t, tenant, orphanID)
		// Put an orphan key directly into HoldCache (simulating crash between PutHoldKey and launch).
		if _, _, err := a.service.PutHoldKey(tenant, orphanID, kOrphan); err != nil {
			t.Fatal(err)
		}
		// Now try PutHoldKey with same KID for another run / different raw bytes -> ps.Supply fails -> HoldCache MUST roll back!
		otherID := run.NewULID(time.Now().Add(time.Millisecond))
		badDup := kOrphan
		badDup.Run = otherID
		badDup.Raw = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32))
		if _, _, err := a.service.PutHoldKey(tenant, otherID, badDup); err == nil {
			t.Fatal("expected PutHoldKey with duplicate kid for another run to fail")
		}
		if hk, ok := a.cache.Get(otherID); ok {
			hk.Zero()
			t.Fatal("PutHoldKey left partial entry in HoldCache after failure")
		}
		// Restart: ReconcileHoldKeys MUST prune orphanID from HoldCache and PushedKeySource!
		a.cache.Close()
		a2 := newPushedHost(t, bucket, bucket, "host-a", a, secretPath)
		if hk, ok := a2.cache.Get(orphanID); ok {
			hk.Zero()
			t.Fatal("orphaned HoldCache entry survived restart")
		}
		if _, err := a2.source.Unwrap(tenant, orphanID, kOrphan.Wrapped); !errors.Is(err, offhost.ErrNeedKey) {
			t.Fatalf("orphaned hold key survived in PushedKeySource after restart: %v", err)
		}
	})

	t.Run("S6_CreateFromLocalSnapshot_requires_expect_and_checks_tenant", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		kms := newTrackedCloudKMS()
		a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
		runA := run.NewULID(time.Now())
		hkA, _ := kms.mint(t, "org-a", runA)
		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: runA, Image: "golden", Tenant: "org-a",
			Keys: &run.KeyBundle{Hold: copyKey(hkA)}, Bases: a.blessed,
		}); err != nil {
			t.Fatal(err)
		}
		snapRef, _, err := a.manager.SnapshotRemote(bg, runA)
		if err != nil {
			t.Fatal(err)
		}
		// 1. Local snapshot without expect in pushed mode -> 400 ErrBadRequest!
		runA2 := run.NewULID(time.Now().Add(time.Millisecond))
		hkA2, _ := kms.mint(t, "org-a", runA2)
		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: runA2, Image: snapRef, Tenant: "org-a",
			Keys: &run.KeyBundle{Hold: copyKey(hkA2)}, Bases: a.blessed,
		}); !errors.Is(err, run.ErrBadRequest) {
			t.Fatalf("create from local snapshot without expect: got %v, want ErrBadRequest", err)
		}
		// 2. Cross-tenant create from local snapshot -> 400 ErrBadRequest!
		runB := run.NewULID(time.Now().Add(2 * time.Millisecond))
		hkB, _ := kms.mint(t, "org-b", runB)
		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: runB, Image: snapRef, Tenant: "org-b",
			Keys:   &run.KeyBundle{Hold: copyKey(hkB)},
			Bases:  a.blessed,
			Expect: &run.RemoteExpect{KID: hkA.KID},
		}); !errors.Is(err, run.ErrBadRequest) {
			t.Fatalf("cross-tenant create from local snapshot: got %v, want ErrBadRequest", err)
		}
		// 3. Same-tenant create from local snapshot with matching expect -> succeeds!
		if _, err := a.manager.Create(bg, run.CreateRequest{
			ID: runA2, Image: snapRef, Tenant: "org-a",
			Keys:   &run.KeyBundle{Hold: copyKey(hkA2)},
			Bases:  a.blessed,
			Expect: &run.RemoteExpect{KID: hkA.KID},
		}); err != nil {
			t.Fatalf("valid same-tenant create from local snapshot: %v", err)
		}
	})

	t.Run("S5_ConcurrentSameIDCreate_one_wins_and_key_survives", func(t *testing.T) {
		bucket := offhosttest.NewMemory()
		kms := newTrackedCloudKMS()
		a := newPushedHost(t, bucket, bucket, "host-a", nil, "")
		const tenant = "org-s5"
		runID := run.NewULID(time.Now())
		k1, _ := kms.mint(t, tenant, runID)
		k2, _ := kms.mint(t, tenant, runID)

		results := make(chan error, 2)
		start := make(chan struct{})
		for _, k := range []run.PushedKey{k1, k2} {
			keyCopy := k
			go func() {
				<-start
				_, err := a.manager.Create(bg, run.CreateRequest{
					ID: runID, Image: "golden", Tenant: tenant,
					Keys: &run.KeyBundle{Hold: copyKey(keyCopy)}, Bases: a.blessed,
				})
				results <- err
			}()
		}
		close(start)
		err1, err2 := <-results, <-results
		wins, busy := 0, 0
		for _, e := range []error{err1, err2} {
			if e == nil {
				wins++
			} else if errors.Is(e, run.ErrBusy) {
				busy++
			} else {
				t.Fatalf("unexpected error from concurrent same-ID create: %v", e)
			}
		}
		if wins != 1 || busy != 1 {
			t.Fatalf("concurrent same-ID create: wins=%d busy=%d (errs: %v, %v); want 1 win and 1 ErrBusy", wins, busy, err1, err2)
		}
		// Winner's hold key MUST still be intact in HoldCache!
		if present, damaged := a.service.HoldKeyStatus(runID); !present || damaged {
			t.Fatalf("winner hold key damaged/missing after loser failed: present=%t damaged=%t", present, damaged)
		}
	})
}

type putFailCustodyService struct {
	*offhost.Service
}

func (p *putFailCustodyService) Advance(context.Context, run.RemoteRecord) (string, error) {
	return "", errors.New("simulated advance failure")
}
