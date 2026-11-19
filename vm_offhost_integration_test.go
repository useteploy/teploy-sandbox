//go:build vmintegration

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/run"
	"github.com/useteploy/teploy-sandbox/internal/s3"
	"github.com/useteploy/teploy-sandbox/internal/vm"
)

// The off-host suite: two daemons on one machine, each with its own
// identity, state directory and ZFS pool, sharing one bucket on a real
// S3-compatible service. The first daemon's pool is created for the test
// and destroyed in the middle of it, which is what losing a host is.
//
// It needs what the rest of the vm suite needs, and:
//
//	SBX_S3_TEST_ENDPOINT, SBX_S3_TEST_BUCKET, SBX_S3_TEST_ACCESS_KEY,
//	SBX_S3_TEST_SECRET_KEY   the service (path-style addressing)
//	SBX_S3_TEST_DATA         optional: the directory a file-backed
//	                         service keeps its objects in, searched for
//	                         guest data in the clear
//	SBX_OFFHOST_MB           guest data per run, in MiB (default 300)
//	SBX_OFFHOST_POOL_FILE    where the first daemon's pool file goes
//	                         (default /var/tmp/sbx-offhost-pool.img)
//
// Without SBX_S3_TEST_ENDPOINT it is skipped.

const offHostPool = "sbxoffhost"

// offHostMarker is written into the guest's disk many times over; it must
// not be found anywhere in the bucket.
const offHostMarker = "TEPLOY-OFFHOST-PLAINTEXT-MARKER-0123456789"

type offHostDaemon struct {
	name    string
	config  vm.Config
	manager *run.Manager
	driver  *vm.Driver
	service *offhost.Service
	store   *offhost.Store
	logs    *bytes.Buffer
}

func zfsCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// startOffHostDaemon is a manager on the VM driver with remote storage,
// wired as serve wires it.
func startOffHostDaemon(t *testing.T, name string, config vm.Config, objects *s3.Client, prefix string, master []byte, previous [][]byte, mutate func(*run.Manager)) *offHostDaemon {
	t.Helper()
	d := &offHostDaemon{name: name, config: config, logs: &bytes.Buffer{}}
	log := slog.New(slog.NewTextHandler(&lockedWriter{w: d.logs}, nil))
	driver, err := vm.New(context.Background(), config, log)
	if err != nil {
		t.Fatalf("%s: vm driver: %v", name, err)
	}
	d.driver = driver
	if _, _, err := driver.Sweep(context.Background()); err != nil {
		t.Fatalf("%s: sweep: %v", name, err)
	}
	keys, err := offhost.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range previous {
		if err := keys.AddPrevious(old); err != nil {
			t.Fatal(err)
		}
	}
	d.store = offhost.NewStore(objects, prefix, keys, log)
	if err := d.store.Probe(context.Background()); err != nil {
		t.Fatalf("%s: probe: %v", name, err)
	}
	if !d.store.Conditional() {
		t.Fatalf("%s: the service has no conditional writes; the suite's race test needs them", name)
	}
	// No grace: what the suite destroys, its next collection deletes.
	d.service = offhost.NewService(d.store, driver.Transfer(), offhost.Config{Daemon: name, MaxChain: offhost.DefaultMaxChain}, log)
	d.manager = run.NewManager(driver, log)
	d.manager.SandboxUser = ""
	d.manager.OffHost = d.service
	if mutate != nil {
		mutate(d.manager)
	}
	if _, err := d.manager.LoadState(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("%s: load state: %v", name, err)
	}
	return d
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (d *offHostDaemon) exec(t *testing.T, id, cmd string, timeout time.Duration) string {
	t.Helper()
	result := vmRun(t, d.manager, id, cmd, "", nil, timeout)
	if result.code != 0 || result.timedOut {
		t.Fatalf("%s: %q: exit %d (timed out: %t): %s", d.name, cmd, result.code, result.timedOut, result.stderr)
	}
	return strings.TrimSpace(result.stdout)
}

// digest is the SHA-256 of everything the suite put in a run.
func (d *offHostDaemon) digest(t *testing.T, id string) string {
	t.Helper()
	return d.exec(t, id, `cat /work/big.bin /work/marker.txt /work/small.bin 2>/dev/null | sha256sum | cut -d' ' -f1`, 5*time.Minute)
}

func (d *offHostDaemon) stopDurable(t *testing.T, id string) *run.Run {
	t.Helper()
	stopped, err := d.manager.Stop(context.Background(), id)
	if err != nil {
		t.Fatalf("%s: stop: %v", d.name, err)
	}
	if stopped.Remote == nil || stopped.Remote.State != run.RemoteDurable {
		t.Fatalf("%s: the stop is not durable: %+v\n%s", d.name, stopped.Remote, d.logs.String())
	}
	return stopped
}

func mib(bytes int64) string { return fmt.Sprintf("%.1f MiB", float64(bytes)/(1<<20)) }

func rate(bytes int64, took time.Duration) string {
	if took <= 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f MiB/s", float64(bytes)/(1<<20)/took.Seconds())
}

// offHostPoolA gives the first daemon a pool of its own, with a golden
// image of its own: the same bytes as the standing one, and another
// snapshot, so nothing of it is on the standing pool's host to begin
// with. The pool is destroyed and its file removed at cleanup.
func offHostPoolA(t *testing.T, configB vm.Config) vm.Config {
	t.Helper()
	poolFile := envOr("SBX_OFFHOST_POOL_FILE", "/var/tmp/sbx-offhost-pool.img")
	destroyPool := func() {
		_ = exec.Command("zpool", "destroy", "-f", offHostPool).Run()
		_ = os.Remove(poolFile)
	}
	destroyPool()
	t.Cleanup(destroyPool)
	zfsCommand(t, "truncate", "-s", "8G", poolFile)
	zfsCommand(t, "zpool", "create", "-O", "compression=lz4", "-O", "volmode=dev", offHostPool, poolFile)
	zfsCommand(t, "sh", "-c", fmt.Sprintf("zfs send %s | zfs receive %s/golden-src", configB.Golden, offHostPool))
	sourceSnapshot := offHostPool + "/golden-src@" + strings.SplitN(configB.Golden, "@", 2)[1]
	zfsCommand(t, "zfs", "clone", sourceSnapshot, offHostPool+"/golden")
	zfsCommand(t, "zfs", "snapshot", offHostPool+"/golden@v1")
	ownerA := sha256.Sum256([]byte("teploy-sandbox vmintegration suite, off-host daemon A"))
	configA := configB
	configA.Pool = offHostPool
	configA.Golden = offHostPool + "/golden@v1"
	configA.Owner = hex.EncodeToString(ownerA[:])
	configA.Cgroup = vm.DefaultCgroup + "-offhost"
	configA.UIDBase = vm.DefaultUIDBase + 2*vm.UIDCount
	configA.Subnet = "10.213.0.0/16"
	configA.Warm = vm.WarmConfig{}
	if a, b := zfsCommand(t, "zfs", "get", "-Hp", "-o", "value", "guid", configA.Golden), zfsCommand(t, "zfs", "get", "-Hp", "-o", "value", "guid", configB.Golden); a == b {
		t.Fatalf("the two golden images are the same snapshot (%s)", a)
	}
	return configA
}

func TestVMOffHost(t *testing.T) {
	endpoint := os.Getenv("SBX_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("SBX_S3_TEST_ENDPOINT is not set")
	}
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	ctx := context.Background()
	dataMB := int(envFloat("SBX_OFFHOST_MB", 300))
	objects, err := s3.New(s3.Config{
		Endpoint: endpoint, Bucket: os.Getenv("SBX_S3_TEST_BUCKET"), PathStyle: true,
		Credentials: s3.Credentials{AccessKey: os.Getenv("SBX_S3_TEST_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_TEST_SECRET_KEY")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.CreateBucket(ctx); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	prefix := fmt.Sprintf("offhost-%d", time.Now().Unix())
	bucketKeys := func(under string) []s3.Object {
		t.Helper()
		listed, err := objects.ListAll(ctx, prefix+"/"+under)
		if err != nil {
			t.Fatal(err)
		}
		return listed
	}
	bucketBytes := func(under string) int64 {
		var total int64
		for _, object := range bucketKeys(under) {
			total += object.Size
		}
		return total
	}
	defer func() {
		// Whatever a failure left in the bucket.
		for _, object := range bucketKeys("") {
			_ = objects.Delete(ctx, object.Key)
		}
	}()
	master := make([]byte, offhost.KeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}

	// The second daemon is the suite's usual one: the standing pool.
	configB := vmTestConfig(t)
	// Clear what an aborted attempt left, then take the baseline.
	newVMManager(t, configB, t.TempDir())
	// The sweep removes what a registry names, and snapshot and base
	// volumes are named by registries that no longer exist anywhere: a
	// FAILED earlier run of this suite leaves orphans nothing collects
	// (the driver's documented stance: those volumes are the caller's).
	// A fresh host has none; make this one match.
	for _, kind := range []string{"teploy-snap-", "teploy-base-"} {
		for _, name := range strings.Fields(zfsCommand(t, "zfs", "list", "-H", "-r", "-o", "name", configB.Pool)) {
			if idx := strings.Index(name, "/"+kind); idx >= 0 {
				zfsCommand(t, "zfs", "destroy", "-R", name)
			}
		}
	}
	baselineB := poolListing(t, configB.Pool)

	configA := offHostPoolA(t, configB)
	thisBase := configB.Pool + "/teploy-base-" + zfsCommand(t, "zfs", "get", "-Hp", "-o", "value", "guid", configA.Golden)

	a := startOffHostDaemon(t, "daemon-a", configA, objects, prefix, master, nil, nil)
	aClosed := false
	defer func() {
		if !aClosed {
			for _, current := range a.manager.List() {
				_ = a.manager.Destroy(ctx, current.ID)
			}
			_ = a.driver.Close(ctx)
		}
	}()
	// The second daemon keeps no local copies: every resume on it after a
	// stop is a restore from the bucket.
	b := startOffHostDaemon(t, "daemon-b", configB, objects, prefix, master, nil, func(m *run.Manager) { m.LocalCache = run.LocalDrop })
	defer func() {
		for _, current := range b.manager.List() {
			_ = b.manager.Destroy(ctx, current.ID)
		}
		_ = b.driver.Close(ctx)
	}()
	limits := &run.Limits{MemoryMB: 1024, CPUs: 1}

	// --- a first, small run: its stop uploads the base image, once for
	// everybody, and it is the run the two daemons race for later.
	small, err := a.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: limits})
	if err != nil {
		t.Fatalf("create: %v\n%s", err, a.logs.String())
	}
	a.exec(t, small.ID, `echo race > /work/marker.txt && sync`, time.Minute)
	smallDigest := a.digest(t, small.ID)
	start := time.Now()
	a.stopDurable(t, small.ID)
	baseBytes := bucketBytes("v1/snap/base-")
	t.Logf("first stop of the fleet, with the base image: %s of base image stored, stop took %s", mib(baseBytes), time.Since(start).Round(time.Millisecond))
	if baseBytes == 0 {
		t.Fatal("no base image was uploaded")
	}

	// --- the run with data
	created, err := a.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: limits, Env: map[string]string{"SECRET_TOKEN": offHostMarker}, Labels: map[string]string{"suite": "offhost"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.ID
	a.exec(t, id, fmt.Sprintf(`dd if=/dev/urandom of=/work/big.bin bs=1M count=%d status=none && for i in $(seq 1 20000); do echo %s; done > /work/marker.txt && sync`, dataMB, offHostMarker), 10*time.Minute)
	digest1 := a.digest(t, id)

	start = time.Now()
	stopped := a.stopDurable(t, id)
	stopTook := time.Since(start)
	upload := time.Duration(stopped.Remote.UploadMs) * time.Millisecond
	fullStored := stopped.Remote.StoredBytes
	t.Logf("stop with %d MiB of guest data: %s stored in %s (%s), whole stop %s, incremental against a previous upload: %t",
		dataMB, mib(fullStored), upload.Round(time.Millisecond), rate(fullStored, upload), stopTook.Round(time.Millisecond), stopped.Remote.Incremental)
	if stopped.Remote.Incremental || fullStored < int64(dataMB)<<20 {
		t.Fatalf("the first stop of a run stored %s, incremental %t", mib(fullStored), stopped.Remote.Incremental)
	}
	if !stopped.Remote.Local {
		t.Fatal("daemon-a keeps local copies, and has none")
	}

	// --- encrypted at rest: no chunk holds the marker, a chunk does not
	// compress, and the run's env is not in its record.
	snapshotID := stopped.Remote.Snapshot
	chunks := bucketKeys("v1/snap/" + snapshotID + "/")
	if len(chunks) < 3 {
		t.Fatalf("the snapshot is %d objects", len(chunks))
	}
	hits, sampled := 0, 0
	var sampleKey string
	var sample []byte
	for _, object := range chunks {
		body, err := objects.Get(ctx, object.Key, object.Size)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(offHostMarker[:20])) {
			hits++
		}
		sampled++
		if sample == nil && !strings.HasSuffix(object.Key, "manifest") {
			sampleKey, sample = object.Key, body
		}
	}
	for _, object := range bucketKeys("v1/run/" + id + "/") {
		body, err := objects.Get(ctx, object.Key, object.Size)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(offHostMarker[:20])) || bytes.Contains(body, []byte("SECRET_TOKEN")) {
			t.Fatalf("the run's record %s holds its env in the clear", object.Key)
		}
	}
	var squeezed bytes.Buffer
	gz := gzip.NewWriter(&squeezed)
	_, _ = gz.Write(sample)
	_ = gz.Close()
	t.Logf("encrypted at rest: %d objects of the snapshot fetched, %d contain the marker the guest wrote 20000 times; chunk %s is %d bytes, gzip makes it %d; its first 32 bytes: %x",
		sampled, hits, strings.TrimPrefix(sampleKey, prefix+"/"), len(sample), squeezed.Len(), sample[:32])
	if hits != 0 || squeezed.Len() < len(sample)*99/100 {
		t.Fatal("guest data is readable in the bucket")
	}
	if dir := os.Getenv("SBX_S3_TEST_DATA"); dir != "" {
		// The same chunk without the client: an unsigned request is
		// refused, and the service's own file for it is not text.
		file := filepath.Join(dir, os.Getenv("SBX_S3_TEST_BUCKET"), sampleKey)
		code, _ := exec.Command("curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", endpoint+"/"+os.Getenv("SBX_S3_TEST_BUCKET")+"/"+sampleKey).Output()
		dump, _ := exec.Command("sh", "-c", "head -c 48 '"+file+"' | od -A d -t x1 | head -3").Output()
		words, _ := exec.Command("sh", "-c", "head -c 4194304 '"+file+"' | strings -n 16 | wc -l").Output()
		t.Logf("plain curl of the chunk, unsigned: HTTP %s; od of the service's file %s:\n%sstrings of 16 or more characters in its first 4 MiB: %s",
			code, file, dump, strings.TrimSpace(string(words)))
		out, _ := exec.Command("grep", "-rlF", offHostMarker[:20], filepath.Join(dir, os.Getenv("SBX_S3_TEST_BUCKET"), prefix)).CombinedOutput()
		t.Logf("grep -rlF for the marker in the service's own files under %s: %d files", dir, len(strings.Fields(string(out))))
		if len(strings.Fields(string(out))) != 0 {
			t.Fatalf("the service's files hold the marker: %s", out)
		}
	}

	// --- an incremental stop: resume here (the local copy is still
	// there), change a little, stop.
	start = time.Now()
	if _, err := a.manager.Resume(ctx, id, 0); err != nil {
		t.Fatalf("resume on the same host: %v\n%s", err, a.logs.String())
	}
	t.Logf("resume on the host that stopped it (local copy kept): %s", time.Since(start).Round(time.Millisecond))
	if got := a.digest(t, id); got != digest1 {
		t.Fatalf("bytes after a local resume: %s, want %s", got, digest1)
	}
	a.exec(t, id, `dd if=/dev/urandom of=/work/small.bin bs=1M count=4 status=none && sync`, time.Minute)
	digest2 := a.digest(t, id)
	stopped = a.stopDurable(t, id)
	incrementalStored := stopped.Remote.StoredBytes
	t.Logf("stop after 4 MiB changed: %s stored in %d ms, incremental: %t (the full upload was %s)",
		mib(incrementalStored), stopped.Remote.UploadMs, stopped.Remote.Incremental, mib(fullStored))
	if !stopped.Remote.Incremental || incrementalStored > fullStored/4 || incrementalStored < 4<<20 {
		t.Fatalf("an incremental stop stored %s", mib(incrementalStored))
	}

	// --- two daemons resume the same run at once: one running copy.
	if _, err := b.manager.SyncRemote(ctx); err != nil {
		t.Fatalf("daemon-b: sync: %v", err)
	}
	seen, err := b.manager.Get(small.ID)
	if err != nil || seen.State != run.StateStopped || seen.Remote == nil || seen.Remote.Local {
		t.Fatalf("daemon-b's view of a run stopped on daemon-a: %+v, %v", seen, err)
	}
	var wg sync.WaitGroup
	raceErrs := make([]error, 2)
	for i, d := range []*offHostDaemon{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, raceErrs[i] = d.manager.Resume(ctx, small.ID, 0)
		}()
	}
	wg.Wait()
	runningCopies := 0
	var winner *offHostDaemon
	for i, d := range []*offHostDaemon{a, b} {
		if current, err := d.manager.Get(small.ID); err == nil && current.State == run.StateRunning {
			runningCopies++
			winner = d
		}
		if raceErrs[i] != nil && !errors.Is(raceErrs[i], run.ErrRemoteConflict) {
			t.Fatalf("%s lost the race with %v, want a conflict", d.name, raceErrs[i])
		}
	}
	processes := len(hypervisorProcesses(t, configA.RunDir))
	t.Logf("two daemons resumed run %s at once: daemon-a: %v; daemon-b: %v; running copies: %d; hypervisor processes: %d",
		small.ID, raceErrs[0], raceErrs[1], runningCopies, processes)
	if runningCopies != 1 || (raceErrs[0] == nil) == (raceErrs[1] == nil) || processes != 1 {
		t.Fatalf("the race did not end with exactly one running copy\n%s\n%s", a.logs.String(), b.logs.String())
	}
	if got := winner.digest(t, small.ID); got != smallDigest {
		t.Fatalf("the raced run's bytes: %s, want %s", got, smallDigest)
	}
	// It goes back to stopped, so it is among the runs the lost host
	// leaves behind.
	winner.stopDurable(t, small.ID)

	// --- the first host is lost: its daemon gone, its pool destroyed.
	if err := a.driver.Close(ctx); err != nil {
		t.Logf("daemon-a close: %v", err)
	}
	aClosed = true
	zfsCommand(t, "zpool", "destroy", "-f", offHostPool)
	if out, _ := exec.Command("zpool", "list", "-H", "-o", "name").Output(); slices.Contains(strings.Fields(string(out)), offHostPool) {
		t.Fatal("the first daemon's pool still exists")
	}
	t.Logf("daemon-a's pool %s destroyed; pools left: %s", offHostPool, strings.Join(strings.Fields(zfsCommand(t, "zpool", "list", "-H", "-o", "name")), " "))

	// --- every stopped run resumes on the other daemon, byte-exact.
	if _, err := b.manager.SyncRemote(ctx); err != nil {
		t.Fatalf("daemon-b: sync: %v", err)
	}
	adopted, err := b.manager.Get(id)
	if err != nil || adopted.State != run.StateStopped || adopted.Remote == nil || adopted.Remote.Local || adopted.Labels["suite"] != "offhost" {
		t.Fatalf("daemon-b's view of the lost host's run: %+v, %v", adopted, err)
	}
	ref, _ := b.service.Ref(adopted.Remote.Snapshot)
	start = time.Now()
	if err := b.service.Ensure(ctx, ref); err != nil {
		t.Fatalf("restore: %v\n%s", err, b.logs.String())
	}
	restoreTook := time.Since(start)
	// Whether the base image is fetched too depends on who won the race:
	// the winner restored the raced run, base image and all, and a base
	// image that was received stays.
	// This test's base image is named by its own golden image's guid
	// (asked before the first daemon's pool is destroyed below); older
	// runs' bases, held or not, are not this test's business.
	hasBase := func() bool {
		return slices.Contains(poolListing(t, configB.Pool), thisBase)
	}
	withBase := !hasBase()
	restored := fullStored + incrementalStored
	if withBase {
		restored += baseBytes
	}
	start = time.Now()
	resumed, err := b.manager.Resume(ctx, id, 0)
	if err != nil {
		t.Fatalf("resume on daemon-b: %v\n%s", err, b.logs.String())
	}
	bootTook := time.Since(start)
	t.Logf("cold resume on daemon-b: restore of %s from the bucket in %s (%s; base image included: %t), boot %s, time to resume %s",
		mib(restored), restoreTook.Round(time.Millisecond), rate(restored, restoreTook), withBase, bootTook.Round(time.Millisecond), (restoreTook + bootTook).Round(time.Millisecond))
	if got := b.digest(t, id); got != digest2 {
		t.Fatalf("bytes on daemon-b: %s, want %s", got, digest2)
	}
	t.Logf("run %s on daemon-b: sha256 of its data %s, as written on daemon-a", resumed.ID, digest2)
	if env := b.exec(t, id, `printf %s "$SECRET_TOKEN"`, time.Minute); env != offHostMarker {
		t.Fatalf("the run's env did not come with it: %q", env)
	}
	if _, err := b.manager.Resume(ctx, small.ID, 0); err != nil {
		t.Fatalf("resume of the other run on daemon-b: %v", err)
	}
	if got := b.digest(t, small.ID); got != smallDigest {
		t.Fatalf("the other run's bytes: %s, want %s", got, smallDigest)
	}
	if err := b.manager.Destroy(ctx, small.ID); err != nil {
		t.Fatal(err)
	}

	// --- and through a fork: stop it here (durable, local copy dropped),
	// fork the stopped run, which restores the whole chain again.
	b.exec(t, id, `echo on-b >> /work/marker.txt && sync`, time.Minute)
	digest3 := b.digest(t, id)
	stopped = b.stopDurable(t, id)
	if stopped.Remote.Local || !stopped.Remote.Incremental {
		t.Fatalf("stop on daemon-b: %+v", stopped.Remote)
	}
	t.Logf("stop on daemon-b after a few bytes changed: %s stored, incremental: %t, local copy kept: %t", mib(stopped.Remote.StoredBytes), stopped.Remote.Incremental, stopped.Remote.Local)
	beforeFork := poolListing(t, configB.Pool)
	start = time.Now()
	child, err := b.manager.Fork(ctx, id, run.ForkRequest{})
	if err != nil {
		t.Fatalf("fork of a run that is only in the bucket: %v\n%s", err, b.logs.String())
	}
	if !hasBase() {
		t.Fatal("the base image this host received did not stay")
	}
	t.Logf("fork of the stopped run, restoring %s through three streams (base image already here), to a running child: %s",
		mib(fullStored+incrementalStored+stopped.Remote.StoredBytes), time.Since(start).Round(time.Millisecond))
	if got := b.digest(t, child.ID); got != digest3 {
		t.Fatalf("the fork's bytes: %s, want %s", got, digest3)
	}
	t.Logf("fork %s: sha256 of its data %s, as the source was stopped", child.ID, digest3)
	if err := b.manager.Destroy(ctx, child.ID); err != nil {
		t.Fatal(err)
	}
	if got := poolListing(t, configB.Pool); !slices.Equal(got, beforeFork) {
		// The fork kept the source's snapshot on the host; with the child
		// gone only the stopped source may still hold it.
		t.Logf("pool after the fork was destroyed: %v", got)
	}

	// --- damage: a tampered chunk, then a deleted one. The restore fails
	// and the pool is as it was.
	for _, current := range b.manager.List() {
		if current.ID != id {
			t.Fatalf("an unexpected run on daemon-b: %+v", current)
		}
	}
	// Drop what the fork left, so the next resume has to fetch.
	stoppedRef, _ := b.service.Ref(stopped.Remote.Snapshot)
	if has, _ := b.service.HasLocal(ctx, stoppedRef); has {
		if err := b.driver.RemoveImage(ctx, stoppedRef); err != nil {
			t.Fatalf("drop the local copy: %v", err)
		}
	}
	clean := poolListing(t, configB.Pool)
	target := chunks[len(chunks)/2]
	if strings.HasSuffix(target.Key, "manifest") {
		target = chunks[0]
	}
	original, err := objects.Get(ctx, target.Key, target.Size)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(original)
	tampered[len(tampered)/2] ^= 0x01
	if err := objects.Put(ctx, target.Key, tampered, s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err = b.manager.Resume(ctx, id, 0)
	t.Logf("resume with one bit flipped in %s: %v", strings.TrimPrefix(target.Key, prefix+"/"), err)
	if err == nil || !errors.Is(err, offhost.ErrCorrupt) {
		t.Fatalf("a resume from a tampered chunk: %v", err)
	}
	if got := poolListing(t, configB.Pool); !slices.Equal(got, clean) {
		t.Fatalf("a failed restore left something in the pool:\n%v\nwant\n%v", got, clean)
	}
	if err := objects.Delete(ctx, target.Key); err != nil {
		t.Fatal(err)
	}
	_, err = b.manager.Resume(ctx, id, 0)
	t.Logf("resume with that chunk deleted: %v", err)
	if err == nil || !errors.Is(err, offhost.ErrCorrupt) {
		t.Fatalf("a resume with a chunk missing: %v", err)
	}
	if got := poolListing(t, configB.Pool); !slices.Equal(got, clean) {
		t.Fatalf("a failed restore left something in the pool:\n%v\nwant\n%v", got, clean)
	}
	if left := hypervisorProcesses(t, configB.RunDir); len(left) != 0 {
		t.Fatalf("a VM runs after two failed restores: %v", left)
	}
	if current, err := b.manager.Get(id); err != nil || current.State != run.StateStopped || current.Remote.State != run.RemoteDurable {
		t.Fatalf("the run after two failed resumes: %+v, %v", current, err)
	}
	t.Logf("after both failed restores the pool lists exactly what it did before them (%d names), no VM runs, and the run is still stopped and durable", len(clean))
	// With the chunk back the run resumes: nothing was spent.
	if err := objects.Put(ctx, target.Key, original, s3.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	// And from a host with nothing of the run, not even its base image:
	// the restore every daemon does the first time.
	if err := b.driver.Transfer().Reclaim(ctx); err != nil || hasBase() {
		t.Fatalf("reclaim the base image: %v", err)
	}
	start = time.Now()
	if err := b.service.Ensure(ctx, stoppedRef); err != nil {
		t.Fatalf("restore with the chunk put back: %v\n%s", err, b.logs.String())
	}
	restoreTook = time.Since(start)
	restored = baseBytes + fullStored + incrementalStored + stopped.Remote.StoredBytes
	start = time.Now()
	if _, err := b.manager.Resume(ctx, id, 0); err != nil {
		t.Fatalf("resume with the chunk restored: %v\n%s", err, b.logs.String())
	}
	t.Logf("with the chunk put back, on a host with nothing of the run: restore of %s (base image and three streams) in %s (%s), boot %s, time to resume %s",
		mib(restored), restoreTook.Round(time.Millisecond), rate(restored, restoreTook), time.Since(start).Round(time.Millisecond), (restoreTook + time.Since(start)).Round(time.Millisecond))
	if got := b.digest(t, id); got != digest3 {
		t.Fatalf("bytes after the repaired resume: %s, want %s", got, digest3)
	}

	// --- destroy and collect: nothing of the run is left in the bucket.
	before := bucketKeys("")
	if err := b.manager.Destroy(ctx, id); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if err := b.manager.CollectRemote(ctx); err != nil {
		t.Fatalf("collect: %v\n%s", err, b.logs.String())
	}
	after := bucketKeys("")
	for _, d := range []*offHostDaemon{a, b} {
		for _, line := range strings.Split(d.logs.String(), "\n") {
			if strings.Contains(line, "snapshot restored") || strings.Contains(line, "base image uploaded") || strings.Contains(line, "remote storage collected") {
				t.Logf("%s log: %s", d.name, line)
			}
		}
	}
	t.Logf("destroy and collect: %d objects (%s) in the bucket before, %d after", len(before), mib(sizeOf(before)), len(after))
	if len(after) != 0 {
		var names []string
		for _, object := range after {
			names = append(names, object.Key)
		}
		t.Fatalf("left in the bucket with every run destroyed: %v", names)
	}
	// The base image of the lost host stays for the next restore until
	// the pool is short; the suite hands the pool back as it found it.
	if err := b.driver.Transfer().Reclaim(ctx); err != nil {
		t.Fatal(err)
	}
	if got := poolListing(t, configB.Pool); !slices.Equal(got, baselineB) {
		t.Fatalf("the standing pool is not as the suite found it:\n%v\nwant\n%v", got, baselineB)
	}
	if left := hypervisorProcesses(t, configB.RunDir); len(left) != 0 {
		t.Fatalf("hypervisor processes left: %v", left)
	}
}

func sizeOf(objects []s3.Object) int64 {
	var total int64
	for _, object := range objects {
		total += object.Size
	}
	return total
}

// The fleet changes its master key: what the old one still protects is
// re-wrapped, no chunk moves, and a daemon given only the new key then
// restores and resumes a run stopped under the old one.
func TestVMKeyRotation(t *testing.T) {
	endpoint := os.Getenv("SBX_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("SBX_S3_TEST_ENDPOINT is not set")
	}
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	ctx := context.Background()
	objects, err := s3.New(s3.Config{
		Endpoint: endpoint, Bucket: os.Getenv("SBX_S3_TEST_BUCKET"), PathStyle: true,
		Credentials: s3.Credentials{AccessKey: os.Getenv("SBX_S3_TEST_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_TEST_SECRET_KEY")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.CreateBucket(ctx); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	prefix := fmt.Sprintf("rot-%d", time.Now().Unix())
	keysUnder := func(under string) []s3.Object {
		t.Helper()
		listed, err := objects.ListAll(ctx, prefix+"/"+under)
		if err != nil {
			t.Fatal(err)
		}
		return listed
	}
	defer func() {
		for _, object := range keysUnder("") {
			_ = objects.Delete(ctx, object.Key)
		}
	}()
	oldMaster, newMaster := make([]byte, offhost.KeySize), make([]byte, offhost.KeySize)
	if _, err := rand.Read(oldMaster); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(newMaster); err != nil {
		t.Fatal(err)
	}

	configB := vmTestConfig(t)
	// This test's daemons keep no warm pool of their own (SBX_VM_WARM
	// reaches every config otherwise): the pool tests are the pool
	// coverage, and this suite's host is small.
	configB.Warm = vm.WarmConfig{}
	newVMManager(t, configB, t.TempDir())
	configA := offHostPoolA(t, configB)

	a := startOffHostDaemon(t, "rot-a", configA, objects, prefix, oldMaster, nil, nil)
	limits := &run.Limits{MemoryMB: 1024, CPUs: 1}
	created, err := a.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: limits})
	if err != nil {
		t.Fatalf("create: %v\n%s", err, a.logs.String())
	}
	a.exec(t, created.ID, `dd if=/dev/urandom of=/work/big.bin bs=1M count=64 status=none && sync`, 5*time.Minute)
	want := a.digest(t, created.ID)
	stopped := a.stopDurable(t, created.ID)
	snapshot := stopped.Remote.Snapshot
	before := keysUnder("v1/snap/" + snapshot + "/")
	if len(before) < 3 {
		t.Fatalf("the snapshot is %d objects", len(before))
	}
	// The run stays stopped and durable: closing the daemon leaves its
	// record exactly as rotation must find it.
	if err := a.driver.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// The fleet's new master, with the old one along to read; one pass.
	b := startOffHostDaemon(t, "rot-b", configB, objects, prefix, newMaster, [][]byte{oldMaster}, nil)
	defer func() {
		for _, current := range b.manager.List() {
			_ = b.manager.Destroy(ctx, current.ID)
		}
		_ = b.driver.Close(context.Background())
	}()
	start := time.Now()
	stats, err := b.manager.RotateRemote(ctx)
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, b.logs.String())
	}
	if stats.Manifests < 2 || stats.Records < 1 {
		t.Fatalf("one pass rewrapped the stop snapshot, the base image and the record: %+v", stats)
	}
	t.Logf("rotation pass: %+v in %s", stats, time.Since(start).Round(time.Millisecond))
	after := keysUnder("v1/snap/" + snapshot + "/")
	if len(after) != len(before) {
		t.Fatalf("the rotation moved objects: %d before, %d after", len(before), len(after))
	}
	for i := range before {
		if before[i].Key != after[i].Key || (before[i].Size != after[i].Size && !strings.HasSuffix(before[i].Key, "manifest")) {
			t.Fatalf("the rotation changed %s", before[i].Key)
		}
	}

	// The old master is gone for good: a daemon given only the new one
	// adopts the run and resumes it, restoring the snapshot from the
	// bucket (its own golden image is a different snapshot).
	if err := b.driver.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := startOffHostDaemon(t, "rot-c", configB, objects, prefix, newMaster, nil, nil)
	defer c.driver.Close(context.Background())
	if _, err := c.manager.SyncRemote(ctx); err != nil {
		t.Fatalf("sync: %v\n%s", err, c.logs.String())
	}
	start = time.Now()
	resumed, err := c.manager.Resume(ctx, created.ID, 0)
	if err != nil {
		t.Fatalf("resume under the new master only: %v\n%s", err, c.logs.String())
	}
	took := time.Since(start)
	if got := c.digest(t, resumed.ID); got != want {
		t.Fatalf("the resumed run's bytes differ: %s != %s", got, want)
	}
	t.Logf("resume from the bucket under the new master only: %s", took.Round(time.Millisecond))
	_ = c.manager.Destroy(ctx, resumed.ID)
}

// A caller snapshot is durable, listed, bootable from its universal ID on
// a host that never held it, and deletable by that ID from there.
func TestVMCallerSnapshots(t *testing.T) {
	endpoint := os.Getenv("SBX_S3_TEST_ENDPOINT")
	if endpoint == "" {
		t.Skip("SBX_S3_TEST_ENDPOINT is not set")
	}
	if os.Getuid() != 0 {
		t.Fatal("the vm suite needs root (zfs, /dev/kvm)")
	}
	ctx := context.Background()
	objects, err := s3.New(s3.Config{
		Endpoint: endpoint, Bucket: os.Getenv("SBX_S3_TEST_BUCKET"), PathStyle: true,
		Credentials: s3.Credentials{AccessKey: os.Getenv("SBX_S3_TEST_ACCESS_KEY"), SecretKey: os.Getenv("SBX_S3_TEST_SECRET_KEY")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.CreateBucket(ctx); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	prefix := fmt.Sprintf("snap-%d", time.Now().Unix())
	keysUnder := func(under string) []s3.Object {
		t.Helper()
		listed, err := objects.ListAll(ctx, prefix+"/"+under)
		if err != nil {
			t.Fatal(err)
		}
		return listed
	}
	defer func() {
		for _, object := range keysUnder("") {
			_ = objects.Delete(ctx, object.Key)
		}
	}()
	master := make([]byte, offhost.KeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}

	configB := vmTestConfig(t)
	// This test's daemons keep no warm pool of their own (SBX_VM_WARM
	// reaches every config otherwise): the pool tests are the pool
	// coverage, and this suite's host is small.
	configB.Warm = vm.WarmConfig{}
	newVMManager(t, configB, t.TempDir())
	configA := offHostPoolA(t, configB)

	a := startOffHostDaemon(t, "snap-a", configA, objects, prefix, master, nil, nil)
	defer func() {
		for _, current := range a.manager.List() {
			_ = a.manager.Destroy(context.Background(), current.ID)
		}
		_ = a.driver.Close(context.Background())
	}()
	created, err := a.manager.Create(ctx, run.CreateRequest{Image: vm.GoldenImage, Limits: &run.Limits{MemoryMB: 1024, CPUs: 1}})
	if err != nil {
		t.Fatalf("create: %v\n%s", err, a.logs.String())
	}
	a.exec(t, created.ID, `dd if=/dev/urandom of=/work/big.bin bs=1M count=64 status=none && sync`, 5*time.Minute)
	want := a.digest(t, created.ID)

	// The snapshot, durable before the call answers.
	ref, remote, err := a.manager.SnapshotRemote(ctx, created.ID)
	if err != nil || remote == nil {
		t.Fatalf("snapshot: %+v %v\n%s", remote, err, a.logs.String())
	}
	if remote.State != run.RemoteDurable || remote.ID == "" {
		t.Fatalf("the snapshot is not durable: %+v", remote)
	}
	listed, err := a.manager.RemoteSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != remote.ID || listed[0].Run != created.ID || listed[0].StoredBytes == 0 || listed[0].CreatedAt.IsZero() {
		t.Fatalf("the listing is the snapshot: %+v", listed)
	}
	t.Logf("caller snapshot %s: %s stored, listed with %d others", remote.ID, mib(remote.StoredBytes), len(listed)-1)

	// Another pool entirely boots it by ID.
	b := startOffHostDaemon(t, "snap-b", configB, objects, prefix, master, nil, nil)
	defer func() {
		for _, current := range b.manager.List() {
			_ = b.manager.Destroy(context.Background(), current.ID)
		}
		_ = b.driver.Close(context.Background())
	}()
	booted, err := b.manager.Create(ctx, run.CreateRequest{Image: "snapshot:" + remote.ID, Limits: &run.Limits{MemoryMB: 1024, CPUs: 1}})
	if err != nil {
		t.Fatalf("create from the snapshot's universal ID: %v\n%s", err, b.logs.String())
	}
	if got := b.digest(t, booted.ID); got != want {
		t.Fatalf("the booted copy's bytes differ: %s != %s", got, want)
	}

	// And deletes it by ID, from the host that never took it. The birth
	// host keeps its local copy until it is deleted there, by its ref.
	if err := b.manager.DeleteSnapshot(ctx, "snapshot:"+remote.ID); err != nil {
		t.Fatalf("delete by universal ID: %v", err)
	}
	if keys := keysUnder("v1/snap/" + remote.ID + "/"); len(keys) != 0 {
		t.Fatalf("the snapshot is still in the bucket: %v", keys)
	}
	if listed, _ := a.manager.RemoteSnapshots(ctx); len(listed) != 0 {
		t.Fatalf("the listing after the delete: %v", listed)
	}
	if has, _ := a.service.HasLocal(ctx, ref); !has {
		t.Fatal("the delete reached into the host that took the snapshot")
	}
	if err := a.manager.DeleteSnapshot(ctx, ref); err != nil {
		t.Fatalf("delete by the birth host's ref: %v", err)
	}
	if has, _ := a.service.HasLocal(ctx, ref); has {
		t.Fatal("the snapshot is still on the host that took it")
	}
}
