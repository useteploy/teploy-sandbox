package offhost

// The scrub that reads (2026-11-21): chunks held to the SHA-256 their
// manifest records, a damaged chunk remembered so that Verify stops
// calling its snapshot whole, and a repair from a local copy that
// replaces the manifest instead of taking it back first.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/offhost/offhosttest"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// rot flips one byte in the middle of a snapshot's chunk index, leaving
// its size as it was: what a listing can never see.
func rot(t *testing.T, memory *offhosttest.Memory, store *Store, id string, index int) {
	t.Helper()
	manifest, _, err := store.Manifest(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	key := store.chunkKey(id, manifest.Attempt, index)
	raw := memory.Raw(key)
	raw[len(raw)/2] ^= 0x10
	memory.SetRaw(key, raw)
}

func TestTheScrubThatReadsFindsBitRot(t *testing.T) {
	memory := offhosttest.NewMemory()
	store := integrityStore(t, memory, testKeyring(t, 1))
	host := newPool()
	host.data[snapS] = randomBytes(t, 4500)
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	rot(t, memory, store, snapS, 3)
	// Sizes say nothing.
	if _, _, err := store.Verify(bg, snapS); err != nil {
		t.Fatalf("before anything was read: %v", err)
	}
	// One round with room for two chunks (1028 bytes each as stored): not there yet, and it says
	// where it is.
	found, err := service.ScrubContent(bg, []string{"snap:" + snapS}, 2100)
	if err != nil || len(found.Damaged) != 0 || found.Complete || found.ReadBytes == 0 || found.ReadBytes > 2*1028 {
		t.Fatalf("a first round of 2100 bytes: %+v, %v", found, err)
	}
	found, err = service.ScrubContent(bg, []string{"snap:" + snapS}, 2100)
	if err != nil || len(found.Damaged) != 1 || found.Damaged[0] != "snap:"+snapS {
		t.Fatalf("the round that reaches chunk 3: %+v, %v", found, err)
	}
	var incomplete *Incomplete
	if _, _, err := store.Verify(bg, snapS); !errors.As(err, &incomplete) || !incomplete.Content || !strings.Contains(err.Error(), "chunk 3") {
		t.Fatalf("Verify after the scrub read a damaged chunk: %v", err)
	}
	// The next round begins a new pass and finds it again.
	if found, _ := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); len(found.Damaged) != 1 {
		t.Fatalf("a later pass: %+v", found)
	}
}

// One read that disagrees is read again before anything is concluded,
// and a later read that agrees clears what was concluded.
func TestOneBadReadIsNotAVerdict(t *testing.T) {
	memory := offhosttest.NewMemory()
	bucket := offhosttest.NewFaulty(memory)
	store := integrityStore(t, bucket, testKeyring(t, 1))
	host := newPool()
	host.data[snapS] = randomBytes(t, 2500)
	service := NewService(store, host, Config{Daemon: "a"}, quiet())
	if _, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	manifest, _, _ := store.Manifest(bg, snapS)
	target := store.chunkKey(snapS, manifest.Attempt, 1)
	good := memory.Raw(target)
	// A first answer that is wrong: damaged for the first read, whole
	// again by the second.
	bad := bytes.Clone(good)
	bad[0] ^= 1
	memory.SetRaw(target, bad)
	gets := 0
	bucket.Set(func(f *offhosttest.Faulty) {
		f.AfterGet = func(key string) {
			if key == target {
				if gets++; gets == 1 {
					memory.SetRaw(target, good) // mended before the second read
				}
			}
		}
	})
	if found, err := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); err != nil || len(found.Damaged) != 0 || gets != 2 {
		t.Fatalf("a chunk whose first read was wrong: %+v, %v (reads %d)", found, err, gets)
	}
	if _, _, err := store.Verify(bg, snapS); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Damaged for two reads: concluded; mended later: a read clears it.
	bucket.Set(func(f *offhosttest.Faulty) { f.AfterGet = nil })
	memory.SetRaw(target, bad)
	if found, _ := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); len(found.Damaged) != 1 {
		t.Fatalf("a chunk damaged for both reads: %+v", found)
	}
	memory.SetRaw(target, good)
	if found, _ := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); len(found.Damaged) != 0 {
		t.Fatalf("after the chunk read whole again: %+v", found)
	}
	if _, _, err := store.Verify(bg, snapS); err != nil {
		t.Fatalf("Verify after a whole read: %v", err)
	}
}

// A snapshot with a damaged chunk, and a host that still has it: the
// upkeep's upload replaces it. The manifest is never taken back on the
// way (a read's verdict is not a listing's), and what restores
// afterwards is the snapshot.
func TestADamagedSnapshotIsRepairedFromALocalCopy(t *testing.T) {
	t.Run("its own chunk", func(t *testing.T) {
		memory := offhosttest.NewMemory()
		bucket := offhosttest.NewFaulty(memory)
		store := integrityStore(t, bucket, testKeyring(t, 1))
		host := newPool()
		host.data[snapS] = randomBytes(t, 3500)
		service := NewService(store, host, Config{Daemon: "a"}, quiet())
		first, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
		if err != nil {
			t.Fatal(err)
		}
		before, _, _ := store.Manifest(bg, snapS)
		rot(t, memory, store, snapS, 2)
		if found, _ := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); len(found.Damaged) != 1 {
			t.Fatalf("scrub: %+v", found)
		}
		bucket.Set(func(f *offhosttest.Faulty) {
			f.BeforeDelete = func(key string) {
				if key == store.manifestKey(snapS) {
					t.Errorf("the manifest of a snapshot a read found damaged was deleted before it was replaced")
				}
			}
		})
		again, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Key: first.Key, Purpose: PurposeStop})
		if err != nil || again.Already {
			t.Fatalf("the repair: %+v, %v", again, err)
		}
		after, _, _ := store.Manifest(bg, snapS)
		if after.Attempt == before.Attempt {
			t.Fatal("the manifest still names the damaged upload")
		}
		if _, _, err := store.Verify(bg, snapS); err != nil {
			t.Fatalf("Verify after the repair: %v", err)
		}
		restores(t, store, snapS, host.data[snapS])
	})
	t.Run("the base image it builds on", func(t *testing.T) {
		memory := offhosttest.NewMemory()
		store := integrityStore(t, memory, testKeyring(t, 1))
		host := newPool()
		host.data[baseB], host.data[snapS] = randomBytes(t, 2500), randomBytes(t, 1500)
		host.base[snapS] = baseB
		service := NewService(store, host, Config{Daemon: "a"}, quiet())
		first, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
		if err != nil {
			t.Fatal(err)
		}
		rot(t, memory, store, baseB, 1)
		if found, _ := service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20); len(found.Damaged) != 1 {
			t.Fatalf("scrub: %+v", found)
		}
		standing, _, _ := store.Manifest(bg, snapS)
		again, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Key: first.Key, Purpose: PurposeStop})
		if err != nil || !again.Already {
			t.Fatalf("the repair of the base: %+v, %v", again, err)
		}
		if now, _, _ := store.Manifest(bg, snapS); now.Attempt != standing.Attempt {
			t.Fatal("the snapshot itself was uploaded again; only the base was damaged")
		}
		restores(t, store, snapS, host.data[snapS])
	})
	t.Run("no copy here", func(t *testing.T) {
		memory := offhosttest.NewMemory()
		store := integrityStore(t, memory, testKeyring(t, 1))
		host := newPool()
		host.data[snapS] = randomBytes(t, 2500)
		service := NewService(store, host, Config{Daemon: "a"}, quiet())
		first, err := service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop})
		if err != nil {
			t.Fatal(err)
		}
		rot(t, memory, store, snapS, 0)
		service.ScrubContent(bg, []string{"snap:" + snapS}, 1<<20)
		delete(host.data, snapS)
		_, err = service.Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Key: first.Key, Purpose: PurposeStop})
		if !errors.Is(err, run.ErrRemoteIncomplete) || !strings.Contains(err.Error(), "no copy") {
			t.Fatalf("an upload of a damaged snapshot with no copy here: %v", err)
		}
		if memory.Raw(store.manifestKey(snapS)) == nil {
			t.Fatal("the manifest was taken back on a read's word")
		}
	})
}

// A restore that meets a damaged chunk remembers it: the next Verify of
// the snapshot says it is not whole, and why.
func TestARestoreThatFailsOnContentIsRemembered(t *testing.T) {
	memory := offhosttest.NewMemory()
	store := integrityStore(t, memory, testKeyring(t, 1))
	host := newPool()
	host.data[snapS] = randomBytes(t, 2500)
	if _, err := NewService(store, host, Config{Daemon: "a"}, quiet()).Upload(bg, run.UploadRequest{Run: runR, Ref: "snap:" + snapS, Purpose: PurposeStop}); err != nil {
		t.Fatal(err)
	}
	rot(t, memory, store, snapS, 1)
	elsewhere := NewService(store, newPool(), Config{Daemon: "b"}, quiet())
	if err := elsewhere.Ensure(bg, "snap:"+snapS); err == nil {
		t.Fatal("a damaged snapshot restored")
	}
	var incomplete *Incomplete
	if err := elsewhere.Verify(bg, "snap:"+snapS); !errors.Is(err, run.ErrRemoteIncomplete) || !errors.As(err, &incomplete) || !incomplete.Content {
		t.Fatalf("Verify after a restore that met a damaged chunk: %v", err)
	}
}
