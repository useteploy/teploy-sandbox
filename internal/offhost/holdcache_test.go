package offhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/hostsecret"
)

// The host's hold-key cache: what it keeps across a restart, what it
// refuses as a clone, and what it gives up as one run's damage.

func openCache(t *testing.T, path string, secret []byte) *HoldCache {
	t.Helper()
	cache, err := OpenHoldCache(path, secret)
	if err != nil {
		t.Fatalf("OpenHoldCache(%s): %v", path, err)
	}
	return cache
}

// cacheOnDisk is the cache file with its entries typed out, for a test
// to read and to damage.
type cacheOnDisk struct {
	Header  string                 `json:"header"`
	Entries map[string]cachedEntry `json:"entries"`
}

func readCacheFile(t *testing.T, path string) cacheOnDisk {
	t.Helper()
	var file cacheOnDisk
	if err := json.Unmarshal(mustRead(t, path), &file); err != nil || file.Entries == nil {
		t.Fatalf("the cache file is not one: %v", err)
	}
	return file
}

func writeCacheFile(t *testing.T, path string, file cacheOnDisk) {
	t.Helper()
	if err := os.WriteFile(path, must2(json.Marshal(file)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// leftovers is what is in the cache's directory beside the cache.
func leftovers(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.Name() != filepath.Base(path) {
			names = append(names, entry.Name())
		}
	}
	return names
}

// flipFirst changes the first character of s, whatever it was.
func flipFirst(s string) string {
	if s == "" {
		return "A"
	}
	first := "A"
	if s[0] == 'A' {
		first = "B"
	}
	return first + s[1:]
}

func TestHoldCacheRoundTrip(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	cache := openCache(t, path, secret)
	if _, ok := cache.Get(runA); ok {
		t.Fatal("a cache that was not there has a key")
	}
	if runs := cache.DamagedRuns(); len(runs) != 0 {
		t.Fatalf("a cache that was not there has damaged runs: %v", runs)
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the cache file was written before any key was put: %v", err)
	}

	one, two := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantTwo, runB)
	for _, key := range []HoldKey{one, two} {
		if err := cache.Put(key); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the cache file has mode %04o, want 0600", mode)
	}
	// Nothing of a key is in the file in the clear, and no field but
	// the four there are.
	data := string(mustRead(t, path))
	if err := (leaks(rawOf(one), rawOf(two), secret))(data); err != nil {
		t.Fatal(err)
	}
	file := readCacheFile(t, path)
	if len(file.Entries) != 2 || file.Header == "" {
		t.Fatalf("the cache file: %d entries", len(file.Entries))
	}
	for run, entry := range file.Entries {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(must2(json.Marshal(entry)), &fields); err != nil || len(fields) != 4 {
			t.Fatalf("the entry of %s: %v", run, err)
		}
	}
	if got, ok := cache.Get(runA); !ok {
		t.Fatal("a key just put is not there")
	} else {
		assertKey(t, got, one)
	}
	cache.Close()

	// The daemon restarts: everything it held is here again.
	again := openCache(t, path, secret)
	if got, ok := again.Get(runA); !ok {
		t.Fatal("the key of run A did not survive the restart")
	} else {
		assertKey(t, got, one)
	}
	if got, ok := again.Get(runB); !ok {
		t.Fatal("the key of run B did not survive the restart")
	} else {
		assertKey(t, got, two)
	}
	if again.Damaged(runA) || len(again.DamagedRuns()) != 0 {
		t.Fatal("an intact cache reports damage")
	}
	// A run has one key: a new hold replaces the one before.
	next := cloud.hold(t, tenantOne, runA)
	if err := again.Put(next); err != nil {
		t.Fatal(err)
	}
	again.Close()
	third := openCache(t, path, secret)
	defer third.Close()
	if got, ok := third.Get(runA); !ok {
		t.Fatal("the new hold of run A is not there")
	} else {
		assertKey(t, got, next)
	}
	if got, ok := third.Get(runB); !ok {
		t.Fatal("the key of run B went with the new hold of run A")
	} else {
		assertKey(t, got, two)
	}
	if left := leftovers(t, path); len(left) != 0 {
		t.Fatalf("left beside the cache: %v", left)
	}
}

func TestAClonedCacheIsRefused(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	key := cloud.hold(t, tenantOne, runA)
	cache := openCache(t, path, secret)
	if err := cache.Put(key); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	data := mustRead(t, path)

	// The host's own secret opens it, again and again.
	again := openCache(t, path, secret)
	again.Close()
	// Another host's does not: a cloned or restored state directory.
	for name, other := range map[string][]byte{
		"another host's secret": randomBytes(t, hostsecret.Size),
		"a secret that differs in one byte": func() []byte {
			near := bytes.Clone(secret)
			near[hostsecret.Size-1] ^= 1
			return near
		}(),
		"a secret that differs in its first byte": func() []byte {
			near := bytes.Clone(secret)
			near[0] ^= 0x80
			return near
		}(),
	} {
		if _, err := OpenHoldCache(path, other); !errors.Is(err, ErrClonedCache) {
			t.Errorf("%s: %v, want ErrClonedCache", name, err)
		}
	}
	// The state directory copied to another machine: the same file,
	// and not this host's secret there.
	clone := filepath.Join(t.TempDir(), HoldCacheFileName)
	if err := os.WriteFile(clone, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHoldCache(clone, randomBytes(t, hostsecret.Size)); !errors.Is(err, ErrClonedCache) {
		t.Errorf("a copied state directory under another host's secret: %v, want ErrClonedCache", err)
	}
	// Restored on the same host, it is this host's, and opens.
	restored := openCache(t, clone, secret)
	if got, ok := restored.Get(runA); !ok {
		t.Fatal("a restored cache on its own host lost the key")
	} else {
		assertKey(t, got, key)
	}
	restored.Close()
	// A header that does not open is all a clone is: one bit changed
	// in it, and the file is refused whole.
	for name, change := range map[string]func(*cacheOnDisk){
		"a bit of the header":         func(f *cacheOnDisk) { f.Header = flipFirst(f.Header) },
		"the header of another cache": func(f *cacheOnDisk) { f.Header = openCacheHeader(t, randomBytes(t, hostsecret.Size)) },
	} {
		file := readCacheFile(t, path)
		change(&file)
		writeCacheFile(t, path, file)
		if _, err := OpenHoldCache(path, secret); !errors.Is(err, ErrClonedCache) {
			t.Errorf("%s: %v, want ErrClonedCache", name, err)
		}
	}
	writeCacheFile(t, path, readCacheFile(t, clone))
	// A secret of another length is no secret at all: said as that.
	for _, bad := range [][]byte{nil, secret[:31], append(bytes.Clone(secret), 0)} {
		_, err := OpenHoldCache(path, bad)
		if err == nil || errors.Is(err, ErrClonedCache) || errors.Is(err, ErrNotHoldCache) {
			t.Errorf("a secret of %d bytes: %v, want a plain error", len(bad), err)
		}
	}

	// With the host secret as the daemon loads it (internal/hostsecret):
	// the same file read at every start of one host, and no other's.
	thisHost := filepath.Join(t.TempDir(), "host-secret")
	first, err := hostsecret.Load(thisHost)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hostsecret.Load(thisHost)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("the host's secret changed between two starts: %v", err)
	}
	live := filepath.Join(t.TempDir(), HoldCacheFileName)
	cache = openCache(t, live, first)
	if err := cache.Put(key); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	restarted := openCache(t, live, second)
	restarted.Close()
	otherHost, err := hostsecret.Load(filepath.Join(t.TempDir(), "host-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHoldCache(live, otherHost); !errors.Is(err, ErrClonedCache) {
		t.Errorf("under another host's loaded secret: %v, want ErrClonedCache", err)
	}
}

// openCacheHeader is a header as this format writes one, under secret.
func openCacheHeader(t *testing.T, secret []byte) string {
	t.Helper()
	cache := openCache(t, filepath.Join(t.TempDir(), HoldCacheFileName), secret)
	defer cache.Close()
	header, err := cache.sealHeader()
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func TestADamagedEntryIsOnlyThatRuns(t *testing.T) {
	cloud := newKMS(t)
	other := cloud.hold(t, tenantOne, runC)
	// ofRunB changes run B's entry in the file.
	ofRunB := func(change func(e *cachedEntry)) func(*testing.T, *cacheOnDisk) {
		return func(_ *testing.T, file *cacheOnDisk) {
			entry := file.Entries[runB]
			change(&entry)
			file.Entries[runB] = entry
		}
	}
	// Each case damages the file after two keys were put (run A's and
	// run B's), and says which runs are then reported damaged and which
	// simply have no key. The cache opens, and every other run keeps its
	// key: one entry's damage is not a clone.
	for name, c := range map[string]struct {
		damaged, absent []string
		damage          func(t *testing.T, file *cacheOnDisk)
	}{
		"a bit of the entry":                     {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Sealed = flipFirst(e.Sealed) })},
		"the last bit of the entry":              {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Sealed = flipLast(e.Sealed) })},
		"the tenant, in the clear":               {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Tenant = tenantOne })},
		"a tenant that is not one, in the clear": {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Tenant = "Org" })},
		"the kid, in the clear":                  {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.KID = other.KID })},
		"the wrapped blob, in the clear":         {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Wrapped = strings.Replace(e.Wrapped, ".1.", ".2.", 1) })},
		"a sealed entry that is not base64":      {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Sealed = "****" })},
		"a sealed entry cut short":               {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Sealed = e.Sealed[:40] })},
		"no sealed entry":                        {[]string{runB}, nil, ofRunB(func(e *cachedEntry) { e.Sealed = "" })},
		"the entry of another run": {[]string{runA, runB}, nil, func(_ *testing.T, file *cacheOnDisk) {
			a, b := file.Entries[runA], file.Entries[runB]
			a.Sealed, b.Sealed = b.Sealed, a.Sealed
			file.Entries[runA], file.Entries[runB] = a, b
		}},
		"the entry under another run's ID": {[]string{runC}, []string{runB}, func(_ *testing.T, file *cacheOnDisk) {
			file.Entries[runC] = file.Entries[runB]
			delete(file.Entries, runB)
		}},
		"the same kid under two runs": {[]string{runC}, nil, func(_ *testing.T, file *cacheOnDisk) { file.Entries[runC] = file.Entries[runA] }},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), HoldCacheFileName)
			secret := randomBytes(t, hostsecret.Size)
			one, two := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantTwo, runB)
			before := map[string]HoldKey{runA: one, runB: two}
			cache := openCache(t, path, secret)
			for _, key := range []HoldKey{one, two} {
				if err := cache.Put(key); err != nil {
					t.Fatal(err)
				}
			}
			cache.Close()
			file := readCacheFile(t, path)
			c.damage(t, &file)
			writeCacheFile(t, path, file)

			again, err := OpenHoldCache(path, secret)
			if err != nil {
				t.Fatalf("a cache with one damaged entry: %v", err)
			}
			defer again.Close()
			if got := again.DamagedRuns(); !equal(got, c.damaged) {
				t.Errorf("DamagedRuns = %v, want %v", got, c.damaged)
			}
			for run, key := range before {
				got, ok := again.Get(run)
				switch {
				case contains(c.damaged, run):
					if ok || !again.Damaged(run) {
						t.Errorf("run %s: a key came back (%v) for a damaged entry, or it is not reported damaged", run, ok)
					}
				case contains(c.absent, run):
					if ok || again.Damaged(run) {
						t.Errorf("run %s: a key came back (%v) for a run with no entry", run, ok)
					}
				default:
					if !ok {
						t.Errorf("run %s lost its key to another run's damaged entry", run)
					} else {
						assertKey(t, got, key)
					}
				}
			}
			// Cloud pushes each damaged run's key again: repaired, and
			// it stays so across a restart, and costs no other run its
			// key.
			repaired := map[string]HoldKey{}
			for _, run := range c.damaged {
				tenant := map[string]string{runA: tenantOne, runB: tenantTwo, runC: tenantOne}[run]
				if held, ok := before[run]; ok {
					tenant = held.Tenant
				}
				fresh := cloud.hold(t, tenant, run)
				if err := again.Put(fresh); err != nil {
					t.Fatal(err)
				}
				if again.Damaged(run) {
					t.Errorf("run %s is still damaged after a push", run)
				}
				repaired[run] = fresh
			}
			if runs := again.DamagedRuns(); len(runs) != 0 {
				t.Errorf("after the pushes DamagedRuns = %v", runs)
			}
			again.Close()
			third := openCache(t, path, secret)
			defer third.Close()
			if runs := third.DamagedRuns(); len(runs) != 0 {
				t.Errorf("after the pushes and a restart DamagedRuns = %v", runs)
			}
			for run, key := range before {
				if fresh, ok := repaired[run]; ok {
					key = fresh
				}
				if contains(c.absent, run) {
					continue
				}
				got, ok := third.Get(run)
				if !ok {
					t.Errorf("after a restart run %s has no key", run)
				} else {
					assertKey(t, got, key)
				}
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, of := range list {
		if of == s {
			return true
		}
	}
	return false
}

// An entry with a field this daemon does not know is that entry's
// damage: the file is this host's, and the other entries open.
func TestAnEntryWithAFieldThisDaemonDoesNotKnowIsThatRunsDamage(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	one, two := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantTwo, runB)
	cache := openCache(t, path, secret)
	for _, key := range []HoldKey{one, two} {
		if err := cache.Put(key); err != nil {
			t.Fatal(err)
		}
	}
	cache.Close()
	data := string(mustRead(t, path))
	sealed := readCacheFile(t, path).Entries[runB].Sealed
	forged := strings.Replace(data, `,"sealed":"`+sealed+`"}`, `,"sealed":"`+sealed+`","extra":1}`, 1)
	if forged == data {
		t.Fatal("the fixture was not changed")
	}
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	again := openCache(t, path, secret)
	defer again.Close()
	if got := again.DamagedRuns(); !equal(got, []string{runB}) {
		t.Errorf("DamagedRuns = %v, want [%s]", got, runB)
	}
	if got, ok := again.Get(runA); !ok {
		t.Fatal("run A lost its key to run B's entry")
	} else {
		assertKey(t, got, one)
	}
	if _, ok := again.Get(runB); ok {
		t.Fatal("a damaged entry gave a key")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDeleteErasesTheKeyAndPersists(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	one, two := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantTwo, runB)
	cache := openCache(t, path, secret)
	if err := cache.Put(one); err != nil {
		t.Fatal(err)
	}
	if err := cache.Put(two); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	where := cache.entries[runA].raw
	held := cache.sealed[runA]
	cache.mu.Unlock()
	before := mustRead(t, path)
	if err := cache.Delete(runA); err != nil {
		t.Fatal(err)
	}
	if !where.key.wiped || !bytes.Equal(where.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("Delete did not wipe the key's bytes where they lie")
	}
	if _, ok := cache.Get(runA); ok {
		t.Fatal("the deleted run still has a key")
	}
	if data := mustRead(t, path); bytes.Equal(data, before) || strings.Contains(string(data), held) {
		t.Fatal("the deleted entry is still in the file")
	}
	if got, ok := cache.Get(runB); !ok {
		t.Fatal("the delete of run A cost run B its key")
	} else {
		assertKey(t, got, two)
	}
	cache.Close()
	again := openCache(t, path, secret)
	if _, ok := again.Get(runA); ok {
		t.Fatal("the deleted run's key came back after a restart")
	}
	if got, ok := again.Get(runB); !ok {
		t.Fatal("the delete of run A cost run B its key across a restart")
	} else {
		assertKey(t, got, two)
	}
	// A run with no entry, or no longer one, is nothing: and writes nothing.
	stamp := mustRead(t, path)
	if err := again.Delete(runA); err != nil {
		t.Errorf("Delete of a run with no key: %v", err)
	}
	if err := again.Delete("not-a-run"); err != nil {
		t.Errorf("Delete of a run there never was: %v", err)
	}
	if !bytes.Equal(mustRead(t, path), stamp) {
		t.Fatal("a Delete of nothing rewrote the file")
	}
	// A damaged run's mark goes with a Delete, and is gone after a restart.
	again.Close()
	file := readCacheFile(t, path)
	moved := file.Entries[runB]
	moved.Sealed = flipFirst(moved.Sealed)
	file.Entries[runC] = moved
	writeCacheFile(t, path, file)
	third := openCache(t, path, secret)
	if !third.Damaged(runC) {
		t.Fatal("the damaged entry is not reported")
	}
	if err := third.Delete(runC); err != nil {
		t.Fatal(err)
	}
	third.Close()
	fourth := openCache(t, path, secret)
	defer fourth.Close()
	if len(fourth.DamagedRuns()) != 0 {
		t.Fatalf("after the delete and a restart DamagedRuns = %v", fourth.DamagedRuns())
	}
	if _, ok := fourth.Get(runB); !ok {
		t.Fatal("run B's key went with the delete of run C")
	}
	if left := leftovers(t, path); len(left) != 0 {
		t.Fatalf("left beside the cache: %v", left)
	}
}

func TestTheCacheFileIsTheOwnersAlone(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	key := cloud.hold(t, tenantOne, runA)
	for _, mode := range []fs.FileMode{0o644, 0o640, 0o604, 0o666, 0o611} {
		// The round before left it readable by others; it is this
		// host's alone again.
		if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		cache := openCache(t, path, secret)
		if err := cache.Put(key); err != nil {
			t.Fatal(err)
		}
		cache.Close()
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenHoldCache(path, secret); !errors.Is(err, ErrCacheReadable) || errors.Is(err, ErrClonedCache) {
			t.Errorf("mode %04o: %v, want ErrCacheReadable", mode, err)
		}
	}
	for _, mode := range []fs.FileMode{0o600, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		cache := openCache(t, path, secret)
		cache.Close()
	}
	// The temporary file the cache writes is the owner's alone too,
	// however the umask is set.
	cache := openCache(t, path, secret)
	if err := cache.Put(cloud.hold(t, tenantOne, runB)); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Errorf("after a write the cache file's mode is %v, %v", info.Mode().Perm(), err)
	}
	// A directory, or a symbolic link, where the cache should be.
	dir := filepath.Join(t.TempDir(), HoldCacheFileName)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHoldCache(dir, secret); err == nil || errors.Is(err, ErrClonedCache) {
		t.Errorf("a directory: %v, want a plain error", err)
	}
	link := filepath.Join(t.TempDir(), HoldCacheFileName)
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenHoldCache(link, secret); err == nil || errors.Is(err, ErrClonedCache) {
		t.Errorf("a symbolic link: %v, want a plain error", err)
	}
	// A path whose directory is not there is made, as the host secret's is.
	deep := filepath.Join(t.TempDir(), "state", "nested", HoldCacheFileName)
	cache = openCache(t, deep, secret)
	if err := cache.Put(key); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	if info, err := os.Stat(filepath.Dir(filepath.Dir(deep))); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the directory made for the cache has mode %v, %v", info.Mode().Perm(), err)
	}
}

func TestWhatIsNotACacheIsRefused(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	key := cloud.hold(t, tenantOne, runA)
	cache := openCache(t, path, secret)
	if err := cache.Put(key); err != nil {
		t.Fatal(err)
	}
	cache.Close()
	good := mustRead(t, path)
	// A header as this format writes one, and nothing under it.
	header := openCacheHeader(t, secret)
	for name, data := range map[string][]byte{
		"an empty file":                          nil,
		"garbage":                                []byte("hello"),
		"an empty object":                        []byte(`{}`),
		"an array":                               []byte(`[]`),
		"null":                                   []byte(`null`),
		"no header":                              []byte(`{"entries":{}}`),
		"a header that is not base64":            []byte(`{"header":"****","entries":{}}`),
		"a header with no magic":                 []byte(`{"header":"","entries":{}}`),
		"entries, and no header, after a header": []byte(`{"header":"` + header + `","entries":{},"entries":{}}`),
		"an unknown field":                       []byte(`{"header":"` + header + `","entries":{},"extra":1}`),
		"the header written twice":               []byte(`{"header":"` + header + `","header":"` + header + `","entries":{}}`),
		"a second document":                      append([]byte(`{"header":"`+header+`","entries":{}}`), '{'),
		"truncated":                              good[:len(good)/2],
		"JSON, and not this JSON":                []byte(`{"magic":"` + holdCacheMagic + `","format":1}`),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenHoldCache(path, secret); !errors.Is(err, ErrNotHoldCache) || errors.Is(err, ErrClonedCache) {
			t.Errorf("%s: %v, want ErrNotHoldCache and not ErrClonedCache", name, err)
		}
	}
	// An entry with a field this daemon does not know is that entry's
	// damage, under a header that opens.
	if err := os.WriteFile(path, []byte(`{"header":"`+header+`","entries":{"`+runA+`":{"tenant":"`+tenantOne+`","kid":"`+key.KID+`","wrapped":"`+key.Wrapped+`","sealed":"AAAA","extra":1}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := OpenHoldCache(path, secret)
	if err != nil {
		t.Fatalf("an entry with an unknown field: %v", err)
	}
	if !equal(cache.DamagedRuns(), []string{runA}) {
		t.Errorf("DamagedRuns = %v", cache.DamagedRuns())
	}
	cache.Close()
}

func flipLast(s string) string {
	if s == "" {
		return "A"
	}
	return s[:len(s)-1] + flipFirst(s[len(s)-1:])
}

func TestAFailedPutDoesNotCommitTheKey(t *testing.T) {
	cloud := newKMS(t)
	dir := t.TempDir()
	path := filepath.Join(dir, HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	cache := openCache(t, path, secret)
	defer cache.Close()
	key := cloud.hold(t, tenantOne, runA)
	if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := cache.Put(key); err == nil {
		t.Fatal("a Put into a directory that is not there said nothing")
	}
	// A key that never reached disk is not committed in memory either,
	// so callers do not acknowledge an unpersisted push.
	if _, ok := cache.Get(runA); ok {
		t.Fatal("a failed Put committed the key in memory")
	}
	if len(cache.DamagedRuns()) != 0 {
		t.Fatal("a failed write marked a run damaged")
	}
}

func TestAPutThatIsRefusedStoresNothing(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	cache := openCache(t, path, randomBytes(t, hostsecret.Size))
	defer cache.Close()
	one, two := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantTwo, runB)
	if err := cache.Put(one); err != nil {
		t.Fatal(err)
	}
	// A kid is one run's.
	sameKID := lying(tenantTwo, runB, one.KID, one.Wrapped, rawOf(two))
	if err := cache.Put(sameKID); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a kid of another run: %v, want ErrCorrupt", err)
	}
	if _, ok := cache.Get(runB); ok {
		t.Fatal("the refused key was stored")
	}
	if len(cache.DamagedRuns()) != 0 {
		t.Fatal("a refused Put marked a run damaged")
	}
	// What is not a key, or not what it says.
	for name, bad := range map[string]HoldKey{
		"a zero hold key": {},
		"a key with a changed field": func() HoldKey {
			key := two
			key.Tenant = tenantOne
			return key
		}(),
		"a key of a tenant that is not one": lying("Org", runB, two.KID, two.Wrapped, rawOf(two)),
	} {
		if err := cache.Put(bad); err == nil {
			t.Errorf("%s: Put accepted it", name)
		}
	}
	// Replacing a run's key wipes the one before where it lies.
	cache.mu.Lock()
	where := cache.entries[runA].raw
	cache.mu.Unlock()
	next := cloud.hold(t, tenantOne, runA)
	if err := cache.Put(next); err != nil {
		t.Fatal(err)
	}
	if !where.key.wiped || !bytes.Equal(where.key.bytes[:], make([]byte, KeySize)) {
		t.Fatal("the key a run no longer has was not wiped")
	}
	if got, ok := cache.Get(runA); !ok {
		t.Fatal("the new key is not there")
	} else {
		assertKey(t, got, next)
	}
}

func TestCloseWipesEveryKey(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	one, two := cloud.hold(t, tenantOne, runA), cloud.hold(t, tenantTwo, runB)
	cache := openCache(t, path, secret)
	for _, key := range []HoldKey{one, two} {
		if err := cache.Put(key); err != nil {
			t.Fatal(err)
		}
	}
	cache.mu.Lock()
	where := []*keyHolder{cache.entries[runA].raw, cache.entries[runB].raw}
	cache.mu.Unlock()
	// A key handed out before is its holder's.
	handed, ok := cache.Get(runA)
	if !ok {
		t.Fatal("run A's key is not there")
	}
	cache.Close()
	cache.Close() // twice is nothing
	for i, at := range where {
		if !at.key.wiped || !bytes.Equal(at.key.bytes[:], make([]byte, KeySize)) {
			t.Errorf("key %d was not wiped by Close", i)
		}
	}
	if _, ok := cache.Get(runA); ok {
		t.Fatal("a closed cache hands out a key")
	}
	if cache.Damaged(runA) || len(cache.DamagedRuns()) != 0 {
		t.Fatal("a closed cache reports damage")
	}
	if err := cache.Put(one); !errors.Is(err, errHoldCacheClosed) {
		t.Errorf("Put on a closed cache: %v", err)
	}
	if err := cache.Delete(runA); !errors.Is(err, errHoldCacheClosed) {
		t.Errorf("Delete on a closed cache: %v", err)
	}
	if _, err := one.ChunkAEAD(snapA); err != nil {
		t.Fatalf("the caller's key was wiped by the cache's Close: %v", err)
	}
	if _, err := handed.ChunkAEAD(snapA); err != nil {
		t.Fatal("a key handed out was wiped by the cache's Close")
	}
	// The file is as it was.
	again := openCache(t, path, secret)
	defer again.Close()
	if got, ok := again.Get(runB); !ok {
		t.Fatal("Close changed the file")
	} else {
		assertKey(t, got, two)
	}
}

func TestTheCachePrintsNoKey(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	one := cloud.hold(t, tenantOne, runA)
	cache := openCache(t, path, secret)
	defer cache.Close()
	if err := cache.Put(one); err != nil {
		t.Fatal(err)
	}
	if err := (leaks(rawOf(one), secret))(everyVerb(cache)); err != nil {
		t.Fatal(err)
	}
	if s := cache.String(); !strings.Contains(s, path) || !strings.Contains(s, "1 keys") || cache.GoString() != s {
		t.Errorf("String = %q", s)
	}
	if _, err := OpenHoldCache(path, randomBytes(t, hostsecret.Size)); !errors.Is(err, ErrClonedCache) || (leaks(secret))(err.Error()) != nil {
		t.Fatal("the clone verdict says something of the secret")
	}
}

func TestTheCacheIsSafeForConcurrentUse(t *testing.T) {
	cloud := newKMS(t)
	path := filepath.Join(t.TempDir(), HoldCacheFileName)
	secret := randomBytes(t, hostsecret.Size)
	cache := openCache(t, path, secret)
	const runs = 6
	const holds = 8
	keys := make([][]HoldKey, runs)
	for r := range keys {
		keys[r] = make([]HoldKey, holds)
		for h := range keys[r] {
			keys[r][h] = cloud.hold(t, tenantOne, runIDs(r))
		}
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				run := runIDs((worker + i) % runs)
				key := keys[(worker+i)%runs][i%holds]
				switch i % 7 {
				case 0, 1:
					if err := cache.Put(key); err != nil {
						t.Errorf("Put: %v", err)
					}
				case 2:
					_, _ = cache.Get(run)
				case 3:
					_ = cache.Damaged(run)
				case 4:
					_ = cache.DamagedRuns()
				case 5:
					if err := cache.Delete(run); err != nil {
						t.Errorf("Delete: %v", err)
					}
				case 6:
					_ = cache.String()
				}
			}
		}()
	}
	wg.Wait()
	cache.Close()
	// Whatever is on disk opens, whole.
	again := openCache(t, path, secret)
	defer again.Close()
	for r := range keys {
		got, ok := again.Get(runIDs(r))
		if !ok {
			continue
		}
		if got.Run != runIDs(r) || got.Tenant != tenantOne {
			t.Errorf("run %s got the key %s", runIDs(r), got)
		}
		for _, key := range keys[r] {
			if key.KID == got.KID {
				assertKey(t, got, key)
			}
		}
	}
}

func runIDs(n int) string {
	// 26 characters of the ULID alphabet, distinct per n.
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	run := []byte(strings.Repeat("0", 26))
	run[25] = alphabet[n%len(alphabet)]
	run[24] = alphabet[(n/len(alphabet))%len(alphabet)]
	return string(run)
}
