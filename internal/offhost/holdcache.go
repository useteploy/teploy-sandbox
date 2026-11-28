package offhost

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/useteploy/teploy-sandbox/internal/hostsecret"
)

// The host's hold-key cache: the current hold key of every run this
// host holds, on disk in the state directory, so that a daemon that
// restarts while Cloud is down still owes, and finishes, its uploads.
//
// The file is sealed under a key derived from the host's secret
// (internal/hostsecret: random, 0600, outside the state directory, in
// no backup), so that a copy of the state directory on another machine
// opens nothing. Two things can be wrong with it, and they are told
// apart by their cause:
//
//   - the header does not open under this host's secret at all: the
//     state directory was cloned or restored elsewhere, every entry is
//     the wrong host's, and the daemon must not start (ErrClonedCache);
//   - one entry does not open or is not valid: that one run's key is
//     damaged or missing, and that one run goes to "needs-key" for Cloud
//     to push again (DamagedRuns). The others load.
//
// Every entry is sealed on its own, under an AAD naming the run, tenant
// and key it is for: one is damaged without the rest, and none can be
// moved to another run.
//
//   key     HKDF-SHA256(host secret, nil, "teploy-sandbox/v2/hold-cache", 32)
//   header  AAD "teploy-sandbox/v2/hold-cache-header"
//   entry   AAD "teploy-sandbox/v2/hold-cache-entry/<tenant>/<run>/<kid>"
//
// The file is replaced whole (a temporary file beside it, fsynced,
// renamed), and is 0600. Erasing a key is best effort, as it is on any
// SSD or copy-on-write filesystem: the bytes of the file it was in may
// outlive it until the device reuses them.

// HoldCacheFileName is the cache's name inside the state directory.
const HoldCacheFileName = "hold-keys.json"

const (
	// holdCacheFormat is the file's format, as its header says.
	holdCacheFormat = 1
	holdCacheMagic  = "teploy-sandbox hold-key cache"
	// maxHoldCacheBytes bounds the file read: an entry is under a
	// kilobyte, and a host holds nothing like a hundred thousand runs.
	maxHoldCacheBytes = 64 << 20
)

var (
	// ErrClonedCache: the cache's header does not open under this host's
	// secret. The state directory was cloned or restored from another
	// host; nothing in it is this host's to use.
	ErrClonedCache = errors.New("hold-key cache does not open under this host's secret (cloned or restored state directory)")
	// ErrNotHoldCache: there is a file where the cache should be, and it
	// is not one this daemon wrote: empty, cut short, of another format.
	// Not a clone (the header opened, or there is none to open).
	ErrNotHoldCache = errors.New("the file is not a hold-key cache")
	// ErrCacheReadable: the cache file is readable by others than its
	// owner.
	ErrCacheReadable = errors.New("the hold-key cache is readable by others than its owner")

	errHoldCacheClosed = errors.New("the hold-key cache is closed")
)

// cachedEntry is one run's key in the file: what the entry's AAD names,
// in the clear, and the entry itself.
type cachedEntry struct {
	Tenant  string `json:"tenant"`
	KID     string `json:"kid"`
	Wrapped string `json:"wrapped"`
	// Sealed is base64(nonce ‖ raw key ‖ wrapped blob ‖ tag): the key's
	// bytes, bound to the blob they are stored as.
	Sealed string `json:"sealed"`
}

// cacheFile is the whole file as it is read. Each entry is decoded on
// its own (see load): the file is this daemon's or it is not, and an
// entry is that run's.
type cacheFile struct {
	// Header is base64(nonce ‖ header ‖ tag) under the cache key: what
	// only this host's secret opens.
	Header  string                     `json:"header"`
	Entries map[string]json.RawMessage `json:"entries"`
}

// cacheHeader is the header's plaintext: a fixed magic and the format.
type cacheHeader struct {
	Magic  string `json:"magic"`
	Format int    `json:"format"`
}

// HoldCache is a host's hold keys, in memory and on disk. Safe for use
// from several goroutines.
type HoldCache struct {
	mu   sync.Mutex
	path string
	aead cipher.AEAD
	// entries are the runs' current hold keys by run ID; sealed is each
	// one's entry as it is on disk, sealed once when it was put.
	entries map[string]HoldKey
	sealed  map[string]string
	// runs is which run each kid is the key of: a kid is one run's.
	runs map[string]string
	// damaged holds the raw JSON of runs whose entry did not open or was
	// not valid, preserved across unrelated writes until repaired by Put
	// or removed by Delete.
	damaged map[string]json.RawMessage
	closed  bool
}

// OpenHoldCache opens the cache at path under the host's secret. A
// cache that is not there yet is empty, and is written when a key is
// first put. One that is there is read whole first: ErrClonedCache when
// its header does not open under this host's secret; ErrNotHoldCache
// when the file is not one; otherwise every entry is opened on its own,
// and one that does not is only that run's (DamagedRuns).
func OpenHoldCache(path string, hostSecret []byte) (*HoldCache, error) {
	if len(hostSecret) != hostsecret.Size {
		return nil, fmt.Errorf("a host secret is %d bytes, got %d", hostsecret.Size, len(hostSecret))
	}
	aead, err := deriveAEAD(hostSecret, labelV2+"hold-cache")
	if err != nil {
		return nil, err
	}
	cache := &HoldCache{
		path:    path,
		aead:    aead,
		entries: make(map[string]HoldKey),
		sealed:  make(map[string]string),
		runs:    make(map[string]string),
		damaged: make(map[string]json.RawMessage),
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		// Where it will be written is made now, so that a path that
		// cannot hold it is refused here and not at the first key.
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		return cache, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := ownerOnly(path, info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	// What is read is what was checked: the mode and owner are looked at
	// again on the open file, not only on the name.
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := ownerOnly(path, opened); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxHoldCacheBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxHoldCacheBytes {
		return nil, fmt.Errorf("%s is larger than a hold-key cache is (%d bytes at most)", path, maxHoldCacheBytes)
	}
	if err := cache.load(data); err != nil {
		return nil, err
	}
	return cache, nil
}

// ownerOnly refuses a file others than its owner could read or write, or
// one not owned by the daemon's user. A symlink is not a regular file
// and is refused before this.
func ownerOnly(path string, info fs.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o; chmod 600 it", ErrCacheReadable, path, perm)
	}
	if owner := holdCacheOwnerOf(info); owner >= 0 && owner != os.Geteuid() {
		return fmt.Errorf("%s belongs to uid %d, and the daemon runs as %d", path, owner, os.Geteuid())
	}
	return nil
}

// load reads the file: its header first, and the whole verdict on the
// cache hangs on that; then each entry on its own, decoded and opened,
// so that one that cannot be is that run's damage and nothing more.
func (c *HoldCache) load(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: %s is empty; remove it, and every run it held asks Cloud for its key again", ErrNotHoldCache, c.path)
	}
	var file cacheFile
	if err := oneJSONDocument(data); err != nil {
		return fmt.Errorf("%w: %s %v", ErrNotHoldCache, c.path, err)
	}
	if err := decodeJSON(data, &file, true); err != nil {
		return fmt.Errorf("%w: %s %v", ErrNotHoldCache, c.path, err)
	}
	if err := c.checkHeader(file.Header); err != nil {
		return err
	}
	// In a fixed order, so that of two entries under one kid the same
	// one is kept whichever way the map is walked.
	runs := make([]string, 0, len(file.Entries))
	for run := range file.Entries {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	for _, run := range runs {
		var entry cachedEntry
		err := oneJSONDocument(file.Entries[run])
		if err == nil {
			err = decodeJSON(file.Entries[run], &entry, true)
		}
		if err == nil {
			var key HoldKey
			if key, err = c.openEntry(run, entry); err == nil {
				if other, ok := c.runs[key.KID]; ok && other != run {
					err = fmt.Errorf("key %s is also the key of run %s", key.KID, other)
				} else {
					c.entries[run] = key
					c.sealed[run] = entry.Sealed
					c.runs[key.KID] = run
				}
			}
		}
		if err != nil {
			raw := bytes.Clone(file.Entries[run])
			if len(raw) == 0 {
				raw = json.RawMessage("null")
			}
			c.damaged[run] = raw
		}
	}
	return nil
}

// checkHeader opens the file's header under the cache key. That it does
// not open is the one verdict on the whole cache: another host's secret
// sealed it (ErrClonedCache). That it opens and is not what this daemon
// writes is another thing altogether (ErrNotHoldCache).
func (c *HoldCache) checkHeader(sealed string) error {
	notOne := func(why string) error {
		return fmt.Errorf("%w: %s %s", ErrNotHoldCache, c.path, why)
	}
	ciphertext, err := decodeBase64(sealed)
	if err != nil || len(ciphertext) < c.aead.NonceSize()+tagSize {
		return notOne("has no header")
	}
	nonce, body := ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, body, []byte(labelV2+"hold-cache-header"))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrClonedCache, c.path)
	}
	var header cacheHeader
	if err := oneJSONDocument(plain); err != nil {
		return notOne("has a header that is not one")
	}
	if err := decodeJSON(plain, &header, true); err != nil {
		return notOne("has a header that is not one")
	}
	if header.Magic != holdCacheMagic {
		return notOne("was not written as a hold-key cache")
	}
	if header.Format != holdCacheFormat {
		return notOne(fmt.Sprintf("was written in format %d, and this daemon reads %d", header.Format, holdCacheFormat))
	}
	return nil
}

// sealHeader is a fresh header.
func (c *HoldCache) sealHeader() (string, error) {
	plain, err := json.Marshal(cacheHeader{Magic: holdCacheMagic, Format: holdCacheFormat})
	if err != nil {
		return "", err
	}
	sealed, err := sealSection(c.aead, plain, []byte(labelV2+"hold-cache-header"))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// entryAAD is what one entry is bound to.
func entryAAD(tenant, run, kid string) []byte {
	return []byte(labelV2 + "hold-cache-entry/" + tenant + "/" + run + "/" + kid)
}

// sealEntry seals a key's bytes together with the blob they are stored
// as: an entry whose blob is edited in the file does not open.
func (c *HoldCache) sealEntry(key HoldKey) (string, error) {
	if _, err := key.key(); err != nil {
		return "", err
	}
	plain := make([]byte, 0, KeySize+len(key.Wrapped))
	plain = append(plain, key.raw.key.bytes[:]...)
	plain = append(plain, key.Wrapped...)
	defer clear(plain)
	sealed, err := sealSection(c.aead, plain, entryAAD(key.Tenant, key.Run, key.KID))
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// openEntry opens one entry as the hold key of run. Any failure is that
// entry's: authentication, a field that is not what it says, bytes of
// another length, a blob in the clear that is not the sealed one.
func (c *HoldCache) openEntry(run string, entry cachedEntry) (HoldKey, error) {
	if !validAADSegment(run) {
		return HoldKey{}, invalidSegment("run ID", run)
	}
	if !ValidTenant(entry.Tenant) || !ValidKID(entry.KID) {
		return HoldKey{}, errors.New("the entry does not name a tenant and a key")
	}
	parsed, err := ParseWrappedHoldKey(entry.Wrapped)
	if err != nil || parsed.Tenant != entry.Tenant || parsed.KID != entry.KID {
		return HoldKey{}, errors.New("the entry's wrapped blob is not the key it names")
	}
	ciphertext, err := decodeBase64(entry.Sealed)
	if err != nil || len(ciphertext) < c.aead.NonceSize()+tagSize+KeySize+1 {
		return HoldKey{}, errors.New("the entry is not one")
	}
	nonce, body := ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():]
	plain, err := c.aead.Open(nil, nonce, body, entryAAD(entry.Tenant, run, entry.KID))
	if err != nil {
		return HoldKey{}, errors.New("the entry does not open")
	}
	defer clear(plain)
	if len(plain) <= KeySize || string(plain[KeySize:]) != entry.Wrapped {
		return HoldKey{}, errors.New("the entry's sealed blob is not the one in the clear")
	}
	return NewHoldKey(entry.Tenant, run, entry.KID, entry.Wrapped, plain[:KeySize])
}

// Put stores a run's current hold key on disk and then in memory. A run
// has one entry: the key it had is wiped and replaced. A kid is one
// run's, and one that is already another run's is refused. A run marked
// damaged is repaired.
//
// Nothing is committed in memory until the file is replaced atomically:
// a caller (such as POST /v1/runs/{id}/keys) must not acknowledge a key
// that did not reach disk. If Put was superseding an older key (another
// kid) and the atomic replace fails, the old key is wiped from memory
// and best-effort removed from the on-disk file so a restart never
// resurrects a superseded key.
func (c *HoldCache) Put(key HoldKey) error {
	stored, err := key.clone()
	if err != nil {
		return err
	}
	kept := false
	defer func() {
		if !kept {
			stored.Zero()
		}
	}()
	sealed, err := c.sealEntry(stored)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errHoldCacheClosed
	}
	if other, ok := c.runs[stored.KID]; ok && other != stored.Run {
		return fmt.Errorf("%w: hold key %s is already the key of run %s, and is put for run %s",
			ErrCorrupt, stored.KID, other, stored.Run)
	}
	data, err := c.marshalWith(stored, sealed)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(c.path, data); err != nil {
		if old, hadOld := c.entries[stored.Run]; hadOld && old.KID != stored.KID {
			// Superseding an old key failed to persist atomically: wipe
			// the old key from memory and best-effort remove it from the
			// existing file in place so a restart never resurrects it.
			old.Zero()
			delete(c.entries, stored.Run)
			delete(c.sealed, stored.Run)
			delete(c.runs, old.KID)
			if withoutOld, mErr := c.marshalCurrent(); mErr == nil {
				_ = writeFileInPlace(c.path, withoutOld)
			}
		}
		return err
	}
	if old, ok := c.entries[stored.Run]; ok {
		old.Zero()
		delete(c.runs, old.KID)
	}
	c.entries[stored.Run] = stored
	c.sealed[stored.Run] = sealed
	c.runs[stored.KID] = stored.Run
	delete(c.damaged, stored.Run)
	kept = true
	return nil
}

// Get is a run's current hold key: a copy, this cache's own to wipe.
// False when the run has none here, or its entry was damaged.
func (c *HoldCache) Get(runID string) (HoldKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return HoldKey{}, false
	}
	key, ok := c.entries[runID]
	if !ok {
		return HoldKey{}, false
	}
	copy, err := key.clone()
	if err != nil {
		return HoldKey{}, false
	}
	return copy, true
}

// Damaged says whether run's entry did not open or was not valid when
// the cache was read: the run's key is not here, and it is Cloud's to
// push again. Repaired by Put.
func (c *HoldCache) Damaged(runID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.damaged[runID]
	return ok
}

// DamagedRuns lists them, sorted.
func (c *HoldCache) DamagedRuns() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var runs []string
	for run := range c.damaged {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	return runs
}

// All returns clones of every intact hold key in the cache, sorted by run ID.
// Callers must Zero each returned HoldKey once supplied.
func (c *HoldCache) All() ([]HoldKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errHoldCacheClosed
	}
	if len(c.entries) == 0 {
		return nil, nil
	}
	runs := make([]string, 0, len(c.entries))
	for run := range c.entries {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	out := make([]HoldKey, 0, len(runs))
	for _, run := range runs {
		clone, err := c.entries[run].clone()
		if err != nil {
			for i := range out {
				out[i].Zero()
			}
			return nil, fmt.Errorf("clone cached hold key for run %s: %w", run, err)
		}
		out = append(out, clone)
	}
	return out, nil
}

// Delete removes a run's key: its bytes are wiped, its entry and its
// damaged mark are gone from the file. A run with neither is nothing,
// and writes nothing. An error is that the file could not be replaced:
// the key is gone from memory all the same, and is in the file until a
// later write, or a Delete once the disk is back.
func (c *HoldCache) Delete(runID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errHoldCacheClosed
	}
	old, held := c.entries[runID]
	_, damaged := c.damaged[runID]
	if !held && !damaged {
		return nil
	}
	if held {
		old.Zero()
		delete(c.entries, runID)
		delete(c.sealed, runID)
		delete(c.runs, old.KID)
	}
	delete(c.damaged, runID)
	return c.persist()
}

// marshalCurrent encodes the cache's current entries plus preserved
// damaged entries. Under the lock.
func (c *HoldCache) marshalCurrent() ([]byte, error) {
	return c.marshalOverlay(nil, "")
}

// marshalWith encodes the cache as it will look once key/sealed are
// installed (removing any damaged mark for key.Run). Under the lock.
func (c *HoldCache) marshalWith(key HoldKey, sealed string) ([]byte, error) {
	return c.marshalOverlay(&key, sealed)
}

func (c *HoldCache) marshalOverlay(add *HoldKey, addSealed string) ([]byte, error) {
	header, err := c.sealHeader()
	if err != nil {
		return nil, err
	}
	file := cacheFile{Header: header, Entries: make(map[string]json.RawMessage, len(c.entries)+len(c.damaged)+1)}
	for run, raw := range c.damaged {
		if add != nil && run == add.Run {
			continue
		}
		file.Entries[run] = raw
	}
	for run, key := range c.entries {
		if add != nil && run == add.Run {
			continue
		}
		entry, err := json.Marshal(cachedEntry{Tenant: key.Tenant, KID: key.KID, Wrapped: key.Wrapped, Sealed: c.sealed[run]})
		if err != nil {
			return nil, err
		}
		file.Entries[run] = entry
	}
	if add != nil {
		entry, err := json.Marshal(cachedEntry{Tenant: add.Tenant, KID: add.KID, Wrapped: add.Wrapped, Sealed: addSealed})
		if err != nil {
			return nil, err
		}
		file.Entries[add.Run] = entry
	}
	return json.Marshal(file)
}

// persist replaces the file with what the cache holds. Under the lock.
func (c *HoldCache) persist() error {
	data, err := c.marshalCurrent()
	if err != nil {
		return err
	}
	return writeFileAtomic(c.path, data)
}

// writeFileInPlace overwrites an existing cache file without creating a
// sibling temp file (used only as a best-effort fallback when atomic
// replace fails while superseding an old key, e.g., read-only directory).
func writeFileInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Close wipes every key the cache holds in memory and empties it. The
// file is left as it is. Copies handed out by Get are their holders'.
func (c *HoldCache) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for run, key := range c.entries {
		key.Zero()
		delete(c.entries, run)
	}
	clear(c.sealed)
	clear(c.runs)
	clear(c.damaged)
	c.closed = true
}

// String names the cache without showing a key; GoString, for `%#v`.
func (c *HoldCache) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprintf("hold-key cache at %s (%d keys, %d damaged)", c.path, len(c.entries), len(c.damaged))
}

// GoString is String, for `%#v`.
func (c *HoldCache) GoString() string { return c.String() }

// writeFileAtomic replaces path with data: a temporary file beside it
// (0600, the mode it keeps), fsynced, renamed over it, and the
// directory's entry with it. A crash leaves the old file, the new one or
// none, never part of one.
func writeFileAtomic(path string, data []byte) (result error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// The rename is only durable once the directory entry is.
	if opened, err := os.Open(dir); err == nil {
		_ = opened.Sync()
		_ = opened.Close()
	}
	return nil
}
