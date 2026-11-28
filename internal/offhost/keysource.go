package offhost

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// A key source is where a daemon that writes v2 gets hold keys: the
// KMS's side of key custody, as far as a host sees it. One interface,
// two sources (--remote-kms):
//
//   - pushed: served from what Cloud pushed. A key this host was not
//     given is answered with ErrNeedKey, and Cloud pushes it.
//   - local: a fleet without Cloud is its own KMS. Each tenant's key is
//     derived from the root key file, and nothing is ever "need key".
//
// With neither, a daemon writes and reads v1 as before, and nothing
// here is used.

// ErrNeedKey: the source cannot open a wrapped hold key now, because the
// key was not pushed to it. It is not that the blob is wrong.
var ErrNeedKey = errors.New("the key source does not hold the key this object is under")

// KeyNeed names one hold key a host needs: the run it is for, and the
// wrapped blob it is named by. Nothing here is secret: a blob is in the
// envelope, in the bucket, in the clear.
type KeyNeed struct {
	Tenant  string
	Run     string
	KID     string
	Wrapped string
}

// NeedKeyError is ErrNeedKey with what is missing: what a daemon answers
// with when it lacks a chain's key (428, needKeys), for Cloud to unwrap
// and push. It never holds a key's bytes.
type NeedKeyError struct {
	Missing []KeyNeed
}

func (e *NeedKeyError) Error() string {
	var out bytes.Buffer
	out.WriteString("need the hold key")
	if len(e.Missing) != 1 {
		out.WriteString("s")
	}
	for _, need := range e.Missing {
		fmt.Fprintf(&out, " of run %s (tenant %s, key %s)", need.Run, need.Tenant, need.KID)
	}
	return out.String()
}

// Unwrap makes errors.Is(err, ErrNeedKey) answer true.
func (e *NeedKeyError) Unwrap() error { return ErrNeedKey }

// KeySource mints and opens the hold keys of a fleet's runs.
type KeySource interface {
	// Mint makes a new hold key for a run of tenant: the key a host is
	// given when it becomes the run's holder.
	Mint(tenant, run string) (HoldKey, error)
	// Unwrap opens the hold key a wrapped blob names, as the key of run
	// of tenant. ErrNeedKey when this source does not hold it; ErrCorrupt
	// when it was not wrapped for that tenant and run; ErrWrongKey when
	// it names a tenant key version this source has not.
	Unwrap(tenant, run, wrapped string) (HoldKey, error)
	// Rewrap returns the blob under the current tenant key version, the
	// key's bytes unchanged, after verifying it opens for tenant and run.
	// A source that cannot says so.
	Rewrap(tenant, run, wrapped string) (string, error)
}

var (
	_ KeySource = (*LocalKeySource)(nil)
	_ KeySource = (*PushedKeySource)(nil)
)

// LocalKeySource is the KMS of a fleet without Cloud. Every tenant's key
// is derived from the root key file:
//
//	TK[tenant, version] = HKDF-SHA256(root[version], nil,
//	                                   "teploy-sandbox/v2/tenant-kek/<tenant>", 32)
//
// The root file's rotation is a new version: new hold keys are wrapped
// under it, old ones open under the version their blob names, and a
// re-wrap pass moves them. A blob is always opened under the one
// version it names, never by trying the versions at hand.
//
// What this does not give is isolation: every host with the file has
// every tenant's key, and tenant is a label. Both Unwrap and Rewrap
// still enforce that the blob names the expected tenant and run.
type LocalKeySource struct {
	mu sync.RWMutex
	// current is the version new hold keys are wrapped under.
	current int
	// roots are the root keys by version, as many as are still to open.
	roots map[int]*keyHolder
}

// NewLocalKeySource makes a source on root key root, version 1.
func NewLocalKeySource(root []byte) (*LocalKeySource, error) {
	return NewLocalKeySourceWithVersion(1, root)
}

// NewLocalKeySourceWithVersion makes a source on root key root, which is
// tenant key version version (1 or later): a rotated root file is the
// next version, and the file before it goes in with AddPrevious.
func NewLocalKeySourceWithVersion(version int, root []byte) (*LocalKeySource, error) {
	if version < 1 {
		return nil, fmt.Errorf("a tenant key version is a number from 1 up, not %d", version)
	}
	if len(root) != KeySize {
		return nil, fmt.Errorf("a root key is %d bytes, got %d", KeySize, len(root))
	}
	return &LocalKeySource{current: version, roots: map[int]*keyHolder{version: rootRaw(root)}}, nil
}

// Version is the tenant key version new hold keys are wrapped under.
func (l *LocalKeySource) Version() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.current
}

// AddPrevious lets the source open, never wrap with, the root key of an
// earlier version. A version that is not earlier than the current one,
// one already known, or the same key as another version is refused.
func (l *LocalKeySource) AddPrevious(version int, root []byte) error {
	if version < 1 {
		return fmt.Errorf("a tenant key version is a number from 1 up, not %d", version)
	}
	if len(root) != KeySize {
		return fmt.Errorf("a root key is %d bytes, got %d", KeySize, len(root))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if version >= l.current {
		return fmt.Errorf("a previous tenant key version is earlier than %d, not %d", l.current, version)
	}
	if _, known := l.roots[version]; known {
		return fmt.Errorf("tenant key version %d is already known", version)
	}
	for other, key := range l.roots {
		if bytes.Equal(key.key.bytes[:], root) {
			return fmt.Errorf("the root key given for version %d is the root key of version %d", version, other)
		}
	}
	l.roots[version] = rootRaw(root)
	return nil
}

// String and GoString name the source; neither shows a key.
func (l *LocalKeySource) String() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return fmt.Sprintf("local key source (tenant key version %d, %d previous)", l.current, len(l.roots)-1)
}

// GoString is String, for `%#v`.
func (l *LocalKeySource) GoString() string { return l.String() }

// root is the root key of one version, and only that one.
func (l *LocalKeySource) root(version int) (*keyHolder, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	root, known := l.roots[version]
	if !known {
		return nil, fmt.Errorf("%w (tenant key version %d, this source is at %d)", ErrWrongKey, version, l.current)
	}
	return root, nil
}

// tenantKey derives the tenant key of tenant from the root key of one
// version. The caller wipes what it gets.
func (l *LocalKeySource) tenantKey(version int, tenant string) ([]byte, error) {
	root, err := l.root(version)
	if err != nil {
		return nil, err
	}
	return TenantKey(root.key.bytes[:], tenant)
}

// Mint makes a new hold key for a run of tenant, with a kid of its own,
// wrapped under the current tenant key version.
func (l *LocalKeySource) Mint(tenant, run string) (HoldKey, error) {
	if !ValidTenant(tenant) {
		return HoldKey{}, fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	if !validAADSegment(run) {
		return HoldKey{}, invalidSegment("run ID", run)
	}
	version := l.Version()
	tk, err := l.tenantKey(version, tenant)
	if err != nil {
		return HoldKey{}, err
	}
	defer clear(tk)
	var (
		raw [KeySize]byte
		id  [kidBytes]byte
	)
	if _, err := rand.Read(raw[:]); err != nil {
		return HoldKey{}, err
	}
	defer clear(raw[:])
	if _, err := rand.Read(id[:]); err != nil {
		return HoldKey{}, err
	}
	kid := hex.EncodeToString(id[:])
	wrapped, err := WrapHoldKey(tk, raw[:], tenant, run, kid, version)
	if err != nil {
		return HoldKey{}, err
	}
	return NewHoldKey(tenant, run, kid, wrapped, raw[:])
}

// Unwrap opens a wrapped hold key under the tenant and the version it
// names, for tenant and run: another tenant's or run's blob does not
// open (ErrCorrupt), and a version this source has not is ErrWrongKey,
// not an attempt with another.
func (l *LocalKeySource) Unwrap(tenant, run, wrapped string) (HoldKey, error) {
	if !ValidTenant(tenant) {
		return HoldKey{}, fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	if !validAADSegment(run) {
		return HoldKey{}, invalidSegment("run ID", run)
	}
	parsed, err := ParseWrappedHoldKey(wrapped)
	if err != nil {
		return HoldKey{}, err
	}
	if parsed.Tenant != tenant {
		return HoldKey{}, fmt.Errorf("%w: the wrapped hold key %s is for tenant %s, not %s",
			ErrCorrupt, parsed.KID, parsed.Tenant, tenant)
	}
	tk, err := l.tenantKey(parsed.TKVersion, parsed.Tenant)
	if err != nil {
		return HoldKey{}, err
	}
	defer clear(tk)
	return UnwrapHoldKey(tk, run, wrapped)
}

// Rewrap returns the blob under the current tenant key version, the
// key's bytes unchanged, so that nothing sealed under the key moves. A
// blob already under the current version is still unwrapped and verified
// for tenant and run before being returned as is.
func (l *LocalKeySource) Rewrap(tenant, run, wrapped string) (string, error) {
	parsed, err := ParseWrappedHoldKey(wrapped)
	if err != nil {
		return "", err
	}
	key, err := l.Unwrap(tenant, run, wrapped)
	if err != nil {
		return "", err
	}
	defer key.Zero()
	version := l.Version()
	if parsed.TKVersion == version {
		return wrapped, nil
	}
	tk, err := l.tenantKey(version, key.Tenant)
	if err != nil {
		return "", err
	}
	defer clear(tk)
	return WrapHoldKey(tk, key.raw.key.bytes[:], key.Tenant, key.Run, key.KID, version)
}

// PushedKeySource is served from what Cloud pushed: it mints nothing
// and holds exactly the keys it was given, each known by its kid.
//
// A blob is answered by the kid it names and by nothing else. A key is
// given out only for the tenant and run it was pushed for: a blob of
// another run or another tenant never gets this host's key (ErrCorrupt).
// A re-wrapped blob of the same kid, tenant, and run still opens using
// the held key, because the key's bytes did not change.
//
// Keys supplied with Supply are held persistently until Forget; keys
// supplied with SupplyEphemeral are reference-counted and wiped+dropped
// as soon as their release closure runs (unless also held).
type PushedKeySource struct {
	mu        sync.Mutex
	keys      map[string]HoldKey // by kid
	held      map[string]bool    // kids supplied persistently via Supply
	ephemeral map[string]int     // active SupplyEphemeral refcounts by kid
}

// NewPushedKeySource makes an empty source: Cloud fills it.
func NewPushedKeySource() *PushedKeySource {
	return &PushedKeySource{
		keys:      map[string]HoldKey{},
		held:      map[string]bool{},
		ephemeral: map[string]int{},
	}
}

// String names the source without showing a key (see LocalKeySource).
func (p *PushedKeySource) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("pushed key source (%d hold keys)", len(p.keys))
}

// GoString is String, for `%#v`.
func (p *PushedKeySource) GoString() string { return p.String() }

// errNotMintedHere: keys are minted by Cloud and pushed; a host makes
// none.
var errNotMintedHere = errors.New("in pushed mode Cloud mints hold keys and pushes them to the host that holds the run: a host mints none")

// errNotRewrappedHere: in pushed mode Cloud re-wraps; a blob is Cloud's.
var errNotRewrappedHere = errors.New("in pushed mode Cloud re-wraps hold keys and pushes them again: a host re-wraps none")

// Mint answers that a host in pushed mode mints nothing.
func (p *PushedKeySource) Mint(tenant, run string) (HoldKey, error) {
	return HoldKey{}, errNotMintedHere
}

// Rewrap answers that a host in pushed mode re-wraps nothing.
func (p *PushedKeySource) Rewrap(tenant, run, wrapped string) (string, error) {
	return "", errNotRewrappedHere
}

// Supply stores hold keys Cloud pushed, each with its own copy of its
// bytes. All are checked before any is stored, and one that is not a
// hold key (a field that is not what it says, a wrapped blob that names
// another key, bytes of another length) refuses the lot.
//
// A kid is one key. A kid pushed again is accepted only as the same key:
// the same bytes for the same run and tenant. Its wrapped blob may
// differ, as it does once Cloud has re-wrapped it, and the new blob is
// what is held from then on.
func (p *PushedKeySource) Supply(keys ...HoldKey) error {
	_, err := p.supply(true, keys...)
	return err
}

// SupplyEphemeral temporarily supplies open keys for the duration of a
// restore. Calling the returned release function decrements their
// reference counts and wipes+drops any key that is not persistently held
// once no caller still borrows it. Safe to call release multiple times.
func (p *PushedKeySource) SupplyEphemeral(keys ...HoldKey) (func(), error) {
	kids, err := p.supply(false, keys...)
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			for _, kid := range kids {
				if p.ephemeral[kid] > 1 {
					p.ephemeral[kid]--
					continue
				}
				delete(p.ephemeral, kid)
				if !p.held[kid] {
					if key, ok := p.keys[kid]; ok {
						key.Zero()
						delete(p.keys, kid)
					}
				}
			}
		})
	}, nil
}

func (p *PushedKeySource) supply(held bool, keys ...HoldKey) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	// Copies, one per kid in the batch.
	var stored []HoldKey
	byKID := make(map[string]int, len(keys))
	committed := false
	defer func() {
		if !committed {
			for _, key := range stored {
				key.Zero()
			}
		}
	}()
	for _, key := range keys {
		copy, err := key.clone()
		if err != nil {
			return nil, fmt.Errorf("hold key %s: %w", quoted(key.KID), err)
		}
		if first, ok := byKID[copy.KID]; ok {
			if err := sameKey(stored[first], copy); err != nil {
				copy.Zero()
				return nil, fmt.Errorf("hold key %s is pushed twice in one batch: %w", quoted(copy.KID), err)
			}
			copy.Zero() // one copy of one key is enough
			continue
		}
		byKID[copy.KID] = len(stored)
		stored = append(stored, copy)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range stored {
		if existing, ok := p.keys[key.KID]; ok {
			if err := sameKey(existing, key); err != nil {
				return nil, fmt.Errorf("hold key %s is pushed again: %w", quoted(key.KID), err)
			}
		}
	}
	if p.keys == nil {
		p.keys = make(map[string]HoldKey)
	}
	if p.held == nil {
		p.held = make(map[string]bool)
	}
	if p.ephemeral == nil {
		p.ephemeral = make(map[string]int)
	}
	committed = true
	kids := make([]string, 0, len(stored))
	for _, key := range stored {
		kids = append(kids, key.KID)
		if existing, ok := p.keys[key.KID]; ok {
			if held {
				existing.Zero()
				p.keys[key.KID] = key
				p.held[key.KID] = true
			} else {
				key.Zero()
				p.ephemeral[key.KID]++
			}
		} else {
			p.keys[key.KID] = key
			if held {
				p.held[key.KID] = true
			} else {
				p.ephemeral[key.KID] = 1
			}
		}
	}
	return kids, nil
}

// sameKey is whether two hold keys of one kid are the one key: the same
// bytes, for the same run and tenant. The wrapped blob may differ, as it
// does after a re-wrap.
func sameKey(a, b HoldKey) error {
	if a.Tenant != b.Tenant || a.Run != b.Run {
		return fmt.Errorf("%w: key %s is pushed for run %s of tenant %s and for run %s of tenant %s",
			ErrCorrupt, a.KID, a.Run, a.Tenant, b.Run, b.Tenant)
	}
	if !bytes.Equal(a.raw.key.bytes[:], b.raw.key.bytes[:]) {
		return fmt.Errorf("%w: key %s is pushed with other bytes than the ones held", ErrCorrupt, a.KID)
	}
	return nil
}

// Forget wipes a pushed key's bytes and drops it: Cloud's own delete of
// the run on this host, or local retention running out. A kid this
// source does not hold is nothing. If an ephemeral restore is still
// borrowing the same kid, it is wiped when that restore finishes.
func (p *PushedKeySource) Forget(kid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.held, kid)
	if p.ephemeral[kid] == 0 {
		if key, ok := p.keys[kid]; ok {
			key.Zero()
			delete(p.keys, kid)
		}
	}
}

// Unwrap opens the hold key the blob names, as the key of run of tenant.
// A kid this source was not pushed is ErrNeedKey, naming what is missing.
// One it holds for another run or tenant is ErrCorrupt, and the key it
// holds is not given out. A re-wrapped blob of the same kid, tenant, and
// run opens with the held key (the sealed section's AAD does not bind
// the wrapping spelling). The key returned is a copy of this source's:
// wiping it wipes no one else's.
func (p *PushedKeySource) Unwrap(tenant, run, wrapped string) (HoldKey, error) {
	if !ValidTenant(tenant) {
		return HoldKey{}, fmt.Errorf("%w: %s is not a tenant", ErrCorrupt, quoted(tenant))
	}
	if !validAADSegment(run) {
		return HoldKey{}, invalidSegment("run ID", run)
	}
	parsed, err := ParseWrappedHoldKey(wrapped)
	if err != nil {
		return HoldKey{}, err
	}
	if parsed.Tenant != tenant {
		return HoldKey{}, fmt.Errorf("%w: the wrapped hold key %s is for tenant %s, not %s",
			ErrCorrupt, parsed.KID, parsed.Tenant, tenant)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	held, ok := p.keys[parsed.KID]
	if !ok {
		return HoldKey{}, &NeedKeyError{Missing: []KeyNeed{{Tenant: parsed.Tenant, Run: run, KID: parsed.KID, Wrapped: wrapped}}}
	}
	if held.Tenant != tenant || held.Run != run {
		return HoldKey{}, fmt.Errorf("%w: the wrapped hold key %s is not the key this host holds for run %s of tenant %s",
			ErrCorrupt, parsed.KID, run, tenant)
	}
	return held.clone()
}
