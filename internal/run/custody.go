package run

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
)

// RemoteNeedsKey is a stopped run whose hold key is missing or damaged in
// this host's hold-key cache (key custody, pushed mode). The local copy is
// kept and Cloud repairs it via POST /v1/runs/{id}/keys.
const RemoteNeedsKey = "needs-key"

// DefaultTenant is the tenant a run belongs to in custody mode when none is
// named.
const DefaultTenant = "default"

// LegacyKID marks a pre-custody (v1) run in expect.kid: the only way v1
// envelopes are read for a non-base object in pushed mode.
const LegacyKID = "v1"

// ValidTenant reports whether s is a valid tenant ID: [a-z0-9-]{1,64}.
func ValidTenant(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// ValidKID reports whether s is a valid hold key ID (32 lowercase hex digits).
func ValidKID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// KeyNeed names one hold key this daemon lacks and needs Cloud to unwrap and
// push (428 Precondition Required). Nothing here is secret.
type KeyNeed struct {
	Tenant  string `json:"tenant"`
	Run     string `json:"run"`
	KID     string `json:"kid"`
	Wrapped string `json:"wrapped"`
}

// NeedKeyError is ErrRemoteNeedKey carrying the exact wrapped blobs Cloud must
// unwrap and push. It never holds raw key material.
type NeedKeyError struct {
	Missing []KeyNeed
	Cause   error
}

func (e *NeedKeyError) Error() string {
	var b strings.Builder
	b.WriteString("need the hold key")
	if len(e.Missing) != 1 {
		b.WriteString("s")
	}
	for _, n := range e.Missing {
		fmt.Fprintf(&b, " of run %s (tenant %s, key %s)", n.Run, n.Tenant, n.KID)
	}
	return b.String()
}

func (e *NeedKeyError) Unwrap() []error {
	if e.Cause != nil {
		return []error{ErrRemoteNeedKey, e.Cause}
	}
	return []error{ErrRemoteNeedKey}
}

// PushedKey is one unwrapped hold key pushed by Cloud in a request body.
// Its String, GoString, and LogValue methods always redact Raw.
type PushedKey struct {
	Run     string `json:"run,omitempty"`
	KID     string `json:"kid,omitempty"`
	Wrapped string `json:"wrapped"`
	Raw     string `json:"raw"`
}

func (k PushedKey) String() string {
	return fmt.Sprintf("PushedKey{run:%q kid:%q raw:<redacted>}", k.Run, k.KID)
}
func (k PushedKey) GoString() string { return k.String() }
func (k PushedKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("run", k.Run), slog.String("kid", k.KID), slog.String("raw", "<redacted>"))
}

// KeyBundle carries pushed hold keys on create, resume, and fork.
type KeyBundle struct {
	Hold  *PushedKey  `json:"hold,omitempty"`
	Holds []PushedKey `json:"holds,omitempty"`
	Open  []PushedKey `json:"open,omitempty"`
}

// HasRaw reports whether the bundle contains any key entries.
func (b *KeyBundle) HasRaw() bool {
	if b == nil {
		return false
	}
	if b.Hold != nil && (b.Hold.Raw != "" || b.Hold.Wrapped != "") {
		return true
	}
	for _, k := range b.Holds {
		if k.Raw != "" || k.Wrapped != "" {
			return true
		}
	}
	for _, k := range b.Open {
		if k.Raw != "" || k.Wrapped != "" {
			return true
		}
	}
	return false
}

// Wipe clears all Raw strings on the bundle.
func (b *KeyBundle) Wipe() {
	if b == nil {
		return
	}
	if b.Hold != nil {
		b.Hold.Raw = ""
	}
	for i := range b.Holds {
		b.Holds[i].Raw = ""
	}
	for i := range b.Open {
		b.Open[i].Raw = ""
	}
}

func (b KeyBundle) String() string {
	return fmt.Sprintf("KeyBundle{hold:%t holds:%d open:%d}", b.Hold != nil, len(b.Holds), len(b.Open))
}
func (b KeyBundle) GoString() string { return b.String() }
func (b KeyBundle) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("hold", b.Hold != nil), slog.Int("holds", len(b.Holds)), slog.Int("open", len(b.Open)))
}

// RemoteExpect is the state Cloud expects of a run or snapshot being resumed,
// forked, or booted from snapshot:<id> in key custody mode.
type RemoteExpect struct {
	Generation uint64 `json:"generation,omitempty"`
	Snapshot   string `json:"snapshot,omitempty"`
	KID        string `json:"kid"`
}

// PushKeysRequest is the POST /v1/runs/{id}/keys body. Accepts either
// {"hold": {kid, wrapped, raw}} or top-level {kid, wrapped, raw}.
type PushKeysRequest struct {
	Hold    *PushedKey `json:"hold,omitempty"`
	KID     string     `json:"kid,omitempty"`
	Wrapped string     `json:"wrapped,omitempty"`
	Raw     string     `json:"raw,omitempty"`
}

// Key resolves the single pushed key from the request.
func (r *PushKeysRequest) Key() (PushedKey, error) {
	hasTop := r.KID != "" || r.Wrapped != "" || r.Raw != ""
	if r.Hold != nil && hasTop {
		return PushedKey{}, fmt.Errorf("%w: provide either hold or top-level key fields, not both", ErrBadRequest)
	}
	if r.Hold != nil {
		return *r.Hold, nil
	}
	if hasTop {
		return PushedKey{KID: r.KID, Wrapped: r.Wrapped, Raw: r.Raw}, nil
	}
	return PushedKey{}, fmt.Errorf("%w: hold key is required", ErrBadRequest)
}

// Wipe clears all Raw key strings from the request.
func (r *PushKeysRequest) Wipe() {
	if r == nil {
		return
	}
	if r.Hold != nil {
		r.Hold.Raw = ""
	}
	r.Raw = ""
}

func (r PushKeysRequest) String() string {
	return fmt.Sprintf("PushKeysRequest{hold:%t kid:%q raw:<redacted>}", r.Hold != nil, r.KID)
}
func (r PushKeysRequest) GoString() string { return r.String() }
func (r PushKeysRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("hold", r.Hold != nil), slog.String("kid", r.KID), slog.String("raw", "<redacted>"))
}

// SnapshotPin authenticates the stop snapshot named by a RecordRunning: its
// hold key ID (or "v1" for legacy) and its verified stream SHA-256, stored
// inside the running record's sealed section under the active holder's key.
type SnapshotPin struct {
	KID          string
	StreamSHA256 string
}

// EnsureOptions governs a key-custody restore.
type EnsureOptions struct {
	Tenant             string
	Run                string
	Bases              map[string]string
	ExpectKID          string
	ExpectStreamSHA256 string
	LegacyRun          string
}

// SnapshotMeta is a snapshot's public custody metadata from remote storage.
type SnapshotMeta struct {
	Purpose string
	Run     string
	Tenant  string
	KID     string
	V2      bool
}

// CustodyOffHost is the key-custody extension of OffHost, implemented by
// *offhost.Service. When Custody() is false, the daemon behaves identically
// to v1.
type CustodyOffHost interface {
	Custody() bool
	EnsureCustody(ctx context.Context, ref string, opts EnsureOptions) (SnapshotPin, error)
	SnapshotPin(ctx context.Context, ref, legacyRun string) (SnapshotPin, error)
	LatestAs(ctx context.Context, id, legacyRun string) (RemoteRecord, error)
	LatestPublicAs(ctx context.Context, id, legacyRun string) (RemoteRecord, error)
	SnapshotMeta(ctx context.Context, ref, legacyRun string) (SnapshotMeta, bool, error)
	VerifyHoldKey(ctx context.Context, tenant, runID, snapshotRef string, key PushedKey) error
	PutHoldKey(tenant, runID string, key PushedKey) (kid, wrapped string, err error)
	BackupHoldKey(runID string) (restore func(newKID string) error, discard func())
	SupplyOpenKeys(tenant, defaultRun string, keys []PushedKey) (release func(), err error)
	EraseHoldKey(runID, kid string) error
	PruneHoldKeys(keepRuns map[string]bool) (int, error)
	HoldKeyStatus(runID string) (present, damaged bool)
	ForgetHoldKeyMemory(kid string)
}

// custody returns the OffHost's CustodyOffHost extension when key custody is
// active, or nil when custody is off.
func (m *Manager) custody() CustodyOffHost {
	if m.OffHost == nil {
		return nil
	}
	c, ok := m.OffHost.(CustodyOffHost)
	if !ok || !c.Custody() {
		return nil
	}
	return c
}

// CustodyEnabled reports whether key custody is active on this daemon.
func (m *Manager) CustodyEnabled() bool { return m.custody() != nil }

// PushedCustody reports whether key custody is active in pushed mode.
func (m *Manager) PushedCustody() bool {
	return m.custody() != nil && m.OffHost.Pushed()
}

// parseWrappedHeader parses the unauthenticated prefix of a t2 wrapped hold
// key ("t2.<tenant>.<tkVersion>.<kid>.<ct>") for pre-checks before unwrap.
func parseWrappedHeader(wrapped string) (tenant, kid string, err error) {
	parts := strings.Split(wrapped, ".")
	if len(parts) != 5 || parts[0] != "t2" {
		return "", "", fmt.Errorf("%w: wrapped hold key is malformed", ErrBadRequest)
	}
	if !ValidTenant(parts[1]) {
		return "", "", fmt.Errorf("%w: wrapped hold key has invalid tenant", ErrBadRequest)
	}
	if !ValidKID(parts[3]) {
		return "", "", fmt.Errorf("%w: wrapped hold key has invalid kid", ErrBadRequest)
	}
	return parts[1], parts[3], nil
}

// DecodeRawKey decodes a 32-byte base64 raw key (standard or raw standard).
// Callers must clear the returned slice after use.
func DecodeRawKey(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("%w: raw key is required", ErrBadRequest)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(raw) != 32 {
		clear(raw)
		return nil, fmt.Errorf("%w: raw key must be 32 base64-encoded bytes", ErrBadRequest)
	}
	return raw, nil
}

// validatePushedKeyShape checks a PushedKey's structural fields (never logs Raw
// or echoes unvalidated caller key fields).
func validatePushedKeyShape(k PushedKey, expectTenant, expectRun string) (tenant, kid string, err error) {
	tenant, kid, err = parseWrappedHeader(k.Wrapped)
	if err != nil {
		return "", "", err
	}
	if k.KID != "" && k.KID != kid {
		return "", "", fmt.Errorf("%w: key kid does not match wrapped blob kid %s", ErrBadRequest, kid)
	}
	if expectTenant != "" && tenant != expectTenant {
		return "", "", fmt.Errorf("%w: key tenant %s does not match run tenant %s", ErrBadRequest, tenant, expectTenant)
	}
	if expectRun != "" && k.Run != "" && k.Run != expectRun {
		return "", "", fmt.Errorf("%w: key run does not match target run %s", ErrBadRequest, expectRun)
	}
	raw, err := DecodeRawKey(k.Raw)
	if err != nil {
		return "", "", err
	}
	clear(raw)
	return tenant, kid, nil
}

// validateBases checks a blessed-base table's syntax.
func validateBases(bases map[string]string) error {
	for id, hash := range bases {
		if !strings.HasPrefix(id, "base-") || len(id) <= 5 {
			return fmt.Errorf("%w: bases entry %q is not a base image ID", ErrBadRequest, id)
		}
		if len(hash) != 64 || strings.Trim(hash, "0123456789abcdef") != "" {
			return fmt.Errorf("%w: bases entry %q must map to a 64-char lowercase hex SHA-256", ErrBadRequest, id)
		}
	}
	return nil
}

// validateExpect validates RemoteExpect syntax.
func validateExpect(expect *RemoteExpect, forStoppedRun, takeover bool) error {
	if expect == nil {
		return nil
	}
	if expect.KID != LegacyKID && !ValidKID(expect.KID) {
		return fmt.Errorf("%w: expect.kid must be a 32-hex key ID or %q", ErrBadRequest, LegacyKID)
	}
	if forStoppedRun && !takeover {
		if expect.Generation == 0 {
			return fmt.Errorf("%w: expect.generation is required for a stopped run", ErrBadRequest)
		}
		if expect.Snapshot == "" {
			return fmt.Errorf("%w: expect.snapshot is required for a stopped run", ErrBadRequest)
		}
	}
	if forStoppedRun && takeover && expect.Generation == 0 {
		return fmt.Errorf("%w: expect.generation is required for takeover", ErrBadRequest)
	}
	return nil
}

// checkRecordExpect holds a remote record against Cloud's RemoteExpect.
func checkRecordExpect(rec RemoteRecord, expect *RemoteExpect, takeover bool, expectTenant string) error {
	if expect == nil {
		return nil
	}
	if expect.KID == LegacyKID {
		if rec.KID != "" {
			return fmt.Errorf("%w: expected legacy v1 record for run %s, got v2 key %s", ErrRemoteConflict, rec.Run, rec.KID)
		}
	} else {
		if rec.KID == "" {
			return fmt.Errorf("%w: run %s record is v1, expected key %s (v1 downgrade refused)", ErrRemoteConflict, rec.Run, expect.KID)
		}
		if rec.KID != expect.KID {
			return fmt.Errorf("%w: run %s record is under key %s, expected %s", ErrRemoteConflict, rec.Run, rec.KID, expect.KID)
		}
		if expectTenant != "" && rec.Tenant != expectTenant {
			return fmt.Errorf("%w: run %s record is of tenant %s, expected %s", ErrRemoteConflict, rec.Run, rec.Tenant, expectTenant)
		}
	}
	if takeover {
		if rec.Generation < expect.Generation {
			return fmt.Errorf("%w: run %s record is at generation %d, behind expected %d", ErrRemoteConflict, rec.Run, rec.Generation, expect.Generation)
		}
		if rec.Generation == expect.Generation && expect.Snapshot != "" && rec.SnapshotID != expect.Snapshot {
			return fmt.Errorf("%w: run %s record at generation %d names snapshot %q, expected %q", ErrRemoteConflict, rec.Run, rec.Generation, rec.SnapshotID, expect.Snapshot)
		}
		return nil
	}
	if rec.Generation != expect.Generation {
		return fmt.Errorf("%w: run %s record is at generation %d, expected %d", ErrRemoteConflict, rec.Run, rec.Generation, expect.Generation)
	}
	if rec.SnapshotID != expect.Snapshot {
		return fmt.Errorf("%w: run %s record names snapshot %q, expected %q", ErrRemoteConflict, rec.Run, rec.SnapshotID, expect.Snapshot)
	}
	return nil
}

// ReconcileHoldKeys checks every stopped run loaded from the registry against
// this host's hold-key cache (pushed mode only), and prunes any orphaned cache
// entries for runs no longer in the registry.
//
// Any non-superseded, non-legacy local stopped run whose cached hold key is
// damaged — or missing while not yet durable — is put into remote.state =
// "needs-key" with its local copy and prior remote metadata (including Damage
// and DurableAt) preserved, so Cloud sees it in GET /v1/runs and repairs it
// via POST /v1/runs/{id}/keys.
func (m *Manager) ReconcileHoldKeys() {
	custody := m.custody()
	if custody == nil || !m.OffHost.Pushed() {
		return
	}
	changed := false
	m.mu.Lock()
	keep := make(map[string]bool, len(m.runs))
	for id, live := range m.runs {
		keep[id] = true
		if live.State != StateStopped {
			continue
		}
		// A run written under v1 before switching to pushed mode has a non-t2
		// remoteKey (or no remoteKID at all with remoteGen > 0); mark it
		// legacy rather than needs-key.
		if !live.remoteLegacy && live.remoteKey != "" && !strings.HasPrefix(live.remoteKey, "t2.") {
			live.remoteLegacy = true
			changed = true
			continue
		}
		if live.remoteLegacy {
			continue
		}
		if live.Remote != nil && live.Remote.State == RemoteSuperseded {
			continue
		}
		local := live.Remote == nil || live.Remote.Local
		if !local {
			continue
		}
		present, damaged := custody.HoldKeyStatus(id)
		isDurable := live.Remote != nil && live.Remote.State == RemoteDurable
		alreadyNeedsKey := live.Remote != nil && live.Remote.State == RemoteNeedsKey
		// Only damaged entries (explicit corruption of this host's cache entry)
		// or missing keys on non-durable runs need a key push. A durable run
		// that never held a key here (e.g. a fork source adopted from remote
		// storage) needs no key until Cloud resumes it.
		if damaged || (!present && !isDurable && !alreadyNeedsKey) {
			var next RemoteState
			if live.Remote != nil {
				next = *live.Remote
			}
			if !alreadyNeedsKey {
				live.remoteWasDurable = isDurable
			}
			next.State = RemoteNeedsKey
			next.Local = local
			if damaged {
				next.Error = "hold key entry damaged in host cache; waiting for key push"
			} else {
				next.Error = "hold key missing in host cache; waiting for key push"
			}
			setRemoteLocked(live, next)
			changed = true
			m.log.Warn("stopped run is missing its hold key; marked needs-key until Cloud pushes it", "id", id, "damaged", damaged, "wasDurable", live.remoteWasDurable)
		}
	}
	m.mu.Unlock()
	if pruned, err := custody.PruneHoldKeys(keep); err != nil {
		m.log.Error("failed to prune orphaned hold-key cache entries", "error", err)
	} else if pruned > 0 {
		m.log.Info("pruned orphaned hold-key cache entries", "count", pruned)
	}
	if changed {
		m.persist()
	}
}

// PushRunKeys handles POST /v1/runs/{id}/keys in pushed mode (K3: stopped-run
// hold-key repair): refuses running runs, takes run exclusivity, requires the
// run's existing kid (or any kid when needs-key with no known kid), verifies
// the raw key opens the run's remote record/manifest before acknowledging,
// persists to HoldCache first, restores prior durable state without bumping
// generation, and publishes any pending stop asynchronously.
func (m *Manager) PushRunKeys(ctx context.Context, id string, req PushKeysRequest) (*Run, error) {
	defer req.Wipe()
	custody := m.custody()
	if custody == nil || !m.OffHost.Pushed() {
		return nil, fmt.Errorf("%w: key push requires --remote-kms pushed", ErrBadRequest)
	}
	pushedKey, err := req.Key()
	if err != nil {
		return nil, err
	}
	defer func() { pushedKey.Raw = "" }()

	current, release, err := m.beginStopped(id)
	if err != nil {
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			release()
		}
	}()

	tenant := current.tenant
	if tenant == "" {
		tenant = DefaultTenant
	}
	wasNeedsKey := current.Remote != nil && current.Remote.State == RemoteNeedsKey
	_, kid, err := validatePushedKeyShape(pushedKey, tenant, id)
	if err != nil {
		return nil, err
	}
	if current.remoteKID != "" && kid != current.remoteKID {
		return nil, fmt.Errorf("%w: run %s uses hold key %s; pushing a different key requires key rotation", ErrRemoteConflict, id, current.remoteKID)
	}
	if current.remoteKID == "" && !wasNeedsKey {
		return nil, fmt.Errorf("%w: run %s does not need a hold key pushed", ErrRemoteConflict, id)
	}
	// Verify raw key bytes actually open the run's existing remote record /
	// snapshot manifest (if any) BEFORE persisting to HoldCache.
	if err := custody.VerifyHoldKey(ctx, tenant, id, current.snapshot, pushedKey); err != nil {
		return nil, err
	}

	// Persist to HoldCache FIRST; if disk write fails, do not acknowledge.
	kid, wrapped, err := custody.PutHoldKey(tenant, id, pushedKey)
	if err != nil {
		return nil, err
	}

	shouldPublish := false
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		_ = custody.EraseHoldKey(id, kid)
		return nil, ErrNotFound
	}
	live.tenant = tenant
	live.remoteKey = wrapped
	live.remoteKID = kid
	live.remoteLegacy = false
	if live.Remote != nil && live.Remote.State == RemoteNeedsKey {
		restored := *live.Remote
		restored.Error = ""
		if live.remoteWasDurable {
			restored.State = RemoteDurable
			live.remoteWasDurable = false
		} else {
			restored.State = RemotePending
			shouldPublish = true
		}
		setRemoteLocked(live, restored)
	}
	view := m.viewLocked(live)
	m.mu.Unlock()
	m.persist()
	release()
	released = true
	m.log.Info("run hold key pushed", "id", id, "tenant", tenant, "kid", kid, "repairedNeedsKey", wasNeedsKey, "publishAsync", shouldPublish)

	if shouldPublish {
		go func() {
			if _, rel, err := m.beginStopped(id); err == nil {
				pubCtx, cancel := context.WithTimeout(context.Background(), m.publishTimeout())
				_ = m.publishHeld(pubCtx, id)
				cancel()
				rel()
			}
		}()
	}
	return view, nil
}

// eraseHoldKey removes a run's cached and in-memory hold key in pushed mode.
// Called ONLY on explicit Destroy or local stopped retention expiry, never on
// remote records read from the bucket.
func (m *Manager) eraseHoldKey(id, kid string) {
	custody := m.custody()
	if custody == nil || !m.OffHost.Pushed() {
		return
	}
	if err := custody.EraseHoldKey(id, kid); err != nil {
		m.log.Error("failed to erase run hold key from host cache", "id", id, "error", err)
	}
}

// custodyViewLocked stamps custody fields onto RemoteState when custody is on.
// When custody is off, RemoteState is untouched (byte-identical to main).
// Caller holds Manager.mu.
func (m *Manager) custodyViewLocked(live *Run, view *Run) {
	if m.custody() == nil || view.Remote == nil {
		return
	}
	state := *view.Remote
	if live.tenant != "" {
		state.Tenant = live.tenant
	} else {
		state.Tenant = DefaultTenant
	}
	if live.remoteKID != "" {
		state.KID = live.remoteKID
	}
	state.Legacy = live.remoteLegacy
	view.Remote = &state
}

// cloneBases returns a copy of bases, or nil when bases is nil.
func cloneBases(bases map[string]string) map[string]string {
	if bases == nil {
		return nil
	}
	return maps.Clone(bases)
}

// ensureLocalFor restores ref using EnsureCustody when custody is on, else
// ensureLocal. When custody is on it also returns the verified tip SnapshotPin
// from the same manifest read that validated the restore (no second read).
func (m *Manager) ensureLocalFor(ctx context.Context, ref string, opts EnsureOptions) (fetched bool, pin SnapshotPin, err error) {
	if m.OffHost == nil || !m.ownsSnapshotRef(ref) {
		return false, SnapshotPin{}, nil
	}
	custody := m.custody()
	if custody == nil {
		fetched, err = m.ensureLocal(ctx, ref)
		return fetched, SnapshotPin{}, err
	}
	if has, err := m.OffHost.HasLocal(ctx, ref); err == nil {
		if has {
			// Verify tip expect.kid / pinned stream hash / return verified pin.
			if opts.ExpectKID != "" || opts.ExpectStreamSHA256 != "" || opts.Run != "" {
				pin, err = custody.EnsureCustody(ctx, ref, opts)
				if err != nil {
					return false, SnapshotPin{}, err
				}
			}
			return false, pin, nil
		}
		fetched = true
	}
	ctx, cancel := context.WithTimeout(ctx, m.publishTimeout())
	defer cancel()
	release, err := m.transferSlot(ctx, false)
	if err != nil {
		return false, SnapshotPin{}, err
	}
	defer release()
	pin, err = custody.EnsureCustody(ctx, ref, opts)
	if err != nil {
		return false, SnapshotPin{}, err
	}
	return fetched, pin, nil
}

// reserveIDs validates and reserves caller-chosen run IDs under m.mu so two
// concurrent creates or forks cannot race for the same ID.
func (m *Manager) reserveIDs(ids ...string) (func(), error) {
	if len(ids) == 0 {
		return func() {}, nil
	}
	seen := make(map[string]bool, len(ids))
	m.mu.Lock()
	for _, id := range ids {
		if seen[id] {
			m.mu.Unlock()
			return nil, fmt.Errorf("%w: duplicate run id %q", ErrBadRequest, id)
		}
		seen[id] = true
		if err := m.checkUnusedIDLocked(id); err != nil {
			m.mu.Unlock()
			return nil, err
		}
	}
	for _, id := range ids {
		m.reserving[id] = struct{}{}
	}
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		for _, id := range ids {
			delete(m.reserving, id)
		}
		m.mu.Unlock()
	}, nil
}

// checkUnusedIDLocked verifies id is a valid ULID not currently in runs,
// reserving, or tombstones. Caller holds Manager.mu.
func (m *Manager) checkUnusedIDLocked(id string) error {
	if !validULID(id) {
		return fmt.Errorf("%w: id %q is not a valid ULID", ErrBadRequest, id)
	}
	if _, exists := m.runs[id]; exists {
		return fmt.Errorf("%w: run %s already exists", ErrBusy, id)
	}
	if _, pending := m.reserving[id]; pending {
		return fmt.Errorf("%w: run %s is already being created", ErrBusy, id)
	}
	if _, dead := m.tombstones[id]; dead {
		return fmt.Errorf("%w: run %s was already destroyed", ErrBusy, id)
	}
	return nil
}

// kidFromWrapped extracts the kid from a wrapped v2 hold key, or "" if not one.
func kidFromWrapped(wrapped string) string {
	_, kid, err := parseWrappedHeader(wrapped)
	if err != nil {
		return ""
	}
	return kid
}

// legacyRunOf returns runID when expect asks for legacy v1 reading.
func legacyRunOf(expect *RemoteExpect, runID string) string {
	if expect != nil && expect.KID == LegacyKID {
		return runID
	}
	return ""
}

// reconciledRecord carries the authenticated record state and snapshot pin
// observed during THIS request's reconcile, so takeover tip verification never
// relies on sticky fields on Run.
type reconciledRecord struct {
	present   bool
	state     string
	kid       string
	pinKID    string
	pinSHA256 string
}

func recordInfoOf(rec RemoteRecord) reconciledRecord {
	info := reconciledRecord{
		present: true,
		state:   rec.State,
		kid:     rec.KID,
	}
	if len(rec.Payload) > 0 {
		var stored stateRun
		if json.Unmarshal(rec.Payload, &stored) == nil {
			info.pinKID = stored.RemotePinKID
			info.pinSHA256 = stored.RemotePinSHA256
		}
	}
	return info
}

// localSnapshotCustody looks up the tenant and hold key ID of a local-only
// snapshot (not yet in remote storage) from this daemon's snapshot notes or
// owning run.
func (m *Manager) localSnapshotCustody(ref string) (tenant, kid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if note, ok := m.snapshotNotes[ref]; ok {
		tenant = note.Tenant
		if note.Key != "" {
			kid = kidFromWrapped(note.Key)
		}
		if tenant == "" && note.Run != "" {
			if owner, ok := m.runs[note.Run]; ok {
				tenant = owner.tenant
			}
		}
		if tenant == "" {
			tenant = DefaultTenant
		}
		return tenant, kid
	}
	for _, r := range m.runs {
		if r.snapshot == ref || r.base == ref || slices.Contains(r.images, ref) {
			tenant = r.tenant
			if tenant == "" {
				tenant = DefaultTenant
			}
			return tenant, r.remoteKID
		}
	}
	return "", ""
}
