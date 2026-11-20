package run

import (
	"context"
	"errors"
	"time"
)

// Off-host durability. With an OffHost configured, a stopped run's
// snapshot is also kept in object storage, beside a small record of the
// run, so that the host that ran it is disposable: any other daemon
// sharing the storage can resume the run. The driver supplies the
// snapshot as a stream (see internal/offhost); the manager decides when
// to publish, who may resume, and when the local copy may go.
//
// A run's record is a series of numbered generations, each created once
// and never changed. This daemon knows a run's generation (remoteGen) and
// only ever moves a run on from the generation it knows: a daemon acting
// on an old view fails instead of overwriting a newer state.

// What a run's `remote` says about its stop.
const (
	// RemotePending: stopped here and not yet off the host. The local
	// snapshot is the only copy.
	RemotePending = "pending"
	// RemoteDurable: the snapshot and the run's record are in remote
	// storage. Only now may the local copy be dropped.
	RemoteDurable = "durable"
	// RemoteFailed: the last attempt to publish failed; it is retried.
	// The local snapshot is the only copy.
	RemoteFailed = "failed"
	// RemoteSuperseded: another daemon took the run over. This copy is
	// kept and can be forked or deleted, never resumed or published.
	RemoteSuperseded = "superseded"
)

// The states of a run's remote record.
const (
	RecordStopped   = "stopped"
	RecordRunning   = "running"
	RecordForked    = "forked"
	RecordDestroyed = "destroyed"
)

// Purposes of an uploaded snapshot.
const (
	PurposeStop     = "stop"
	PurposeSnapshot = "snapshot"
)

// RemoteState is the off-host side of a stopped run.
type RemoteState struct {
	State string `json:"state"`
	// Generation is the generation of the run's remote record this
	// daemon last wrote or read.
	Generation uint64 `json:"generation,omitempty"`
	// Snapshot is the name the stop's snapshot has in remote storage,
	// the same on every daemon.
	Snapshot string `json:"snapshot,omitempty"`
	// Local is whether this host has a copy of the snapshot. A resume
	// without one restores it from remote storage first.
	Local bool `json:"local"`
	// StoredBytes is what the last upload added to remote storage,
	// UploadMs how long it took, and Incremental whether it was sent
	// against the run's previous upload.
	StoredBytes int64      `json:"storedBytes,omitempty"`
	UploadMs    int64      `json:"uploadMs,omitempty"`
	Incremental bool       `json:"incremental,omitempty"`
	DurableAt   *time.Time `json:"durableAt,omitempty"`
	// Error is why the last publish failed.
	Error string `json:"error,omitempty"`
}

var (
	// ErrRemoteConflict: the run changed on another daemon first, or
	// belongs to one.
	ErrRemoteConflict = errors.New("run is held by another daemon")
	// ErrRemoteUnavailable: remote storage could not be asked, so the
	// daemon cannot tell whether the run is its to change.
	ErrRemoteUnavailable = errors.New("remote storage unavailable")
	// ErrRemoteIncomplete: remote storage was asked, and a snapshot it
	// is supposed to hold is not whole there (its manifest, a chunk, or
	// something its stream builds on is missing). Not a failure to ask:
	// a verdict.
	ErrRemoteIncomplete = errors.New("snapshot is not whole in remote storage")
	// ErrNotCallerSnapshot: the snapshot is a run's stop, which goes
	// with its run and is not a caller's to delete or boot by ID.
	ErrNotCallerSnapshot = errors.New("snapshot belongs to a run")
)

// RemoteRecord is one generation of a run's remote record.
type RemoteRecord struct {
	Run        string
	Generation uint64
	State      string
	// Mine is whether this daemon wrote it.
	Mine  bool
	Owner string
	// Snapshot is the local reference of the snapshot the record names,
	// and SnapshotID its name in remote storage (set on a record read).
	Snapshot   string
	SnapshotID string
	// Payload is the run as the registry file holds a stopped run.
	Payload []byte
	// Key is the run's wrapped data key ("" to have one minted).
	Key       string
	WrittenAt time.Time
}

// UploadRequest asks for a snapshot to be made durable.
type UploadRequest struct {
	Run string
	Ref string
	// Base is the reference of the run's previous upload, when this host
	// still has it: the stream is then only what changed since.
	Base string
	// Key is the run's wrapped data key, "" for a run without one yet.
	Key     string
	Purpose string
}

// UploadResult describes an upload.
type UploadResult struct {
	// ID is the snapshot's name in remote storage, the same on every host.
	ID  string
	Key string
	// StoredBytes is the size of what was written; StreamBytes of the
	// stream before encryption. Both are zero when Already.
	StoredBytes int64
	StreamBytes int64
	Incremental bool
	// Already: the snapshot was in remote storage; nothing was sent.
	Already bool
	Took    time.Duration
}

// RotateStats is what one master-key rotation pass did. Nothing was
// re-uploaded: the data keys themselves did not change, only the master
// each is wrapped by — which is also why a rotation is not a recovery
// from a master key that leaked. PreviousKeyNeeded says whether the pass
// saw anything a previous master still opens, and PreviousKeyNeededFor
// why, in words; a pass that ends without it is necessary for retiring
// the previous master, and every daemon's own pass must end so.
type RotateStats struct {
	Manifests         int `json:"manifestsRewrapped"`
	ManifestsCurrent  int `json:"manifestsCurrent"`
	ManifestsSkipped  int `json:"manifestsSkipped"`
	Records           int `json:"recordsRewrapped"`
	RecordsCurrent    int `json:"recordsCurrent"`
	RecordsRunning    int `json:"recordsRunning"`
	RecordsConflicted int `json:"recordsConflicted"`
	RecordsUnfenced   int `json:"recordsUnfenced"`
	RecordsDestroyed  int `json:"recordsDestroyed"`
	// RecordsRunningPrevious and RecordsDestroyedPrevious are the
	// running and destroyed records a previous master still wraps.
	RecordsRunningPrevious   int `json:"recordsRunningPrevious"`
	RecordsDestroyedPrevious int `json:"recordsDestroyedPrevious"`
	// LocalKeys is how many data keys in this daemon's own registry
	// (running runs, snapshot uploads owed) were re-wrapped by the pass;
	// LocalKeysFailed how many could not be.
	LocalKeys       int `json:"localKeysRewrapped"`
	LocalKeysFailed int `json:"localKeysFailed"`
	// PreviousKeyNeeded: the previous master key must stay configured.
	PreviousKeyNeeded    bool     `json:"previousKeyNeeded"`
	PreviousKeyNeededFor []string `json:"previousKeyNeededFor"`
}

// OffHost is remote storage as the manager uses it.
type OffHost interface {
	// Fenced is whether storage can decide between two daemons (it has
	// conditional writes).
	Fenced() bool
	// Upload makes a snapshot durable. Uploading one that is already
	// there is cheap and succeeds.
	Upload(ctx context.Context, req UploadRequest) (UploadResult, error)
	// Advance creates record.Generation, which must be the generation
	// after the run's newest. ErrRemoteConflict when it is not, or when
	// another daemon created it first. It returns the run's key.
	Advance(ctx context.Context, record RemoteRecord) (key string, err error)
	// Latest is a run's newest generation; ErrNotFound for none.
	Latest(ctx context.Context, run string) (RemoteRecord, error)
	// Runs is every run with a record, and its newest generation.
	Runs(ctx context.Context) (map[string]uint64, error)
	// Ensure makes sure this host has the snapshot, restoring it from
	// remote storage when it does not. ErrNotFound when it is in
	// neither place.
	Ensure(ctx context.Context, ref string) error
	// Verify checks that the snapshot is whole in remote storage, with
	// everything its stream builds on: ErrRemoteIncomplete when it is
	// not, another error when storage could not be asked. Upload has
	// done this for what it reports; a caller verifies again whenever
	// time has passed and something depends on the answer — before the
	// only other copy is deleted, and on the scrub's schedule.
	Verify(ctx context.Context, ref string) error
	// SnapshotPurpose is what remote storage says a snapshot is
	// (PurposeStop or PurposeSnapshot) and which run it was taken of;
	// found is false when remote storage has no such snapshot.
	SnapshotPurpose(ctx context.Context, ref string) (purpose, owner string, found bool, err error)
	// Rewrap returns a wrapped data key under the current master key.
	Rewrap(owner, key string) (string, error)
	HasLocal(ctx context.Context, ref string) (bool, error)
	HasRemote(ctx context.Context, ref string) (bool, error)
	// Ref is the local reference of a snapshot ID; false for a string
	// that is not an ID.
	Ref(id string) (string, bool)
	// DeleteSnapshot removes a caller's snapshot from remote storage.
	// One that is not there is not an error; a run's stop snapshot is
	// ErrNotCallerSnapshot.
	DeleteSnapshot(ctx context.Context, ref string) error
	// Collect deletes what nothing refers to any more.
	Collect(ctx context.Context) error
	// Rotate re-wraps the bucket's keys under the current master: every
	// manifest, and every stopped run's record as a new generation with
	// the state and the owner unchanged. Chunks do not move.
	Rotate(ctx context.Context) (RotateStats, error)
	// RemoteID is the universal ID of a snapshot ref, the name it has
	// on every daemon sharing the storage; false for a ref that is not
	// one of this daemon's snapshot refs.
	RemoteID(ref string) (string, bool)
	// ListSnapshots lists the caller snapshots in the bucket: what a
	// create with image "snapshot:<id>" can boot, and what a delete by
	// that ID can remove.
	ListSnapshots(ctx context.Context) ([]RemoteSnapshot, error)
	// Pressure is whether local storage is short enough that copies
	// which are safe in remote storage should go.
	Pressure(ctx context.Context) (bool, error)
}

// RemoteSnapshot is one caller snapshot in the bucket. Membership is
// the durability probe: a snapshot the upload of which failed is here
// exactly when its retry has landed.
type RemoteSnapshot struct {
	ID string `json:"id"`
	// Run is the run the snapshot was taken of, if it said so.
	Run string `json:"run,omitempty"`
	// CreatedAt is when the snapshot was uploaded (a rotation re-wraps
	// the manifest but keeps this).
	CreatedAt time.Time `json:"createdAt"`
	// StoredBytes is what the snapshot occupies in the bucket.
	StoredBytes int64 `json:"storedBytes"`
}
