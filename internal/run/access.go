package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
)

// Access: the run's side of SSH and published ports (docs/wire-contract.md,
// "Access"). The manager keeps, per run,
//
//   - the access epoch, an opaque, strictly increasing integer. A grant
//     carries a copy of it (ep) and is accepted only while ep is at least
//     the run's epoch, so raising it revokes every grant issued before.
//     It starts at the run's creation as the unix time then (a floor, not
//     a timestamp), a revoke sets it to max(now, epoch+1), and it is never
//     compared with a clock;
//   - the run's ports: which are public (reachable without a grant) and
//     which speak h2c;
//   - the bytes its access streams moved.
//
// None of it exists unless access is enabled (EnableAccess): with access
// off the run JSON, the registry file and the remote record are what they
// were before it existed.
//
// A run that moves loses its grants: any resume that is not this daemon
// continuing its own state (a run adopted from remote storage — stopped on
// another daemon, taken over, or brought back from its last stop after a
// restart lost it) sets epoch = max(epoch+1, accessEpoch+1, now)
// (moveAccessLocked). With remote storage a revoke writes the new epoch to
// the run's remote record before it answers, and fails loudly when it
// cannot.

// Port visibility and protocol values.
const (
	PortPublic  = "public"
	PortPrivate = "private"

	PortHTTP = "http"
	PortH2C  = "h2c"

	// MaxPublicPorts bounds a run's public ports, maxPorts all of its
	// port entries.
	MaxPublicPorts = 16
	maxPorts       = 64
)

// ErrAccessDisabled is the answer of every access call on a daemon that
// has access off.
var ErrAccessDisabled = errors.New("access is not enabled on this daemon")

// ErrUnsupportedDriver: the driver cannot open a stream to a guest port.
var ErrUnsupportedDriver = errors.New("the driver cannot open access streams")

// ErrPortRefused: nothing accepted the connection on the guest port.
var ErrPortRefused = errors.New("nothing is listening on the guest port")

// ErrGuestAgent: the run's guest agent cannot open access streams (it is
// older than guest protocol version 2, or at its own limit).
var ErrGuestAgent = errors.New("the run's guest agent cannot open access streams")

// ErrAccessWriteThrough: a revoke raised the epoch and closed the run's
// streams here, and could not write the new epoch to remote storage.
var ErrAccessWriteThrough = errors.New("the run's new access state is not in remote storage")

// ErrAccessNotPersisted: a revoke or port change took effect on this
// daemon (the epoch raised and streams closed, or the port changed), and
// the registry file could not be written: a restart before the next good
// write would bring the old access state back.
var ErrAccessNotPersisted = errors.New("the run's new access state is not in the registry file")

// accessEpochHeadroom is how far below accessgrant.MaxEpoch a resume's
// accessEpoch must stay: an epoch at the maximum can never be raised
// again, so a run there could never be revoked or moved.
const accessEpochHeadroom = 1 << 20

// ValidResumeEpoch reports whether a resume may ask for epoch.
func ValidResumeEpoch(epoch int64) bool {
	return epoch >= 0 && epoch <= accessgrant.MaxEpoch-accessEpochHeadroom
}

// PortSpec is one port entry of a run.
type PortSpec struct {
	Port       int    `json:"port"`
	Visibility string `json:"visibility"`
	Protocol   string `json:"protocol"`
}

// PortRequest is the PUT /v1/runs/{id}/ports/{port} body.
type PortRequest struct {
	Visibility string `json:"visibility"`
	Protocol   string `json:"protocol,omitempty"`
}

// AccessView is the run JSON's access field, present once access is on.
type AccessView struct {
	Epoch   int64      `json:"epoch"`
	Ports   []PortSpec `json:"ports"`
	Streams int        `json:"streams"`
}

// AccessStreams is the access listener's side: the manager tells it when
// a run's streams must end. It is called without the manager's lock held.
type AccessStreams interface {
	// CloseRun ends every access stream of the run.
	CloseRun(id, reason string)
	// ClosePort ends the anonymous (public) streams of one port.
	ClosePort(id string, port int, reason string)
	// Streams is how many access streams the run has open.
	Streams(id string) int
}

// accessState is a manager with access on.
type accessState struct {
	streams AccessStreams
}

// EnableAccess turns access on. Call before LoadState and before serving.
// streams may be nil until the listener exists (SetAccessStreams).
func (m *Manager) EnableAccess(streams AccessStreams) {
	m.access = &accessState{streams: streams}
}

// SetAccessStreams hands the manager the listener's stream registry.
func (m *Manager) SetAccessStreams(streams AccessStreams) {
	if m.access != nil {
		m.access.streams = streams
	}
}

// AccessEnabled reports whether access is on.
func (m *Manager) AccessEnabled() bool { return m.access != nil }

func (m *Manager) closeAccessRun(id, reason string) {
	if m.access != nil && m.access.streams != nil {
		m.access.streams.CloseRun(id, reason)
	}
}

func (m *Manager) closeAccessPort(id string, port int, reason string) {
	if m.access != nil && m.access.streams != nil {
		m.access.streams.ClosePort(id, port, reason)
	}
}

// accessFloor is the epoch a run starts with: the unix time now.
func (m *Manager) accessFloor() int64 { return m.now().Unix() }

// accessViewLocked fills a view's access field. Caller holds mu.
func (m *Manager) accessViewLocked(run *Run, view *Run) {
	if m.access == nil {
		return
	}
	ports := slices.Clone(run.accessPorts)
	if ports == nil {
		ports = []PortSpec{}
	}
	streams := 0
	if m.access.streams != nil && run.State == StateRunning {
		streams = m.access.streams.Streams(run.ID)
	}
	view.Access = &AccessView{Epoch: run.accessEpoch, Ports: ports, Streams: streams}
	view.Usage.AccessRxBytes = counterOf(run.accessBytes.Rx)
	view.Usage.AccessTxBytes = counterOf(run.accessBytes.Tx)
	view.Usage.AccessAnonRxBytes = counterOf(run.accessBytes.AnonRx)
	view.Usage.AccessAnonTxBytes = counterOf(run.accessBytes.AnonTx)
}

func counterOf(n int64) *int64 { return &n }

// accessBytes is what a run's access streams moved, on this daemon and
// before (it travels with the run like its other usage totals). Rx is
// what the guest received through them, Tx what it sent.
type accessBytes struct {
	Rx     int64 `json:"rx,omitempty"`
	Tx     int64 `json:"tx,omitempty"`
	AnonRx int64 `json:"anonRx,omitempty"`
	AnonTx int64 `json:"anonTx,omitempty"`
}

func (a accessBytes) empty() bool { return a == accessBytes{} }

// AddAccessBytes counts bytes an access stream moved for a run. anon
// marks a stream opened without a grant (a public port).
func (m *Manager) AddAccessBytes(id string, rx, tx int64, anon bool) {
	if m.access == nil || (rx <= 0 && tx <= 0) {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok {
		return
	}
	run.accessBytes.Rx += max(rx, 0)
	run.accessBytes.Tx += max(tx, 0)
	if anon {
		run.accessBytes.AnonRx += max(rx, 0)
		run.accessBytes.AnonTx += max(tx, 0)
	}
}

// ParsePort reads a guest port from a path: 1-65535, plain decimal.
func ParsePort(text string) (int, error) {
	n := 0
	if text == "" || len(text) > 5 || text[0] == '0' {
		return 0, fmt.Errorf("%w: port %q must be 1-65535", ErrBadRequest, text)
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, fmt.Errorf("%w: port %q must be 1-65535", ErrBadRequest, text)
		}
		n = n*10 + int(text[i]-'0')
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("%w: port %q must be 1-65535", ErrBadRequest, text)
	}
	return n, nil
}

// validatePorts holds a run's port list to its rules: ports in range,
// each once, known visibility and protocol, at most MaxPublicPorts public.
func validatePorts(ports []PortSpec) error {
	if len(ports) > maxPorts {
		return fmt.Errorf("%d port entries, at most %d", len(ports), maxPorts)
	}
	seen := map[int]bool{}
	public := 0
	for _, p := range ports {
		if p.Port < 1 || p.Port > 65535 || seen[p.Port] {
			return fmt.Errorf("bad or repeated port %d", p.Port)
		}
		seen[p.Port] = true
		switch p.Visibility {
		case PortPublic:
			public++
		case PortPrivate:
		default:
			return fmt.Errorf("port %d: unknown visibility %q", p.Port, p.Visibility)
		}
		if p.Protocol != PortHTTP && p.Protocol != PortH2C {
			return fmt.Errorf("port %d: unknown protocol %q", p.Port, p.Protocol)
		}
	}
	if public > MaxPublicPorts {
		return fmt.Errorf("%d public ports, at most %d", public, MaxPublicPorts)
	}
	return nil
}

// SetPort records a port's visibility and protocol. It is data only and
// allowed while the run is stopped. Making a public port private ends
// its anonymous streams. Like a revoke, the change is written to the
// registry file and, with remote storage and a remote record, to the
// run's record before it answers; the run it returns carries the change
// even when either write failed (ErrAccessNotPersisted,
// ErrAccessWriteThrough).
func (m *Manager) SetPort(ctx context.Context, id string, port int, req PortRequest) (*Run, error) {
	if m.access == nil {
		return nil, ErrAccessDisabled
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port must be 1-65535", ErrBadRequest)
	}
	if req.Visibility != PortPublic && req.Visibility != PortPrivate {
		return nil, fmt.Errorf("%w: visibility must be %q or %q", ErrBadRequest, PortPublic, PortPrivate)
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = PortHTTP
	}
	if protocol != PortHTTP && protocol != PortH2C {
		return nil, fmt.Errorf("%w: protocol must be %q or %q", ErrBadRequest, PortHTTP, PortH2C)
	}
	m.mu.Lock()
	run, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	if run.removing {
		m.mu.Unlock()
		return nil, ErrBusy
	}
	ports := slices.Clone(run.accessPorts)
	wasPublic := false
	at := slices.IndexFunc(ports, func(p PortSpec) bool { return p.Port == port })
	spec := PortSpec{Port: port, Visibility: req.Visibility, Protocol: protocol}
	if at >= 0 {
		wasPublic = ports[at].Visibility == PortPublic
		ports[at] = spec
	} else {
		ports = append(ports, spec)
	}
	slices.SortFunc(ports, func(a, b PortSpec) int { return a.Port - b.Port })
	if err := validatePorts(ports); err != nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	run.accessPorts = ports
	run.accessDirty = true
	m.mu.Unlock()
	if wasPublic && req.Visibility != PortPublic {
		m.closeAccessPort(id, port, "unpublished")
	}
	return m.accessChanged(ctx, id, "run port changed", "port", port)
}

// DeletePort removes a port entry; a public port's anonymous streams end.
// It is written through like SetPort.
func (m *Manager) DeletePort(ctx context.Context, id string, port int) (*Run, error) {
	if m.access == nil {
		return nil, ErrAccessDisabled
	}
	m.mu.Lock()
	run, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	if run.removing {
		m.mu.Unlock()
		return nil, ErrBusy
	}
	wasPublic := false
	run.accessPorts = slices.DeleteFunc(slices.Clone(run.accessPorts), func(p PortSpec) bool {
		if p.Port == port {
			wasPublic = p.Visibility == PortPublic
			return true
		}
		return false
	})
	if len(run.accessPorts) == 0 {
		run.accessPorts = nil
	}
	run.accessDirty = true
	m.mu.Unlock()
	if wasPublic {
		m.closeAccessPort(id, port, "unpublished")
	}
	return m.accessChanged(ctx, id, "run port removed", "port", port)
}

// accessChanged makes a change to a run's access state durable before it
// is answered: the registry file first, then, with remote storage and a
// remote record, the record (writeAccessThrough). The run it returns
// carries the change whatever failed; the error says what did, the
// registry file first (a restart is the nearer way to lose it).
func (m *Manager) accessChanged(ctx context.Context, id, what string, args ...any) (*Run, error) {
	m.mu.Lock()
	run, ok := m.runs[id]
	// A run with no record yet whose first record is being written (a
	// stop's publish holds the run) is written through too: the attempt
	// answers busy, so the caller is not told the change landed while
	// the publish carries a payload taken before it. The publish also
	// writes what changed meanwhile (publishHeld).
	//
	// So is a stopped run whose publish was attempted and not confirmed
	// (its record may have landed with the answer lost, and another
	// daemon may adopt that record before this one's upkeep runs):
	// writeAccessHeld looks, and writes to this daemon's own record.
	published := ok && m.OffHost != nil && (run.remoteGen > 0 || run.exclusive || unconfirmedPublishLocked(run))
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	persistErr := m.persistNow()
	m.log.Info(what, append([]any{"id", id}, args...)...)
	var throughErr error
	if published {
		throughErr = m.writeAccessThrough(ctx, id)
	}
	view, err := m.Get(id)
	if err != nil {
		return nil, err
	}
	if persistErr != nil {
		m.log.Error("access change not written to the registry file; a restart before the next good write brings the old access state back", "id", id, "error", persistErr)
		if throughErr != nil {
			return view, fmt.Errorf("%w: %v (and remote storage: %v)", ErrAccessNotPersisted, persistErr, throughErr)
		}
		return view, fmt.Errorf("%w: %v", ErrAccessNotPersisted, persistErr)
	}
	if throughErr != nil {
		m.log.Error("access change not written to remote storage; if the run moves before it is, the old access state goes with it", "id", id, "error", throughErr)
		return view, fmt.Errorf("%w: %v", ErrAccessWriteThrough, throughErr)
	}
	return view, nil
}

// nextEpoch is the epoch a revoke moves to: max(now, epoch+1).
func nextEpoch(epoch, now int64) (int64, error) {
	if epoch >= accessgrant.MaxEpoch {
		return 0, fmt.Errorf("%w: the access epoch is at its maximum", ErrBadRequest)
	}
	return min(max(now, epoch+1), accessgrant.MaxEpoch), nil
}

// RevokeAccess raises the run's access epoch, ending every grant issued
// before, closes all of its access streams, and, with remote storage and
// a remote record, writes the new epoch there before answering; the
// registry file is written first, and a failure there is an error too
// (ErrAccessNotPersisted). The run it returns carries the new epoch even
// when a write failed (ErrAccessWriteThrough, ErrAccessNotPersisted): the
// bump and the closing happened.
func (m *Manager) RevokeAccess(ctx context.Context, id string) (*Run, error) {
	if m.access == nil {
		return nil, ErrAccessDisabled
	}
	m.mu.Lock()
	run, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	next, err := nextEpoch(run.accessEpoch, m.now().Unix())
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	run.accessEpoch = next
	m.mu.Unlock()
	// After the bump: a stream admitted from here on sees the new epoch,
	// and one admitted before is in the registry and closed now.
	m.closeAccessRun(id, "revoked")
	return m.accessChanged(ctx, id, "run access revoked", "epoch", next)
}

// accessWriteTimeout bounds a revoke's write to remote storage.
const accessWriteTimeout = 30 * time.Second

// writeAccessThrough writes the run's access state into a new generation
// of its remote record: the newest record as it is, with only the access
// fields of its payload changed. It needs the run's exclusivity, so that
// no other write to the record interleaves; a busy run is an error the
// caller retries.
func (m *Manager) writeAccessThrough(ctx context.Context, id string) error {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if live.exclusive || live.removing {
		m.mu.Unlock()
		return fmt.Errorf("%w: the run is busy (a stop, resume, fork or delete is under way); try again", ErrBusy)
	}
	live.exclusive = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		if live, ok := m.runs[id]; ok {
			live.exclusive = false
		}
		m.mu.Unlock()
	}()
	return m.writeAccessHeld(ctx, id)
}

// writeAccessHeld is writeAccessThrough for a caller that holds the run's
// exclusivity already (a resume, a reconcile).
func (m *Manager) writeAccessHeld(ctx context.Context, id string) error {
	m.mu.Lock()
	live, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	generation := live.remoteGen
	unconfirmed, snapshot := unconfirmedPublishLocked(live), live.snapshot
	m.mu.Unlock()
	if generation == 0 && unconfirmed && m.OffHost != nil {
		adopted, err := m.adoptUnconfirmed(ctx, id, snapshot)
		if err != nil || adopted == 0 {
			return err
		}
		generation = adopted
	}
	if generation == 0 {
		return nil
	}
	var ports []PortSpec
	written := false
	defer func() {
		if !written {
			return
		}
		// The record carries these ports now: they are no longer only
		// this daemon's.
		m.mu.Lock()
		if live, ok := m.runs[id]; ok && slices.Equal(live.accessPorts, ports) {
			live.accessDirty = false
		}
		m.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), accessWriteTimeout)
	defer cancel()
	latest, err := m.OffHost.Latest(ctx, id)
	if err != nil {
		return err
	}
	if !latest.Mine && latest.State == RecordRunning {
		return fmt.Errorf("%w: daemon %s holds the run", ErrRemoteConflict, latest.Owner)
	}
	if latest.Generation != generation {
		return fmt.Errorf("%w: remote storage has generation %d of the run's record, this daemon knows %d", ErrRemoteConflict, latest.Generation, generation)
	}
	if latest.State == RecordDestroyed || latest.State == RecordForked || len(latest.Payload) == 0 {
		// Nothing resumes from either: a fork's record only keeps its
		// parent's snapshot alive until the fork first stops.
		return nil
	}
	var stored stateRun
	if err := json.Unmarshal(latest.Payload, &stored); err != nil {
		return fmt.Errorf("the run's remote record: %w", err)
	}
	// The record is the one this daemon knows (in step): its access
	// state is taken by the one rule (the epoch can only rise here), and
	// this daemon's ports, the newer, go back if they differ.
	m.mu.Lock()
	live, ok = m.runs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	writeBack := m.reconcileAccessFromRecordLocked(live, recordAccess{Epoch: stored.AccessEpoch, Ports: stored.AccessPorts}, false)
	epoch := live.accessEpoch
	ports = slices.Clone(live.accessPorts)
	m.mu.Unlock()
	if !writeBack {
		written = true
		return nil
	}
	stored.AccessEpoch = epoch
	stored.AccessPorts = ports
	payload, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	next := latest
	next.Generation = latest.Generation + 1
	next.Payload = payload
	if next.Tenant == "" {
		m.mu.Lock()
		if live, ok := m.runs[id]; ok {
			next.Tenant = live.tenant
		}
		m.mu.Unlock()
	}
	key, err := m.OffHost.Advance(ctx, next)
	if err != nil {
		return remoteErr(err)
	}
	written = true
	m.mu.Lock()
	if live, ok := m.runs[id]; ok && live.remoteGen == generation {
		live.remoteGen = next.Generation
		live.remoteKey = key
		if live.Remote != nil {
			state := *live.Remote
			state.Generation = live.remoteGen
			live.Remote = &state
		}
	}
	m.mu.Unlock()
	m.persist()
	return nil
}

// unconfirmedPublishLocked reports whether a run is stopped with no
// record this daemon knows of, though a write of its first record was
// attempted: that record may be in remote storage with the answer lost,
// or the daemon died before noting it. advanceStopped notes the attempt
// on disk before the write, so this survives a restart. A run whose
// snapshot upload failed before any record write (storage down) is not
// unconfirmed: nothing of it can be in another daemon's hands. Caller
// holds mu, and only calls this with remote storage on.
func unconfirmedPublishLocked(run *Run) bool {
	return run.State == StateStopped && run.remoteGen == 0 && run.firstRecordTried
}

// adoptUnconfirmed looks for the record an unconfirmed publish may have
// landed. None: 0, nothing to write to (the next publish writes the
// run's access state as it is then). This daemon's own "stopped" with
// the run's snapshot: its generation, taken as the run's (the publish's
// retry builds on it). Anything else is a conflict: another daemon has
// the run, and what this daemon changes is not the run's. The caller
// holds the run's exclusivity.
func (m *Manager) adoptUnconfirmed(ctx context.Context, id, snapshot string) (uint64, error) {
	latest, err := m.OffHost.Latest(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, remoteErr(err)
	}
	if !latest.Mine || latest.State != RecordStopped || latest.Snapshot != snapshot {
		return 0, fmt.Errorf("%w: remote storage has generation %d of the run's record (%s, by %s), which this daemon did not know it wrote", ErrRemoteConflict, latest.Generation, latest.State, latest.Owner)
	}
	m.mu.Lock()
	live, ok := m.runs[id]
	if ok && live.remoteGen == 0 {
		live.remoteGen, live.remoteKey = latest.Generation, latest.Key
		if live.Remote != nil {
			state := *live.Remote
			state.Generation = live.remoteGen
			live.Remote = &state
		}
	}
	m.mu.Unlock()
	m.persist()
	m.log.Warn("a stopped run's first record was in remote storage though its publish was not confirmed; taking its generation", "id", id, "generation", latest.Generation)
	return latest.Generation, nil
}

// moveAccessLocked applies the resume rule. A run continuing on this
// daemon resumes with max(epoch, the caller's accessEpoch). A run that
// moved here resumes with max(epoch+1, accessEpoch+1, now): strictly above
// every epoch a grant can have copied from its record or from the caller,
// so moving a run revokes all of its grants whatever the clocks say
// (max(record, passed, now) alone would let a grant minted at the record's
// epoch survive a move made within the same second). It reports whether
// the epoch changed. Caller holds mu.
func (m *Manager) moveAccessLocked(run *Run, passed int64) bool {
	if m.access == nil {
		return false
	}
	epoch := max(run.accessEpoch, passed)
	if run.accessMoved {
		epoch = max(run.accessEpoch+1, passed+1, m.accessFloor())
		run.accessMoved = false
	}
	epoch = min(epoch, accessgrant.MaxEpoch)
	changed := epoch != run.accessEpoch
	if changed {
		m.log.Info("run access epoch raised on resume", "id", run.ID, "from", run.accessEpoch, "to", epoch)
	}
	run.accessEpoch = epoch
	return changed
}

// AccessTarget is what the access listener needs of a run to admit a
// stream: taken under the manager's lock, after the stream is counted.
type AccessTarget struct {
	Epoch int64
	// Public and Protocol describe the port asked for.
	Public   bool
	Protocol string
	Ports    []PortSpec
	State    string
}

// AccessLookup is a run as the access listener's lookup route shows it.
func (m *Manager) AccessLookup(id string) (AccessTarget, error) {
	if m.access == nil {
		return AccessTarget{}, ErrAccessDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok || run.pendingCleanup {
		return AccessTarget{}, ErrNotFound
	}
	return AccessTarget{Epoch: run.accessEpoch, Ports: slices.Clone(run.accessPorts), State: run.State}, nil
}

// AccessAdmit is the manager's half of admitting an access stream to a
// run's port: the run must be here, running, and not being stopped,
// removed or torn down. The listener counts the stream in its registry
// BEFORE it calls this, so a stop, revoke or unpublish that changes the
// run after this answer finds the stream there and closes it.
func (m *Manager) AccessAdmit(id string, port int) (AccessTarget, error) {
	if m.access == nil {
		return AccessTarget{}, ErrAccessDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	run, ok := m.runs[id]
	if !ok || run.pendingCleanup {
		return AccessTarget{}, ErrNotFound
	}
	if run.State != StateRunning || run.removing || run.accessClosing || superseded(run) {
		return AccessTarget{Epoch: run.accessEpoch, State: StateStopped}, stoppedErr(id)
	}
	target := AccessTarget{Epoch: run.accessEpoch, Protocol: PortHTTP, State: run.State}
	for _, p := range run.accessPorts {
		if p.Port == port {
			target.Public = p.Visibility == PortPublic
			target.Protocol = p.Protocol
		}
	}
	return target, nil
}

// PortDialer is implemented by a driver that can open a byte stream to a
// TCP port on the guest's loopback without any network path: the VM
// driver through its guest agent over vsock.
type PortDialer interface {
	DialPort(ctx context.Context, containerID string, port int) (net.Conn, error)
}

// DialPort opens a stream to a guest port of a running run.
func (m *Manager) DialPort(ctx context.Context, id string, port int) (net.Conn, error) {
	dialer, ok := m.runtime.(PortDialer)
	if !ok {
		return nil, ErrUnsupportedDriver
	}
	m.mu.Lock()
	run, ok := m.runs[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	if run.State != StateRunning || run.removing || run.accessClosing || superseded(run) {
		m.mu.Unlock()
		return nil, stoppedErr(id)
	}
	container := run.ContainerID
	m.mu.Unlock()
	return dialer.DialPort(ctx, container, port)
}

// superseded reports whether another daemon took the run over: this copy
// may keep running (killing it would lose what only it has), but it is no
// longer the run, and the access state it holds is not the run's — the
// new holder's revokes and unpublishes never reach it. It takes no access
// streams. Caller holds mu.
func superseded(run *Run) bool {
	return run.Remote != nil && run.Remote.State == RemoteSuperseded
}

// mergePorts is a run's ports when this daemon changed them (dirty) and a
// newer record says otherwise: this daemon's entries, each public only if
// the record has it public too. Failing closed: a port either side made
// private stays private, a port either side removed is not public, and
// nothing becomes public that this daemon's user did not make public.
func mergePorts(local, record []PortSpec) []PortSpec {
	if len(local) == 0 {
		return nil
	}
	public := map[int]bool{}
	for _, p := range record {
		if p.Visibility == PortPublic {
			public[p.Port] = true
		}
	}
	merged := slices.Clone(local)
	for i := range merged {
		if merged[i].Visibility == PortPublic && !public[merged[i].Port] {
			merged[i].Visibility = PortPrivate
		}
	}
	return merged
}

// CanDialPorts reports whether the driver can open access streams.
func (m *Manager) CanDialPorts() bool {
	_, ok := m.runtime.(PortDialer)
	return ok
}
