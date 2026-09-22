package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Lease errors. ErrLeaseHeld: a fenced call (exec, file write) arrived
// without the credentials of the active lease, or a lease was requested
// while a different owner holds an unexpired one. ErrLeaseSuperseded:
// the holder's generation is stale — the lease lapsed or was regranted
// away; the stale holder has lost and must re-acquire. ErrBusy: a
// takeover was attempted while an exec/write is in flight on the run.
var (
	ErrLeaseHeld       = errors.New("run lease held")
	ErrLeaseSuperseded = errors.New("run lease superseded")
	ErrBusy            = errors.New("run busy")
)

// LeaseState is the lease view carried on run JSON: who holds writable
// ownership, the fencing generation, and when the lease lapses.
type LeaseState struct {
	Holder     string    `json:"holder"`
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// LeaseCredential accompanies a fenced call (exec, file write). The
// zero value is "no credential": fine while the run holds no active
// lease, refused when one is held. Generations start at 1, so an owner
// without a generation never matches a live grant.
type LeaseCredential struct {
	Owner      string
	Generation uint64
}

// activeLease returns the run's lease unless it has lapsed. Expiry
// frees the run lazily — every lease decision asks the clock, so no
// sweeper is needed. Caller holds Manager.mu.
func activeLease(run *Run, now time.Time) *LeaseState {
	if run.Lease == nil || !run.Lease.ExpiresAt.After(now) {
		return nil
	}
	return run.Lease
}

// checkFence refuses a write-path call while an active lease exists
// that cred does not match. With no active lease every caller passes —
// existing credential-less callers are unaffected. Caller holds
// Manager.mu.
func checkFence(run *Run, cred LeaseCredential, now time.Time) error {
	lease := activeLease(run, now)
	if lease == nil {
		return nil
	}
	if cred.Owner == lease.Holder && cred.Generation == lease.Generation {
		return nil
	}
	return fmt.Errorf("%w: run %s is leased to %q (generation %d) until %s",
		ErrLeaseHeld, run.ID, lease.Holder, lease.Generation, lease.ExpiresAt)
}

// AcquireLease grants owner writable ownership of the run for ttl and
// returns the lease's fencing generation and expiry. Every grant bumps
// the generation, so credentials from any earlier lease — expired,
// released, or regranted — can never pass the fence again. Re-acquiring
// as the CURRENT holder is allowed and bumps too (their old credential
// dies with the grant).
//
// A grant is refused with ErrBusy while any exec or file write is in
// flight on the run: takeover happens only BETWEEN execs, never under
// one. Residual limit, deliberate in this slice: a long-running exec
// delays a takeover up to its timeout — there is no mid-exec kill. A
// caller that keeps execing can therefore hold off a takeover
// indefinitely; the lease expiry does not interrupt an in-flight exec
// either, only prevents its renewal.
func (m *Manager) AcquireLease(runID, owner string, ttl time.Duration) (uint64, time.Time, error) {
	if strings.TrimSpace(owner) == "" {
		return 0, time.Time{}, fmt.Errorf("%w: lease owner is required", ErrBadRequest)
	}
	if ttl <= 0 || ttl > MaxTTL {
		return 0, time.Time{}, fmt.Errorf("%w: lease ttl must be positive and at most %s", ErrBadRequest, MaxTTL)
	}
	m.mu.Lock()
	current, ok := m.runs[runID]
	if !ok {
		m.mu.Unlock()
		return 0, time.Time{}, ErrNotFound
	}
	now := m.now()
	if lease := activeLease(current, now); lease != nil && lease.Holder != owner {
		m.mu.Unlock()
		return 0, time.Time{}, fmt.Errorf("%w: run %s is leased to %q until %s", ErrLeaseHeld, runID, lease.Holder, lease.ExpiresAt)
	}
	if current.execs > 0 {
		m.mu.Unlock()
		return 0, time.Time{}, fmt.Errorf("%w: an exec or write is in flight on run %s; acquire after it finishes", ErrBusy, runID)
	}
	current.leaseGen++
	current.Lease = &LeaseState{Holder: owner, Generation: current.leaseGen, ExpiresAt: now.Add(ttl)}
	granted := *current.Lease
	m.mu.Unlock()
	m.log.Info("lease acquired", "id", runID, "owner", owner, "generation", granted.Generation, "expiresAt", granted.ExpiresAt)
	return granted.Generation, granted.ExpiresAt, nil
}

// RenewLease extends the lease's expiry, but only for the holder of the
// CURRENT generation: a stale holder (expired, released, or regranted
// away) learns it lost via ErrLeaseSuperseded and must re-acquire.
// Renewing under one's own in-flight exec is allowed — an exec does not
// extend its lease, so a holder running long commands must renew to
// keep the lease alive across them.
func (m *Manager) RenewLease(runID, owner string, generation uint64, ttl time.Duration) (time.Time, error) {
	if strings.TrimSpace(owner) == "" {
		return time.Time{}, fmt.Errorf("%w: lease owner is required", ErrBadRequest)
	}
	if ttl <= 0 || ttl > MaxTTL {
		return time.Time{}, fmt.Errorf("%w: lease ttl must be positive and at most %s", ErrBadRequest, MaxTTL)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.runs[runID]
	if !ok {
		return time.Time{}, ErrNotFound
	}
	lease := activeLease(current, m.now())
	if lease == nil || lease.Holder != owner || lease.Generation != generation {
		return time.Time{}, fmt.Errorf("%w: no active generation %d lease held by %q on run %s", ErrLeaseSuperseded, generation, owner, runID)
	}
	// Copy-on-write: never mutate a LeaseState a reader may hold.
	current.Lease = &LeaseState{Holder: owner, Generation: generation, ExpiresAt: m.now().Add(ttl)}
	return current.Lease.ExpiresAt, nil
}

// ReleaseLease clears the lease when owner+generation match the current
// grant; any mismatch is refused with ErrLeaseSuperseded — a stale
// holder must learn the lease is no longer theirs to give back.
// Releasing a lapsed-but-unregranted lease succeeds (it was already
// free). The generation counter never resets, so a released credential
// stays dead even after the pointer is gone.
func (m *Manager) ReleaseLease(runID, owner string, generation uint64) error {
	if strings.TrimSpace(owner) == "" {
		return fmt.Errorf("%w: lease owner is required", ErrBadRequest)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.runs[runID]
	if !ok {
		return ErrNotFound
	}
	if current.Lease == nil || current.Lease.Holder != owner || current.Lease.Generation != generation {
		return fmt.Errorf("%w: no generation %d lease held by %q on run %s", ErrLeaseSuperseded, generation, owner, runID)
	}
	current.Lease = nil
	m.log.Info("lease released", "id", runID, "owner", owner, "generation", generation)
	return nil
}

// ExecSession is one admitted exec. Its in-flight reservation — the
// thing that blocks AcquireLease — ends when Exec returns, or when
// Abandon is called if the caller never runs the command.
type ExecSession struct {
	manager     *Manager
	runID       string
	containerID string
}

// BeginExec admits one exec under the lease fence: while the run holds
// an active lease, only a call carrying that lease's owner+generation
// gets in; with no lease, every caller does (existing credential-less
// callers are unaffected). Admission and the in-flight mark happen
// atomically under the manager lock, so a lease can never be granted
// between the fence check and the runtime call, and never under a
// running exec.
func (m *Manager) BeginExec(runID string, cred LeaseCredential) (*ExecSession, error) {
	m.mu.Lock()
	current, ok := m.runs[runID]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	if err := checkFence(current, cred, m.now()); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	current.execs++
	containerID := current.ContainerID
	m.mu.Unlock()
	return &ExecSession{manager: m, runID: runID, containerID: containerID}, nil
}

// Exec runs the admitted command and releases the in-flight reservation
// when it returns.
func (s *ExecSession) Exec(ctx context.Context, cmd, cwd string, timeout time.Duration, stdout, stderr io.Writer) (int, bool, error) {
	code, timedOut, err := s.manager.runtime.Exec(ctx, s.containerID, cmd, cwd, timeout, stdout, stderr)
	s.manager.finishExec(s.runID)
	return code, timedOut, err
}

// Abandon releases the reservation without running.
func (s *ExecSession) Abandon() { s.manager.finishExec(s.runID) }

// finishExec releases an in-flight slot. A run destroyed mid-exec took
// its counter with it — there is nothing to release.
func (m *Manager) finishExec(runID string) {
	m.mu.Lock()
	if current, ok := m.runs[runID]; ok && current.execs > 0 {
		current.execs--
	}
	m.mu.Unlock()
}

// WriteFile is the files API's write path, fenced exactly like exec:
// while the run holds an active lease only the holder may write. Writes
// reserve the in-flight slot too — a write is a docker exec under the
// hood, so a takeover must not land under a running write either.
func (m *Manager) WriteFile(ctx context.Context, runID string, cred LeaseCredential, path string, data io.Reader) error {
	m.mu.Lock()
	current, ok := m.runs[runID]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if err := checkFence(current, cred, m.now()); err != nil {
		m.mu.Unlock()
		return err
	}
	current.execs++
	containerID := current.ContainerID
	m.mu.Unlock()
	err := m.runtime.WriteFile(ctx, containerID, path, data)
	m.finishExec(runID)
	return err
}

// ReadFile is the files API's read path — deliberately unfenced. A
// lease gates writable ownership, not visibility: any caller may read
// whether or not a lease is held.
func (m *Manager) ReadFile(ctx context.Context, runID, path string) ([]byte, error) {
	current, err := m.Get(runID)
	if err != nil {
		return nil, err
	}
	return m.runtime.ReadFile(ctx, current.ContainerID, path)
}
