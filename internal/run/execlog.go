package run

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Recoverable execs.
//
// An exec started with `recoverable: true` gets an ID and a record here:
// its status (running, exit code, timeout, error) and the last
// ExecOutputBytes of its output, stdout and stderr interleaved in the
// order the daemon received them, every byte at a global offset. The
// command is detached from its HTTP request, so a client that loses the
// stream can come back for the status and the rest of the output.
//
// Records are memory only. A daemon restart loses every one of them
// (the runs they belonged to are gone too, unless stopped); a lookup then
// answers ErrExecNotFound, which says so, rather than waiting for
// anything. A finished record expires ExecRetention after the command
// ended, and every record of a run goes when the run is destroyed.

const (
	// ExecOutputBytes is how much of one exec's output is kept: the last
	// 1 MiB. One bit per byte more says which stream it came from.
	ExecOutputBytes = 1 << 20
	// ExecRecordsPerRun and ExecRecordsTotal bound how many records are
	// kept for one run and for the whole daemon. Finished records are
	// evicted oldest first to make room; a running one never is, so a
	// recoverable exec beyond either bound with every slot running is
	// refused (ErrAtCapacity). Worst case memory is ExecRecordsTotal *
	// ExecOutputBytes * 9/8, about 72 MiB.
	ExecRecordsPerRun = 16
	ExecRecordsTotal  = 64
	// ExecRetention is how long a finished record is kept.
	ExecRetention = 15 * time.Minute
	// ExecOutputMaxChunks bounds the chunks one output read returns: a
	// command that alternates streams byte by byte would otherwise turn a
	// 1 MiB read into a million JSON objects. The read stops early and
	// says where to continue.
	ExecOutputMaxChunks = 4096
)

// Exec states.
const (
	ExecRunning  = "running"
	ExecExited   = "exited"
	ExecTimedOut = "timedOut"
	// ExecFailed is a command the sandbox could not run to the end: the
	// run was stopped or destroyed under it, the runtime failed. Its exit
	// code is -1, as on the stream.
	ExecFailed = "failed"
)

// ErrExecNotFound is the answer for an exec ID this daemon has no record
// of; its message gives every reason that can be.
var ErrExecNotFound = errors.New("no such exec")

func execNotFound(runID, execID string) error {
	return fmt.Errorf("%w: %s on run %s. Exec records are kept in this daemon's memory only: they are lost when the daemon restarts, expire %s after the command ends, and go when the run is destroyed",
		ErrExecNotFound, execID, runID, ExecRetention)
}

// ExecStatus is a recoverable exec as GET /v1/runs/{id}/execs/{execId}
// answers it.
type ExecStatus struct {
	ID         string     `json:"id"`
	RunID      string     `json:"runId"`
	State      string     `json:"state"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	// ExitCode is null while running; -1 when the sandbox failed (Error).
	ExitCode *int `json:"exitCode"`
	TimedOut bool `json:"timedOut"`
	// Signal is inferred from an exit code of 128+n (the shell's
	// convention, which both drivers report a killed command by): a
	// command that exits with such a code itself looks the same. Absent
	// otherwise, and on a timeout.
	Signal int    `json:"signal,omitempty"`
	Error  string `json:"error,omitempty"`
	// Detached says the stream that started the exec went away before
	// the command ended.
	Detached bool `json:"detached"`
	// Output is the range of offsets still held: [start, end).
	Output ExecOutputRange `json:"output"`
	// ExpiresAt is when a finished record goes.
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// ExecOutputRange is the output a record holds: bytes from Start up to
// End, End being every byte the command has written so far. CapBytes is
// the bound (ExecOutputBytes).
type ExecOutputRange struct {
	Start    int64 `json:"start"`
	End      int64 `json:"end"`
	CapBytes int   `json:"capBytes"`
}

// ExecChunk is a run of bytes from one stream. Data is base64 in JSON.
type ExecChunk struct {
	Stream string `json:"stream"`
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

// ExecOutput is one read of a record's output.
type ExecOutput struct {
	// Start is the offset of the first byte returned and Next the offset
	// after the last one: the `since` of the next read.
	Start int64 `json:"start"`
	Next  int64 `json:"next"`
	// End is every byte written so far; Next < End means there is more.
	End int64 `json:"end"`
	// Truncated says bytes the caller asked for (since < the oldest held)
	// have already left the buffer: Start is later than asked.
	Truncated bool        `json:"truncated"`
	Chunks    []ExecChunk `json:"chunks"`
	// Done: the command has ended and Next == End.
	Done bool `json:"done"`
}

// outputRing keeps the last cap bytes written, with one bit per byte for
// the stream (set: stderr). It grows to cap and then wraps; offset o is at
// o % cap. Memory is bounded by cap*9/8 whatever the writes look like.
type outputRing struct {
	cap  int
	buf  []byte
	bits []byte
	end  int64
}

func (r *outputRing) earliest() int64 { return max(0, r.end-int64(len(r.buf))) }

func (r *outputRing) write(p []byte, stderr bool) {
	if len(p) > r.cap {
		// Only the last cap bytes can be kept; skip the rest at once.
		r.end += int64(len(p) - r.cap)
		p = p[len(p)-r.cap:]
	}
	if len(r.buf) < r.cap {
		// Growing: offset o is at position o while everything still
		// fits, so a write that would not is the end of growing.
		if r.end == int64(len(r.buf)) && r.end+int64(len(p)) <= int64(r.cap) {
			pos := len(r.buf)
			r.resize(pos + len(p))
			copy(r.buf[pos:], p)
			r.mark(pos, len(p), stderr)
			r.end += int64(len(p))
			return
		}
		r.resize(r.cap)
	}
	for len(p) > 0 {
		pos := int(r.end % int64(r.cap))
		n := min(len(p), r.cap-pos)
		copy(r.buf[pos:], p[:n])
		r.mark(pos, n, stderr)
		r.end += int64(n)
		p = p[n:]
	}
}

// resize makes buf n bytes long, keeping what it holds where it is, and
// never with a backing array beyond cap: append's own growth could
// allocate up to twice what is needed.
func (r *outputRing) resize(n int) {
	if cap(r.buf) < n {
		grown := make([]byte, n, min(r.cap, max(n, 2*cap(r.buf))))
		copy(grown, r.buf)
		r.buf = grown
	} else {
		r.buf = r.buf[:n]
	}
	need := (n + 7) / 8
	if len(r.bits) < need {
		bits := make([]byte, need, min((r.cap+7)/8, max(need, 2*cap(r.bits))))
		copy(bits, r.bits)
		r.bits = bits
	}
}

func (r *outputRing) mark(pos, n int, stderr bool) {
	for i := 0; i < n; i++ {
		at := (pos + i) % r.cap
		if stderr {
			r.bits[at/8] |= 1 << (at % 8)
		} else {
			r.bits[at/8] &^= 1 << (at % 8)
		}
	}
}

func (r *outputRing) isStderr(offset int64) bool {
	at := int(offset % int64(r.cap))
	return r.bits[at/8]&(1<<(at%8)) != 0
}

// read returns the held bytes in [from, to) as chunks, splitting where
// the stream changes, at most maxChunks of them; next is where it
// stopped.
func (r *outputRing) read(from, to int64, maxChunks int) (chunks []ExecChunk, next int64) {
	next = from
	for next < to && len(chunks) < maxChunks {
		stderr := r.isStderr(next)
		start := next
		for next < to && r.isStderr(next) == stderr {
			next++
		}
		data := make([]byte, 0, next-start)
		for o := start; o < next; {
			pos := int(o % int64(r.cap))
			n := min(int(next-o), r.cap-pos)
			data = append(data, r.buf[pos:pos+n]...)
			o += int64(n)
		}
		stream := "stdout"
		if stderr {
			stream = "stderr"
		}
		chunks = append(chunks, ExecChunk{Stream: stream, Offset: start, Data: data})
	}
	return chunks, next
}

// ExecRecord is one recoverable exec. Its writers are safe to use from
// the runtime's copy goroutines; Finish is called once.
type ExecRecord struct {
	id, runID string
	started   time.Time
	registry  *execRegistry

	mu       sync.Mutex
	ring     outputRing
	done     bool
	finished time.Time
	exitCode int
	timedOut bool
	errText  string
	detached bool
}

// ID is the exec's ID, the one the caller looks it up by.
func (e *ExecRecord) ID() string { return e.id }

// Write records p as output of the given stream ("stdout" or "stderr").
func (e *ExecRecord) Write(stream string, p []byte) {
	e.mu.Lock()
	e.ring.write(p, stream == "stderr")
	e.mu.Unlock()
}

// Finish records how the command ended. err is a sandbox failure; the
// exit code is then -1, as the stream reports it.
func (e *ExecRecord) Finish(code int, timedOut bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done {
		return
	}
	e.done = true
	e.finished = e.registry.now()
	e.exitCode, e.timedOut = code, timedOut
	if err != nil {
		e.exitCode = -1
		e.errText = err.Error()
	}
}

// Detach records that the stream went away before the command ended.
func (e *ExecRecord) Detach() {
	e.mu.Lock()
	if !e.done {
		e.detached = true
	}
	e.mu.Unlock()
}

func (e *ExecRecord) finishedAt() (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.finished, e.done
}

func (e *ExecRecord) status() ExecStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := ExecStatus{
		ID: e.id, RunID: e.runID, State: ExecRunning, StartedAt: e.started,
		Detached: e.detached,
		Output:   ExecOutputRange{Start: e.ring.earliest(), End: e.ring.end, CapBytes: e.ring.cap},
	}
	if e.done {
		finished := e.finished
		expires := finished.Add(e.registry.ttl)
		code := e.exitCode
		status.FinishedAt, status.ExpiresAt, status.ExitCode = &finished, &expires, &code
		status.TimedOut = e.timedOut
		status.Error = e.errText
		switch {
		case e.errText != "":
			status.State = ExecFailed
		case e.timedOut:
			status.State = ExecTimedOut
		default:
			status.State = ExecExited
			if code > 128 && code <= 128+64 {
				status.Signal = code - 128
			}
		}
	}
	return status
}

// output reads the record: from since when it is given (resume), else the
// last limit bytes (tail).
func (e *ExecRecord) output(since *int64, limit int) (ExecOutput, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	earliest, end := e.ring.earliest(), e.ring.end
	out := ExecOutput{End: end}
	var from int64
	if since != nil {
		if *since < 0 || *since > end {
			return out, fmt.Errorf("%w: since %d is outside the output, which ends at offset %d", ErrBadRequest, *since, end)
		}
		from = *since
		if from < earliest {
			from = earliest
			out.Truncated = true
		}
	} else {
		from = max(earliest, end-int64(limit))
	}
	to := min(end, from+int64(limit))
	out.Chunks, out.Next = e.ring.read(from, to, ExecOutputMaxChunks)
	if out.Chunks == nil {
		out.Chunks = []ExecChunk{}
	}
	out.Start = from
	out.Done = e.done && out.Next == end
	return out, nil
}

// execRegistry holds the recoverable execs of every run.
type execRegistry struct {
	now      func() time.Time
	ttl      time.Duration
	capBytes int
	perRun   int
	total    int

	mu      sync.Mutex
	records map[string]*ExecRecord
}

func newExecRegistry(now func() time.Time) *execRegistry {
	return &execRegistry{
		now: now, ttl: ExecRetention, capBytes: ExecOutputBytes,
		perRun: ExecRecordsPerRun, total: ExecRecordsTotal,
		records: map[string]*ExecRecord{},
	}
}

// start makes the record for a new exec on runID, evicting expired
// records, and then the oldest finished ones, to stay within the bounds.
func (g *execRegistry) start(runID string) (*ExecRecord, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	if err := g.makeRoomLocked(func(e *ExecRecord) bool { return e.runID == runID }, g.perRun); err != nil {
		return nil, fmt.Errorf("%w: run %s already has %d recoverable execs running", ErrAtCapacity, runID, g.perRun)
	}
	if err := g.makeRoomLocked(func(*ExecRecord) bool { return true }, g.total); err != nil {
		return nil, fmt.Errorf("%w: this daemon already has %d recoverable execs running", ErrAtCapacity, g.total)
	}
	now := g.now()
	record := &ExecRecord{id: NewULID(now), runID: runID, started: now, registry: g, ring: outputRing{cap: g.capBytes}}
	g.records[record.id] = record
	return record, nil
}

// makeRoomLocked evicts the oldest finished records among those that
// match until fewer than bound match; it fails when only running ones
// are left.
func (g *execRegistry) makeRoomLocked(match func(*ExecRecord) bool, bound int) error {
	var held, finished []*ExecRecord
	for _, record := range g.records {
		if !match(record) {
			continue
		}
		held = append(held, record)
		if _, done := record.finishedAt(); done {
			finished = append(finished, record)
		}
	}
	sort.Slice(finished, func(i, j int) bool {
		a, _ := finished[i].finishedAt()
		b, _ := finished[j].finishedAt()
		return a.Before(b)
	})
	for over := len(held) - bound + 1; over > 0; over-- {
		if len(finished) == 0 {
			return ErrAtCapacity
		}
		delete(g.records, finished[0].id)
		finished = finished[1:]
	}
	return nil
}

func (g *execRegistry) sweepLocked() {
	now := g.now()
	for id, record := range g.records {
		if finished, done := record.finishedAt(); done && !now.Before(finished.Add(g.ttl)) {
			delete(g.records, id)
		}
	}
}

// sweep drops expired records, and every record of a run keep says is
// gone.
func (g *execRegistry) sweep(keep func(runID string) bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	for id, record := range g.records {
		if !keep(record.runID) {
			delete(g.records, id)
		}
	}
}

func (g *execRegistry) get(runID, execID string) (*ExecRecord, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	record, ok := g.records[execID]
	if !ok || record.runID != runID {
		return nil, execNotFound(runID, execID)
	}
	return record, nil
}

func (g *execRegistry) list(runID string) []ExecStatus {
	g.mu.Lock()
	g.sweepLocked()
	var records []*ExecRecord
	for _, record := range g.records {
		if record.runID == runID {
			records = append(records, record)
		}
	}
	g.mu.Unlock()
	statuses := make([]ExecStatus, 0, len(records))
	for _, record := range records {
		statuses = append(statuses, record.status())
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].ID < statuses[j].ID })
	return statuses
}

func (g *execRegistry) dropRun(runID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, record := range g.records {
		if record.runID == runID {
			delete(g.records, id)
		}
	}
}

// count is how many records are held, for tests.
func (g *execRegistry) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.records)
}

// RecordExec makes the record of a recoverable exec on a run; the caller
// writes the command's output to it and finishes it. Refused with
// ErrAtCapacity when the bounds are full of running execs.
func (m *Manager) RecordExec(runID string) (*ExecRecord, error) {
	if _, err := m.Get(runID); err != nil {
		return nil, err
	}
	return m.execLog.start(runID)
}

// ExecStatus is a recoverable exec's status. The run must exist (a
// stopped one does); an exec this daemon has no record of is
// ErrExecNotFound with the reasons.
func (m *Manager) ExecStatus(runID, execID string) (ExecStatus, error) {
	if _, err := m.Get(runID); err != nil {
		return ExecStatus{}, err
	}
	record, err := m.execLog.get(runID, execID)
	if err != nil {
		return ExecStatus{}, err
	}
	return record.status(), nil
}

// ExecOutput reads a recoverable exec's output: from since when it is not
// nil, else the last limit bytes. limit must be positive; it is capped at
// ExecOutputBytes.
func (m *Manager) ExecOutput(runID, execID string, since *int64, limit int) (ExecOutput, error) {
	if _, err := m.Get(runID); err != nil {
		return ExecOutput{}, err
	}
	record, err := m.execLog.get(runID, execID)
	if err != nil {
		return ExecOutput{}, err
	}
	if limit <= 0 {
		return ExecOutput{}, fmt.Errorf("%w: limit must be positive", ErrBadRequest)
	}
	return record.output(since, min(limit, ExecOutputBytes))
}

// ListExecs is every recoverable exec this daemon holds a record of for a
// run, oldest first.
func (m *Manager) ListExecs(runID string) ([]ExecStatus, error) {
	if _, err := m.Get(runID); err != nil {
		return nil, err
	}
	return m.execLog.list(runID), nil
}
