package access

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Kind is what an access stream is.
type Kind int

const (
	// KindConnect is a byte stream to a guest port.
	KindConnect Kind = iota + 1
	// KindSession is a shell (a later task; counted here already so the
	// caps reserve room for it).
	KindSession
)

func (k Kind) String() string {
	if k == KindSession {
		return "session"
	}
	return "connect"
}

// Default caps (docs/wire-contract.md, "Access").
const (
	DefaultPerRun         = 64
	DefaultPerRunAnon     = 16
	DefaultSessionReserve = 4
	DefaultIdle           = time.Hour
	DefaultAnonMbit       = 20
	DefaultTotalMbit      = 2000
	sweepEvery            = 10 * time.Second
	copyChunk             = 32 << 10
)

// Limits are the registry's caps and rates.
type Limits struct {
	// PerRun is a run's streams of every kind; at most PerRunAnon of them
	// without a grant, and SessionReserve of them only for sessions, so
	// that a run's owner can always open a shell while the run is under
	// its cap.
	PerRun         int
	PerRunAnon     int
	SessionReserve int
	// Total is the daemon's streams.
	Total int
	// GrantedMbit and AnonMbit shape each run's granted and anonymous
	// streams (each way, summed over the run's streams); TotalMbit all of
	// the daemon's. Zero or less is no limit.
	GrantedMbit int
	AnonMbit    int
	TotalMbit   int
	// Idle closes a stream that moved nothing for this long.
	Idle time.Duration
}

func (l Limits) withDefaults() Limits {
	if l.PerRun <= 0 {
		l.PerRun = DefaultPerRun
	}
	if l.PerRunAnon <= 0 {
		l.PerRunAnon = DefaultPerRunAnon
	}
	if l.SessionReserve < 0 {
		l.SessionReserve = 0
	}
	if l.SessionReserve == 0 {
		l.SessionReserve = DefaultSessionReserve
	}
	l.SessionReserve = min(l.SessionReserve, l.PerRun)
	l.PerRunAnon = min(l.PerRunAnon, l.PerRun-l.SessionReserve)
	if l.Idle <= 0 {
		l.Idle = DefaultIdle
	}
	return l
}

// Admission refusals.
var (
	ErrRunStreams  = errors.New("the run has as many access streams as it may")
	ErrAnonStreams = errors.New("the run has as many anonymous access streams as it may")
	ErrAtCapacity  = errors.New("the daemon has as many access streams as it may")
	ErrClosed      = errors.New("the access listener is shutting down")
)

// Registry is every open access stream, by run.
type Registry struct {
	// failed is set when the access listener died: the control routes
	// say so, and a probe notices instead of a page at expiry time.
	failed atomic.Bool
	limits Limits
	now    func() time.Time
	log    *slog.Logger
	// meter receives the bytes streams moved (run.Manager.AddAccessBytes).
	meter func(run string, rx, tx int64, anon bool)
	total *bucket

	mu     sync.Mutex
	runs   map[string]*runStreams
	count  int
	closed bool
}

type runStreams struct {
	streams  map[*Stream]struct{}
	anon     int
	sessions int
	granted  *bucket
	anonRate *bucket
	// released is when its last stream went, when the set is empty: the
	// entry stays so its rate buckets are not re-earned by churn, and
	// goes after a quiet minute.
	released time.Time
}

// NewRegistry is an empty registry.
func NewRegistry(limits Limits, meter func(run string, rx, tx int64, anon bool), log *slog.Logger) *Registry {
	limits = limits.withDefaults()
	if meter == nil {
		meter = func(string, int64, int64, bool) {}
	}
	r := &Registry{limits: limits, now: time.Now, log: log, meter: meter, runs: map[string]*runStreams{}}
	r.total = newBucket(limits.TotalMbit, r.now)
	return r
}

// Limits is the registry's configuration.
func (r *Registry) Limits() Limits { return r.limits }

// Stream is one admitted access stream.
type Stream struct {
	reg     *Registry
	Run     string
	Port    int
	Kind    Kind
	Anon    bool
	Edge    string
	Jti     string
	Request string
	opened  time.Time

	rx, tx    atomic.Int64
	last      atomic.Int64
	flushMu   sync.Mutex
	flushedRx int64
	flushedTx int64

	done chan struct{}

	mu sync.Mutex
	// fnMu is held while the OnClose functions run, and Release waits for
	// it: the handler that owns the stream's sockets does not return
	// while another goroutine is still closing them.
	fnMu     sync.Mutex
	closed   bool
	released bool
	reason   string
	onClose  []func()
	expiry   *time.Timer
}

// Admit counts a new stream against the caps. The caller must Release it.
func (r *Registry) Admit(run string, kind Kind, port int, anon bool, edge, jti, request string) (*Stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrClosed
	}
	if r.limits.Total > 0 && r.count >= r.limits.Total {
		return nil, ErrAtCapacity
	}
	streams := r.runs[run]
	if streams != nil && len(streams.streams) == 0 && !streams.released.IsZero() && r.now().Sub(streams.released) > time.Minute {
		// Idle a while: the entry's place in the rate buckets is spent,
		// and a new stream must not re-earn the burst by waiting out a
		// quiet minute between blasts.
		delete(r.runs, run)
		streams = nil
	}
	if streams == nil {
		streams = &runStreams{
			streams:  map[*Stream]struct{}{},
			granted:  newBucket(r.limits.GrantedMbit, r.now),
			anonRate: newBucket(r.limits.AnonMbit, r.now),
		}
	}
	n := len(streams.streams)
	switch {
	case kind == KindSession && n >= r.limits.PerRun:
		return nil, ErrRunStreams
	case kind != KindSession && n-streams.sessions >= r.limits.PerRun-r.limits.SessionReserve:
		return nil, ErrRunStreams
	case kind != KindSession && n >= r.limits.PerRun:
		return nil, ErrRunStreams
	case anon && streams.anon >= r.limits.PerRunAnon:
		return nil, ErrAnonStreams
	}
	now := r.now()
	s := &Stream{reg: r, Run: run, Port: port, Kind: kind, Anon: anon, Edge: edge, Jti: jti, Request: request, opened: now, done: make(chan struct{})}
	s.last.Store(now.UnixNano())
	streams.streams[s] = struct{}{}
	if anon {
		streams.anon++
	}
	if kind == KindSession {
		streams.sessions++
	}
	r.runs[run] = streams
	r.count++
	return s, nil
}

// Done is closed when the stream is closed.
func (s *Stream) Done() <-chan struct{} { return s.done }

// OnClose registers what closing the stream does (closing its sockets).
// It reports false, without registering, when the stream is closed
// already: the caller then tears down itself.
func (s *Stream) OnClose(fn func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.onClose = append(s.onClose, fn)
	return true
}

// CloseAt closes the stream at t, with reason "grant-expired".
func (s *Stream) CloseAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	wait := t.Sub(s.reg.now())
	if s.expiry != nil {
		s.expiry.Stop()
	}
	s.expiry = time.AfterFunc(max(wait, 0), func() { s.Close("grant-expired") })
}

// Close ends the stream: every OnClose function runs once.
func (s *Stream) Close(reason string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.reason = reason
	fns := s.onClose
	s.onClose = nil
	if s.expiry != nil {
		s.expiry.Stop()
	}
	close(s.done)
	s.fnMu.Lock()
	s.mu.Unlock()
	defer s.fnMu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// Reason is why the stream was closed ("" while open, or when it ended
// on its own).
func (s *Stream) Reason() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reason
}

// Moved records bytes the stream carried: rx to the guest, tx from it.
func (s *Stream) Moved(rx, tx int) {
	if rx > 0 {
		s.rx.Add(int64(rx))
	}
	if tx > 0 {
		s.tx.Add(int64(tx))
	}
	s.last.Store(s.reg.now().UnixNano())
}

// Shape waits until n more bytes of this stream fit its run's and the
// daemon's rates; false when the stream closed meanwhile.
func (s *Stream) Shape(n int) bool {
	s.reg.mu.Lock()
	streams := s.reg.runs[s.Run]
	var perRun *bucket
	if streams != nil {
		perRun = streams.granted
		if s.Anon {
			perRun = streams.anonRate
		}
	}
	s.reg.mu.Unlock()
	return waitAll(n, s.done, perRun, s.reg.total)
}

// flush hands the bytes moved since the last flush to the meter.
func (s *Stream) flush() {
	s.flushMu.Lock()
	rx, tx := s.rx.Load(), s.tx.Load()
	drx, dtx := rx-s.flushedRx, tx-s.flushedTx
	s.flushedRx, s.flushedTx = rx, tx
	s.flushMu.Unlock()
	if drx > 0 || dtx > 0 {
		s.reg.meter(s.Run, drx, dtx, s.Anon)
	}
}

// Release takes the stream out of the registry once its handler is done
// with it, and meters what is left.
func (s *Stream) Release() {
	s.Close("")
	// A Close from another goroutine may still be running its functions.
	s.fnMu.Lock()
	s.fnMu.Unlock()
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return
	}
	s.released = true
	reason := s.reason
	s.mu.Unlock()
	r := s.reg
	r.mu.Lock()
	if streams := r.runs[s.Run]; streams != nil {
		if _, ok := streams.streams[s]; ok {
			delete(streams.streams, s)
			r.count--
			if s.Anon {
				streams.anon--
			}
			if s.Kind == KindSession {
				streams.sessions--
			}
		}
		if len(streams.streams) == 0 {
			// Kept, not deleted: the buckets age out in Admit, so a
			// stream that churns (open, blast, close, reopen) does not
			// re-earn its burst each time.
			streams.released = r.now()
		}
	}
	r.mu.Unlock()
	s.flush()
	if r.log != nil {
		if reason == "" {
			reason = "ended"
		}
		r.log.Info("access stream closed", "run", s.Run, "kind", s.Kind.String(), "port", s.Port, "anonymous", s.Anon,
			"edge", s.Edge, "jti", s.Jti, "request", s.Request, "rxBytes", s.rx.Load(), "txBytes", s.tx.Load(),
			"duration", r.now().Sub(s.opened).Round(time.Millisecond).String(), "reason", reason)
	}
}

// matching closes the streams of run that pick selects.
func (r *Registry) matching(run string, pick func(*Stream) bool) []*Stream {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Stream
	if streams := r.runs[run]; streams != nil {
		for s := range streams.streams {
			if pick(s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// CloseRun ends every stream of a run (run.AccessStreams).
func (r *Registry) CloseRun(run, reason string) {
	for _, s := range r.matching(run, func(*Stream) bool { return true }) {
		s.Close(reason)
	}
}

// ClosePort ends a port's anonymous streams (run.AccessStreams).
func (r *Registry) ClosePort(run string, port int, reason string) {
	for _, s := range r.matching(run, func(s *Stream) bool { return s.Anon && s.Kind == KindConnect && s.Port == port }) {
		s.Close(reason)
	}
}

// Streams is how many streams a run has open (run.AccessStreams).
func (r *Registry) Streams(run string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if streams := r.runs[run]; streams != nil {
		return len(streams.streams)
	}
	return 0
}

// Count is how many streams the daemon has open.
func (r *Registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// CloseAll ends every stream and admits no more.
// ListenerFailed marks the registry's listener as dead.
func (r *Registry) ListenerFailed() { r.failed.Store(true) }

// ListenerDown says the listener died and nothing is being served.
func (r *Registry) ListenerDown() bool { return r.failed.Load() }

func (r *Registry) CloseAll(reason string) {
	r.mu.Lock()
	r.closed = true
	var all []*Stream
	for _, streams := range r.runs {
		for s := range streams.streams {
			all = append(all, s)
		}
	}
	r.mu.Unlock()
	for _, s := range all {
		s.Close(reason)
	}
}

// sweep meters what every stream moved since the last sweep and closes
// the streams idle for longer than Limits.Idle.
func (r *Registry) sweep() {
	r.mu.Lock()
	var all []*Stream
	for _, streams := range r.runs {
		for s := range streams.streams {
			all = append(all, s)
		}
	}
	r.mu.Unlock()
	cutoff := r.now().Add(-r.limits.Idle).UnixNano()
	for _, s := range all {
		s.flush()
		if s.last.Load() < cutoff {
			s.Close("idle")
		}
	}
}

// Run sweeps until ctx ends.
func (r *Registry) Run(ctx context.Context) {
	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}
