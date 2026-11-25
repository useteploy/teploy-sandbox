package access

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// [S3] Per run: 64 streams, at most 16 anonymous, and 4 only for
// sessions, so a run's owner can always open a shell while the run is
// under its cap; per daemon: the total.
func TestRegistryCaps(t *testing.T) {
	r := NewRegistry(Limits{Total: 1000}, nil, quiet())
	var held []*Stream
	admit := func(run string, kind Kind, anon bool) error {
		s, err := r.Admit(run, kind, 3000, anon, "edge", GrantRef{}, "")
		if err == nil {
			held = append(held, s)
		}
		return err
	}
	for i := range DefaultPerRunAnon {
		if err := admit(runA, KindConnect, true); err != nil {
			t.Fatalf("anonymous %d: %v", i, err)
		}
	}
	if err := admit(runA, KindConnect, true); !errors.Is(err, ErrAnonStreams) {
		t.Fatalf("anonymous over the sub-cap: %v", err)
	}
	// A flooded public port does not stop the owner's shell.
	if err := admit(runA, KindSession, false); err != nil {
		t.Fatalf("session beside a flooded public port: %v", err)
	}
	for i := DefaultPerRunAnon; i < DefaultPerRun-DefaultSessionReserve; i++ {
		if err := admit(runA, KindConnect, false); err != nil {
			t.Fatalf("granted %d: %v", i, err)
		}
	}
	if err := admit(runA, KindConnect, false); !errors.Is(err, ErrRunStreams) {
		t.Fatalf("connect into the session reserve: %v", err)
	}
	for i := 1; i < DefaultSessionReserve; i++ {
		if err := admit(runA, KindSession, false); err != nil {
			t.Fatalf("session %d of the reserve: %v", i, err)
		}
	}
	if err := admit(runA, KindSession, false); !errors.Is(err, ErrRunStreams) {
		t.Fatalf("a session over the run's cap: %v", err)
	}
	if got := r.Streams(runA); got != DefaultPerRun {
		t.Fatalf("run streams %d, want %d", got, DefaultPerRun)
	}
	// Another run is not affected by the first being full.
	if err := admit(runB, KindConnect, true); err != nil {
		t.Fatalf("another run: %v", err)
	}
	// Releasing gives the slot back.
	held[0].Release()
	if err := admit(runA, KindConnect, true); err != nil {
		t.Fatalf("after a release: %v", err)
	}
	small := NewRegistry(Limits{Total: 2}, nil, quiet())
	_, _ = small.Admit(runA, KindConnect, 1, false, "e", GrantRef{}, "")
	_, _ = small.Admit(runB, KindConnect, 1, false, "e", GrantRef{}, "")
	if _, err := small.Admit("01JD8X3Y4Z5A6B7C8D9E0F1G2K", KindSession, 1, false, "e", GrantRef{}, ""); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("over the daemon total: %v", err)
	}
}

// [S3] 16 runs saturated with anonymous streams do not block a 17th
// run's session, with the daemon cap at maxRuns x 64.
func TestSaturatedRunsDoNotBlockAnother(t *testing.T) {
	const maxRuns = 17
	r := NewRegistry(Limits{Total: maxRuns * DefaultPerRun}, nil, quiet())
	runs := make([]string, maxRuns)
	for i := range runs {
		runs[i] = "01JD8X3Y4Z5A6B7C8D9E0F1G" + string(rune('A'+i/26)) + string("0123456789ABCDEFGHJKMNPQRS"[i%26])
	}
	for _, id := range runs[:16] {
		for {
			if _, err := r.Admit(id, KindConnect, 1, true, "e", GrantRef{}, ""); err != nil {
				break
			}
		}
		for {
			if _, err := r.Admit(id, KindConnect, 1, false, "e", GrantRef{}, ""); err != nil {
				break
			}
		}
	}
	if _, err := r.Admit(runs[16], KindSession, 0, false, "e", GrantRef{}, ""); err != nil {
		t.Fatalf("a session to a 17th run beside 16 saturated ones: %v", err)
	}
}

func TestStreamCloseAndRelease(t *testing.T) {
	r := NewRegistry(Limits{Total: 10}, nil, quiet())
	s, _ := r.Admit(runA, KindConnect, 1, false, "e", GrantRef{}, "")
	calls := 0
	if !s.OnClose(func() { calls++ }) {
		t.Fatal("OnClose on an open stream")
	}
	r.CloseRun(runA, "revoked")
	r.CloseRun(runA, "again")
	if calls != 1 || s.Reason() != "revoked" {
		t.Fatalf("close ran %d times, reason %q", calls, s.Reason())
	}
	if s.OnClose(func() {}) {
		t.Fatal("OnClose on a closed stream registered")
	}
	if r.Count() != 1 {
		t.Fatal("a closed stream left the registry before its release")
	}
	s.Release()
	s.Release()
	if r.Count() != 0 || r.Streams(runA) != 0 {
		t.Fatalf("after release: %d", r.Count())
	}
	// CloseAt in the past closes at once.
	s2, _ := r.Admit(runA, KindConnect, 1, false, "e", GrantRef{}, "")
	s2.CloseAt(time.Now().Add(-time.Second))
	select {
	case <-s2.Done():
	case <-time.After(time.Second):
		t.Fatal("CloseAt in the past did not close")
	}
	if s2.Reason() != "grant-expired" {
		t.Fatalf("reason %q", s2.Reason())
	}
	s2.Release()
	r.CloseAll("shutdown")
	if _, err := r.Admit(runA, KindConnect, 1, false, "e", GrantRef{}, ""); !errors.Is(err, ErrClosed) {
		t.Fatalf("admit after CloseAll: %v", err)
	}
}

func TestIdleStreamsAreClosedAndBytesMetered(t *testing.T) {
	var meteredRx, meteredTx int64
	r := NewRegistry(Limits{Total: 10, Idle: time.Minute}, func(_ string, rx, tx int64, _ bool) { meteredRx += rx; meteredTx += tx }, quiet())
	now := time.Now()
	r.now = func() time.Time { return now }
	busy, _ := r.Admit(runA, KindConnect, 1, false, "e", GrantRef{}, "")
	idle, _ := r.Admit(runA, KindConnect, 2, false, "e", GrantRef{}, "")
	busy.Moved(10, 20)
	now = now.Add(50 * time.Second)
	busy.Moved(1, 2)
	now = now.Add(20 * time.Second)
	r.sweep()
	if idle.Reason() != "idle" || busy.Reason() != "" {
		t.Fatalf("after the sweep: idle %q busy %q", idle.Reason(), busy.Reason())
	}
	if meteredRx != 11 || meteredTx != 22 {
		t.Fatalf("metered %d/%d at the sweep", meteredRx, meteredTx)
	}
	busy.Moved(5, 5)
	busy.Release()
	if meteredRx != 16 || meteredTx != 27 {
		t.Fatalf("metered %d/%d at the release", meteredRx, meteredTx)
	}
}

func TestBucket(t *testing.T) {
	now := time.Unix(0, 0)
	b := newBucket(8, func() time.Time { return now }) // 1 MB/s, burst 100 kB
	if wait := b.take(100000); wait != 0 {
		t.Fatalf("the burst waited %s", wait)
	}
	if wait := b.take(500000); wait < 490*time.Millisecond || wait > 510*time.Millisecond {
		t.Fatalf("half a second of traffic waits %s", wait)
	}
	if newBucket(0, time.Now) != nil || (*bucket)(nil).take(1<<30) != 0 {
		t.Fatal("no limit is not a nil bucket")
	}
}

// [S2] The sizing check refuses a stream cap the memory budget cannot hold.
func TestCheckMemory(t *testing.T) {
	if err := CheckMemory(22*64, 1024); err != nil {
		t.Fatalf("22 runs x 64 streams in 1 GiB: %v", err)
	}
	if err := CheckMemory(22*64, 256); err == nil || !strings.Contains(err.Error(), "access-streams-max") {
		t.Fatalf("22 runs x 64 streams in 256 MiB: %v", err)
	}
	if StreamMemory != 320<<10 {
		t.Fatalf("a stream's worst case is %d", StreamMemory)
	}
}

func TestConfigStore(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	key := "MCowBQYDK2VwAyEA" // not a raw key: refused
	for name, config := range map[string]Config{
		"keys without audience": {IssuerKeys: []IssuerKey{{Kid: "a", Ed25519: strings.Repeat("A", 43) + "="}}},
		"bad key":               {Audience: testAudience, IssuerKeys: []IssuerKey{{Kid: "a", Ed25519: key}}},
		"bad audience":          {Audience: "Upper.Example.com"},
		"bad denylisted name":   {Audience: testAudience, EdgeDenylist: []string{"has space"}},
	} {
		if err := store.Set(config); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	good := Config{Audience: testAudience, IssuerKeys: []IssuerKey{{Kid: "a", Ed25519: strings.Repeat("A", 43) + "="}}, EdgeDenylist: []string{"old-edge"}}
	if err := store.Set(good); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, configFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("persisted config: %v %v", info, err)
	}
	again, err := OpenStore(dir, "")
	if err != nil || again.Config().Audience != testAudience || !again.Denied("old-edge") || again.Denied("edge-1") {
		t.Fatalf("reopened: %+v %v", again.Config(), err)
	}
	// A file-managed configuration refuses PUT and reloads on demand.
	file := filepath.Join(dir, "operator.json")
	_ = os.WriteFile(file, []byte(`{"audience":"usercontent.example.com","edgeDenylist":["edge-9"]}`), 0o600)
	managed, err := OpenStore(dir, file)
	if err != nil || !managed.Denied("edge-9") {
		t.Fatalf("file-managed: %v", err)
	}
	if err := managed.Set(good); !errors.Is(err, ErrManagedByFile) {
		t.Fatalf("PUT on a file-managed config: %v", err)
	}
	_ = os.WriteFile(file, []byte(`{"audience":"usercontent.example.com","edgeDenylist":["edge-8"]}`), 0o600)
	if err := managed.Reload(); err != nil || !managed.Denied("edge-8") || managed.Denied("edge-9") {
		t.Fatalf("reload: %v", err)
	}
	_ = os.WriteFile(file, []byte(`{not json`), 0o600)
	if err := managed.Reload(); err == nil || !managed.Denied("edge-8") {
		t.Fatal("a broken file replaced the configuration")
	}
	if _, err := OpenStore(dir, filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("a missing operator file was taken for an empty configuration")
	}
}
