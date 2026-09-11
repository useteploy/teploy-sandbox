package run

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidateWorkPath(t *testing.T) {
	for path, wantErr := range map[string]bool{
		"a.txt":        false,
		"notes/a.txt":  false,
		"":             true,
		"/etc/passwd":  true,
		"../escape":    true,
		"a/../../b":    true,
		"a//b":         true,
		"nested/../ok": true,
	} {
		got, err := ValidateWorkPath(path)
		if wantErr && err == nil {
			t.Fatalf("%q: expected rejection, got %q", path, got)
		}
		if !wantErr {
			if err != nil {
				t.Fatalf("%q: unexpected error %v", path, err)
			}
			if !strings.HasPrefix(got, WorkDir+"/") {
				t.Fatalf("%q resolved outside workdir: %q", path, got)
			}
		}
	}
}

func TestULIDShape(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		id := NewULID(time.Now())
		if len(id) != 26 {
			t.Fatalf("ULID length: %q", id)
		}
		for _, r := range id {
			if !strings.ContainsRune(ulidAlphabet, r) {
				t.Fatalf("ULID char %q outside alphabet", r)
			}
		}
		if seen[id] {
			t.Fatalf("duplicate ULID: %q", id)
		}
		seen[id] = true
	}
	// timestamps order lexicographically
	early := NewULID(time.UnixMilli(1_000_000))
	late := NewULID(time.UnixMilli(2_000_000_000_000))
	if early >= late {
		t.Fatalf("ULIDs must sort by time: %q >= %q", early, late)
	}
}

// fakeEgress records what the manager asked the proxy pool for.
type fakeEgress struct {
	mu     sync.Mutex
	opened map[string][]string
	closed []string
	err    error
}

func newFakeEgress() *fakeEgress { return &fakeEgress{opened: map[string][]string{}} }

func (f *fakeEgress) OpenFor(runID string, extra []string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened[runID] = extra
	return "http://172.31.99.1:40001", nil
}

func (f *fakeEgress) Close(runID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = append(f.closed, runID)
}

func TestParseNetworkTiers(t *testing.T) {
	for raw, want := range map[string]string{
		"":          NetworkNone,
		"none":      NetworkNone,
		"allowlist": NetworkAllowlist,
		"egress":    NetworkAllowlist, // deployed callers still send this
		"open":      NetworkOpen,
	} {
		got, err := ParseNetwork(raw)
		if err != nil || got != want {
			t.Fatalf("ParseNetwork(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"teploy", "host", "bridge", "Open", "ALLOWLIST", "full"} {
		if got, err := ParseNetwork(raw); err == nil {
			t.Fatalf("ParseNetwork(%q) = %q, want rejection", raw, got)
		} else if !errors.Is(err, ErrBadRequest) {
			t.Fatalf("ParseNetwork(%q) must be a 400: %v", raw, err)
		}
	}
}

func TestCreateOpenTierTakesNoProxy(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	manager.ProxyURL = "http://172.31.99.1:7443"

	open, err := manager.Create(context.Background(), CreateRequest{Image: "alpine", Network: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if open.Network != NetworkOpen {
		t.Fatalf("network: %q", open.Network)
	}
	// An open run has a real default route; a proxy URL pointing at the
	// internal bridge would be both unreachable and a filter it is
	// explicitly opting out of.
	if rt.created[0].ProxyURL != "" {
		t.Fatalf("open run must not be handed a proxy URL: %q", rt.created[0].ProxyURL)
	}

	// The alias normalizes so callers of either name see one tier name.
	aliased, err := manager.Create(context.Background(), CreateRequest{Image: "alpine", Network: "egress"})
	if err != nil {
		t.Fatal(err)
	}
	if aliased.Network != NetworkAllowlist {
		t.Fatalf("egress must normalize to allowlist, got %q", aliased.Network)
	}
	if rt.created[1].ProxyURL != manager.ProxyURL {
		t.Fatalf("allowlist run must get the shared proxy, got %q", rt.created[1].ProxyURL)
	}
}

func TestCreatePerRunEgressAllow(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	manager.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	manager.Egress = pool

	created, err := manager.Create(context.Background(), CreateRequest{
		Image:       "ruby:3.3",
		Network:     "allowlist",
		EgressAllow: []string{"RubyGems.org", ".hex.pm", "forge.example.com:49152"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Extra entries are scoped to this run: its own proxy, not the
	// deployment-wide one every other run is pointed at.
	if got := rt.created[0].ProxyURL; got == manager.ProxyURL || got == "" {
		t.Fatalf("run with egressAllow must get a private proxy, got %q", got)
	}
	want := []string{"rubygems.org", ".hex.pm", "forge.example.com:49152"}
	if got := pool.opened[created.ID]; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("normalized entries: %v, want %v", got, want)
	}

	// ...and it dies with the run.
	if err := manager.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if len(pool.closed) != 1 || pool.closed[0] != created.ID {
		t.Fatalf("destroy must close the run's proxy, closed=%v", pool.closed)
	}
}

func TestCreateEgressAllowRefusals(t *testing.T) {
	manager, _, _ := newTestManager(t)
	manager.ProxyURL = "http://172.31.99.1:7443"
	manager.Egress = newFakeEgress()

	for _, tc := range []struct {
		name string
		req  CreateRequest
	}{
		{"url not host", CreateRequest{Image: "x", Network: "allowlist", EgressAllow: []string{"https://rubygems.org/gems"}}},
		{"wildcard", CreateRequest{Image: "x", Network: "allowlist", EgressAllow: []string{"*.hex.pm"}}},
		{"whole TLD", CreateRequest{Image: "x", Network: "allowlist", EgressAllow: []string{".com"}}},
		{"bad port", CreateRequest{Image: "x", Network: "allowlist", EgressAllow: []string{"forge.example.com:99999"}}},
		{"empty entry", CreateRequest{Image: "x", Network: "allowlist", EgressAllow: []string{""}}},
		// A per-run list on a tier with no allowlist is a caller
		// misunderstanding, not a no-op — say so.
		{"none tier", CreateRequest{Image: "x", Network: "none", EgressAllow: []string{"rubygems.org"}}},
		{"open tier", CreateRequest{Image: "x", Network: "open", EgressAllow: []string{"rubygems.org"}}},
	} {
		if _, err := manager.Create(context.Background(), tc.req); err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		} else if !errors.Is(err, ErrBadRequest) {
			t.Fatalf("%s: must be a 400, got %v", tc.name, err)
		}
	}

	// No proxy on this daemon: refuse rather than hand back a run whose
	// extra entries were quietly dropped.
	bare, _, _ := newTestManager(t)
	if _, err := bare.Create(context.Background(), CreateRequest{
		Image: "x", Network: "allowlist", EgressAllow: []string{"rubygems.org"},
	}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("egressAllow without a proxy pool must 400, got %v", err)
	}
}

// TestDestroyRetriesAfterFailedRemove is the sandbox-01 regression: Destroy
// untracked the run before runtime.Remove, so a failed removal leaked the
// container with nothing left that knows about it — and released the run's
// warm volume and egress proxy on top. The run must stay tracked and its
// resources held until the removal actually succeeds.
func TestDestroyRetriesAfterFailedRemove(t *testing.T) {
	manager, rt, _ := newTestManager(t)
	created, err := manager.Create(context.Background(), CreateRequest{Image: "x"})
	if err != nil {
		t.Fatal(err)
	}

	rt.removeErr = errors.New("docker daemon down")
	if err := manager.Destroy(context.Background(), created.ID); err == nil {
		t.Fatal("destroy must surface the remove failure")
	}
	if _, err := manager.Get(created.ID); err != nil {
		t.Fatal("failed destroy must keep the run tracked for retry")
	}

	rt.removeErr = nil
	if err := manager.Destroy(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	if len(rt.removed) != 1 || rt.removed[0] != created.ContainerID {
		t.Fatalf("the retry must remove the container, removed=%v", rt.removed)
	}
	if _, err := manager.Get(created.ID); err == nil {
		t.Fatal("run must be untracked after the successful retry")
	}
}

func TestReapClosesPerRunProxy(t *testing.T) {
	manager, _, _ := newTestManager(t)
	manager.ProxyURL = "http://172.31.99.1:7443"
	pool := newFakeEgress()
	manager.Egress = pool
	now := time.Now()
	manager.SetClock(func() time.Time { return now })

	created, err := manager.Create(context.Background(), CreateRequest{
		Image: "x", Network: "allowlist", TTLSec: 60, EgressAllow: []string{"rubygems.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if reaped := manager.Reap(context.Background()); reaped != 1 {
		t.Fatalf("reaped %d", reaped)
	}
	if len(pool.closed) != 1 || pool.closed[0] != created.ID {
		t.Fatalf("the reaper must close the run's proxy too, closed=%v", pool.closed)
	}
}
