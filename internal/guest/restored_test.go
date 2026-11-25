//go:build unix

package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
)

func TestRestoredStepsTheClockAddsTheEntropyAndReportsWhatItDid(t *testing.T) {
	srv, client := newTestServer(t)
	var set int64
	var added []byte
	reseeded := true
	srv.SetClock = func(nowNs int64) error { set = nowNs; return nil }
	srv.AddEntropy = func(entropy []byte) (bool, error) { added = bytes.Clone(entropy); return reseeded, nil }
	seen := true
	srv.VMGenIDSeen = func() bool { return seen }
	srv.ClockNs = func() int64 { return set + 7 }

	const now = 1700000000123456789
	entropy := bytes.Repeat([]byte{0x5a}, RestoredEntropyBytes)
	got, err := client.Restored(ctxT(t), now, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if set != now {
		t.Errorf("the clock was set to %d, want %d", set, now)
	}
	if !bytes.Equal(added, entropy) {
		t.Errorf("the entropy added is %d bytes, want the %d the daemon sent, unchanged", len(added), len(entropy))
	}
	if want := (RestoredResult{VMGenIDSeen: true, Reseeded: true, ClockNs: now + 7}); got != want {
		t.Errorf("answer %+v, want %+v", got, want)
	}

	// What the agent cannot do is said, not assumed: no VM Generation ID
	// and a reseed the kernel refused.
	seen, reseeded = false, false
	if got, err = client.Restored(ctxT(t), now, entropy); err != nil {
		t.Fatal(err)
	}
	if got.VMGenIDSeen || got.Reseeded {
		t.Errorf("answer %+v claims a reseed the agent did not get", got)
	}
}

func TestRestoredFailsWhenTheClockCannotBeSet(t *testing.T) {
	srv, client := newTestServer(t)
	srv.SetClock = func(int64) error { return errors.New("operation not permitted") }
	added := false
	srv.AddEntropy = func([]byte) (bool, error) { added = true; return true, nil }
	_, err := client.Restored(ctxT(t), 1700000000000000000, make([]byte, RestoredEntropyBytes))
	if !IsCode(err, CodeInternal) {
		t.Fatalf("a clock that could not be set: %v, want an internal error", err)
	}
	if added {
		t.Errorf("entropy was added although the handshake had already failed")
	}
	// Entropy the kernel will not take is a failure too: the daemon must
	// not hand back a guest whose random state is still the saved one.
	srv.SetClock = func(int64) error { return nil }
	srv.AddEntropy = func([]byte) (bool, error) { return false, errors.New("no such device") }
	if _, err := client.Restored(ctxT(t), 1700000000000000000, make([]byte, RestoredEntropyBytes)); !IsCode(err, CodeInternal) {
		t.Fatalf("entropy the kernel refused: %v, want an internal error", err)
	}
}

func TestRestoredNeedsTheTimeAndTheEntropy(t *testing.T) {
	srv, client := newTestServer(t)
	set, added := false, false
	srv.SetClock = func(int64) error { set = true; return nil }
	srv.AddEntropy = func([]byte) (bool, error) { added = true; return true, nil }
	for name, req := range map[string]struct {
		now     int64
		entropy int
	}{
		"no time":         {0, RestoredEntropyBytes},
		"a negative time": {-1, RestoredEntropyBytes},
		"no entropy":      {1700000000000000000, 0},
		"too little":      {1700000000000000000, RestoredEntropyBytes - 1},
		"too much":        {1700000000000000000, RestoredEntropyBytes + 1},
	} {
		if _, err := client.Restored(ctxT(t), req.now, make([]byte, req.entropy)); !IsCode(err, CodeBadRequest) {
			t.Errorf("%s: %v, want a bad request", name, err)
		}
	}
	if set || added {
		t.Errorf("a malformed request reached the clock (%t) or the pool (%t)", set, added)
	}
}

// The request is a version 3 frame, and an agent built before version 3
// refuses it as such, so the daemon can tell "too old" from "failed".
func TestRestoredIsVersionThreeAndAnOlderAgentSaysSo(t *testing.T) {
	if requestVersion(OpRestored) != 3 {
		t.Fatalf("restored is sent as version %d, want 3", requestVersion(OpRestored))
	}
	var got Request
	old := func(conn net.Conn) {
		defer conn.Close()
		_, payload, err := readFrame(conn)
		if err != nil {
			return
		}
		_ = json.Unmarshal(payload, &got)
		_ = writeJSONFrame(conn, frameResult, Result{V: 2, Code: CodeUnsupportedVersion, Error: "protocol version 3 is not supported; this agent speaks 1 to 2"})
	}
	client := &Client{Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go old(b)
		return a, nil
	}}
	entropy := make([]byte, RestoredEntropyBytes)
	if _, err := client.Restored(ctxT(t), 1700000000000000000, entropy); !IsCode(err, CodeUnsupportedVersion) {
		t.Fatalf("restored to an agent that speaks to version 2: %v", err)
	}
	if got.V != 3 || got.Op != OpRestored || got.NowNs != 1700000000000000000 || !bytes.Equal(got.Entropy, entropy) {
		t.Errorf("the request the agent read: %+v", got)
	}
	// A version 3 agent answers a version 2 daemon's other ops as before.
	if requestVersion(OpPing) != 1 || requestVersion(OpExec) != 1 || requestVersion(OpConnect) != 2 {
		t.Fatalf("the older ops changed version: ping %d exec %d connect %d", requestVersion(OpPing), requestVersion(OpExec), requestVersion(OpConnect))
	}
}
