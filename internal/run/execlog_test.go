package run

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

// The ring against a model that keeps everything: whatever the writes
// look like, it holds exactly the last cap bytes, each with its stream,
// and never more memory than its bound.
func TestOutputRingMatchesAModel(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	for _, tc := range []struct{ capBytes, maxWrite int }{
		{1, 3}, {7, 17}, {64, 131}, {1000, 2003},
		// Small writes: the ring grows in many steps before it wraps.
		{64, 5}, {1000, 37}, {4096, 300},
	} {
		capBytes := tc.capBytes
		ring := outputRing{cap: capBytes}
		var all []byte
		var streams []bool
		for range 400 {
			n := random.Intn(tc.maxWrite + 1)
			p := make([]byte, n)
			random.Read(p)
			stderr := random.Intn(2) == 0
			ring.write(p, stderr)
			all = append(all, p...)
			for range p {
				streams = append(streams, stderr)
			}
			if cap(ring.buf) > capBytes || cap(ring.bits) > (capBytes+7)/8 {
				t.Fatalf("cap %d: buffer grew to %d bytes, bits %d", capBytes, cap(ring.buf), cap(ring.bits))
			}
			if ring.end != int64(len(all)) {
				t.Fatalf("end %d, wrote %d", ring.end, len(all))
			}
			earliest := max(0, len(all)-capBytes)
			if ring.earliest() != int64(earliest) {
				t.Fatalf("cap %d: earliest %d, want %d", capBytes, ring.earliest(), earliest)
			}
			from := int64(earliest + random.Intn(len(all)-earliest+1))
			chunks, next := ring.read(from, ring.end, 1<<30)
			if next != ring.end {
				t.Fatalf("read stopped at %d of %d", next, ring.end)
			}
			at := from
			for i, chunk := range chunks {
				if chunk.Offset != at || !bytes.Equal(chunk.Data, all[at:at+int64(len(chunk.Data))]) {
					t.Fatalf("cap %d chunk %d at %d: wrong bytes", capBytes, i, chunk.Offset)
				}
				for o := at; o < at+int64(len(chunk.Data)); o++ {
					if streams[o] != (chunk.Stream == "stderr") {
						t.Fatalf("cap %d: byte %d is from the wrong stream", capBytes, o)
					}
				}
				if i > 0 && chunks[i-1].Stream == chunk.Stream {
					t.Fatalf("cap %d: two chunks in a row from %s", capBytes, chunk.Stream)
				}
				at += int64(len(chunk.Data))
			}
		}
	}
}

func TestExecOutputChunkBound(t *testing.T) {
	g := newExecRegistry(time.Now)
	record, err := g.start("run")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 * ExecOutputMaxChunks {
		stream := "stdout"
		if i%2 == 1 {
			stream = "stderr"
		}
		record.Write(stream, []byte{'x'})
	}
	zero := int64(0)
	out, err := record.output(&zero, ExecOutputBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Chunks) != ExecOutputMaxChunks || out.Next != ExecOutputMaxChunks || out.Done {
		t.Fatalf("chunks %d next %d done %t", len(out.Chunks), out.Next, out.Done)
	}
}

func TestExecRecordBoundsEvictFinishedFirst(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g := newExecRegistry(func() time.Time { return now })
	var first []*ExecRecord
	for range ExecRecordsPerRun {
		record, err := g.start("a")
		if err != nil {
			t.Fatal(err)
		}
		first = append(first, record)
	}
	if _, err := g.start("a"); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("a run full of running execs: %v", err)
	}
	// One finishes: it makes the room, the others stay.
	now = now.Add(time.Second)
	first[3].Finish(0, false, nil)
	if _, err := g.start("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.get("a", first[3].ID()); !errors.Is(err, ErrExecNotFound) {
		t.Fatalf("the finished record should have been evicted: %v", err)
	}
	if _, err := g.get("a", first[4].ID()); err != nil {
		t.Fatalf("a running record was evicted: %v", err)
	}

	// The daemon-wide bound.
	for i := 0; g.count() < ExecRecordsTotal; i++ {
		if _, err := g.start(string(rune('b' + i/ExecRecordsPerRun))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := g.start("z"); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("a daemon full of running execs: %v", err)
	}
}

func TestExecRecordsExpireAfterRetention(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	m := NewManager(&fakeRT{}, testLogger())
	m.SetClock(func() time.Time { return now })
	created, err := m.Create(context.Background(), CreateRequest{Image: "x"})
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.RecordExec(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Running records never expire.
	now = now.Add(2 * ExecRetention)
	if status, err := m.ExecStatus(created.ID, record.ID()); err != nil || status.State != ExecRunning {
		t.Fatalf("running: %+v %v", status, err)
	}
	record.Finish(-1, false, errors.New("run stopped"))
	status, err := m.ExecStatus(created.ID, record.ID())
	if err != nil || status.State != ExecFailed || *status.ExitCode != -1 || status.Error != "run stopped" || !status.ExpiresAt.Equal(now.Add(ExecRetention)) {
		t.Fatalf("failed: %+v %v", status, err)
	}
	now = now.Add(ExecRetention - time.Second)
	if _, err := m.ExecStatus(created.ID, record.ID()); err != nil {
		t.Fatalf("before retention: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := m.ExecStatus(created.ID, record.ID()); !errors.Is(err, ErrExecNotFound) {
		t.Fatalf("after retention: %v", err)
	}
	if m.execLog.count() != 0 {
		t.Fatalf("expired records still held: %d", m.execLog.count())
	}
}

func TestExecRecordsGoWhenTheRunDoes(t *testing.T) {
	m := NewManager(&fakeRT{}, testLogger())
	keep, _ := m.Create(context.Background(), CreateRequest{Image: "x"})
	drop, _ := m.Create(context.Background(), CreateRequest{Image: "x"})
	kept, _ := m.RecordExec(keep.ID)
	if _, err := m.RecordExec(drop.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.Destroy(context.Background(), drop.ID); err != nil {
		t.Fatal(err)
	}
	if m.execLog.count() != 1 {
		t.Fatalf("records after destroy: %d", m.execLog.count())
	}
	if _, err := m.ExecStatus(keep.ID, kept.ID()); err != nil {
		t.Fatal(err)
	}
	// Another run's ID does not reach the record.
	if _, err := m.ExecStatus(drop.ID, kept.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("destroyed run: %v", err)
	}
	other, _ := m.Create(context.Background(), CreateRequest{Image: "x"})
	if _, err := m.ExecStatus(other.ID, kept.ID()); !errors.Is(err, ErrExecNotFound) {
		t.Fatalf("someone else's exec: %v", err)
	}
}
