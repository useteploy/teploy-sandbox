package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

// scrubOnly is remote storage as far as a scrub of a daemon with no
// stopped runs reaches: the scrub that reads, and nothing else.
type scrubOnly struct{ run.OffHost }

func (scrubOnly) ScrubContent(context.Context, []string, int64) (run.ContentScrub, error) {
	return run.ContentScrub{ReadBytes: 1234, Snapshots: 2, Complete: true}, nil
}

// POST /v1/remote/scrub answers with what the scrub found, the scrub
// that reads included (2026-11-21); the three fields it had are as they
// were.
func TestRemoteScrubAnswersWhatItRead(t *testing.T) {
	ts, _, manager := newTestServer(t)
	manager.OffHost = scrubOnly{}
	manager.RemoteScrubReadBytes = 1 << 20
	resp := request(t, ts, "POST", "/v1/remote/scrub", "test-token", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var answer map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"checked", "notWhole", "unreachable", "contentSnapshots", "damaged"} {
		if _, ok := answer[field]; !ok {
			t.Errorf("no %q in %v", field, answer)
		}
	}
	if answer["contentReadBytes"] != float64(1234) {
		t.Fatalf("contentReadBytes: %v", answer["contentReadBytes"])
	}
}
