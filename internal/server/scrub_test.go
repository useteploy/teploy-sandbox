package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/offhost"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// scrubOnly is remote storage as far as a scrub of a daemon with no
// stopped runs reaches: the scrub that reads, and nothing else.
type scrubOnly struct{ run.OffHost }

func (scrubOnly) ScrubContent(context.Context, []string, int64) (run.ContentScrub, error) {
	return run.ContentScrub{ReadBytes: 1234, Snapshots: 2, Complete: true}, nil
}
func (scrubOnly) Rotate(context.Context) (run.RotateStats, error) {
	return run.RotateStats{}, nil
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
	for _, field := range []string{"checked", "notWhole", "unreachable", "contentSnapshots", "damaged", "rechecked"} {
		if _, ok := answer[field]; !ok {
			t.Errorf("no %q in %v", field, answer)
		}
	}
	if answer["contentReadBytes"] != float64(1234) {
		t.Fatalf("contentReadBytes: %v", answer["contentReadBytes"])
	}
}

// fakePushedCustody implements run.OffHost + run.CustodyOffHost for HTTP-level
// scrubbing, 428, and listener-guard tests without S3/ZFS.
type fakePushedCustody struct {
	run.OffHost
	needErr error
	keys    map[string]string // runID -> kid
}

func (f *fakePushedCustody) Fenced() bool { return true }
func (f *fakePushedCustody) Pushed() bool { return true }
func (f *fakePushedCustody) Custody() bool {
	return true
}
func (f *fakePushedCustody) HasLocal(context.Context, string) (bool, error)  { return true, nil }
func (f *fakePushedCustody) HasRemote(context.Context, string) (bool, error) { return true, nil }
func (f *fakePushedCustody) RemoteID(ref string) (string, bool)              { return "snap-id", true }
func (f *fakePushedCustody) Ref(id string) (string, bool)                    { return "teploy-sbx-snap:" + id, true }
func (f *fakePushedCustody) Verify(context.Context, string) error            { return nil }
func (f *fakePushedCustody) Upload(_ context.Context, req run.UploadRequest) (run.UploadResult, error) {
	return run.UploadResult{ID: "snap-1", Key: req.Key, StoredBytes: 128}, nil
}
func (f *fakePushedCustody) Advance(_ context.Context, rec run.RemoteRecord) (string, error) {
	return rec.Key, nil
}
func (f *fakePushedCustody) Latest(_ context.Context, id string) (run.RemoteRecord, error) {
	if f.needErr != nil {
		return run.RemoteRecord{}, f.needErr
	}
	return run.RemoteRecord{}, run.ErrNotFound
}
func (f *fakePushedCustody) LatestPublic(ctx context.Context, id string) (run.RemoteRecord, error) {
	return f.Latest(ctx, id)
}
func (f *fakePushedCustody) LatestAs(ctx context.Context, id, _ string) (run.RemoteRecord, error) {
	return f.Latest(ctx, id)
}
func (f *fakePushedCustody) LatestPublicAs(ctx context.Context, id, _ string) (run.RemoteRecord, error) {
	return f.Latest(ctx, id)
}
func (f *fakePushedCustody) EnsureCustody(_ context.Context, _ string, _ run.EnsureOptions) (run.SnapshotPin, error) {
	return run.SnapshotPin{}, f.needErr
}
func (f *fakePushedCustody) SnapshotPin(context.Context, string, string) (run.SnapshotPin, error) {
	return run.SnapshotPin{}, nil
}
func (f *fakePushedCustody) SnapshotMeta(context.Context, string, string) (run.SnapshotMeta, bool, error) {
	return run.SnapshotMeta{}, false, nil
}
func (f *fakePushedCustody) VerifyHoldKey(context.Context, string, string, string, run.PushedKey) error {
	return nil
}
func (f *fakePushedCustody) PutHoldKey(tenant, runID string, key run.PushedKey) (string, string, error) {
	parsed, err := offhost.ParseWrappedHoldKey(key.Wrapped)
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", run.ErrBadRequest, err)
	}
	if parsed.Tenant != tenant {
		return "", "", fmt.Errorf("%w: tenant mismatch", run.ErrBadRequest)
	}
	if f.keys == nil {
		f.keys = map[string]string{}
	}
	f.keys[runID] = parsed.KID
	return parsed.KID, key.Wrapped, nil
}
func (f *fakePushedCustody) BackupHoldKey(runID string) (func(string) error, func()) {
	prev, had := f.keys[runID]
	return func(string) error {
		if had {
			f.keys[runID] = prev
		} else {
			delete(f.keys, runID)
		}
		return nil
	}, func() {}
}
func (f *fakePushedCustody) SupplyOpenKeys(_ string, _ string, _ []run.PushedKey) (func(), error) {
	return func() {}, nil
}
func (f *fakePushedCustody) EraseHoldKey(runID, _ string) error {
	delete(f.keys, runID)
	return nil
}
func (f *fakePushedCustody) PruneHoldKeys(map[string]bool) (int, error) { return 0, nil }
func (f *fakePushedCustody) HoldKeyStatus(runID string) (bool, bool) {
	_, ok := f.keys[runID]
	return ok, false
}
func (f *fakePushedCustody) ForgetHoldKeyMemory(string) {}
func (f *fakePushedCustody) StageHoldKey(tenant, runID string, key run.PushedKey) (string, string, error) {
	return f.PutHoldKey(tenant, runID, key)
}
func (f *fakePushedCustody) CommitHoldKey(string, string, string) error               { return nil }
func (f *fakePushedCustody) DropStagedHoldKey(string, string) error                   { return nil }
func (f *fakePushedCustody) StagedHoldKeys() map[string]string                        { return nil }
func (f *fakePushedCustody) UpdateHoldKeyWrapped(string, string, string) error        { return nil }
func (f *fakePushedCustody) DeleteOlderRecords(context.Context, string, uint64) error { return nil }
func (f *fakePushedCustody) RekeySnapshot(context.Context, string, run.RekeySnapshotRequest) (run.RekeySnapshotResult, error) {
	return run.RekeySnapshotResult{Status: offhost.RekeyDone}, nil
}
func (f *fakePushedCustody) RekeyBulk(context.Context, run.RekeyBulkRequest) (run.RekeyBulkStats, error) {
	return run.RekeyBulkStats{Reasons: []string{}, Results: []run.RekeySnapshotResult{}}, nil
}
func (f *fakePushedCustody) RewrapRemote(context.Context, run.RotateRequest) (run.RewrapStats, error) {
	return run.RewrapStats{Reasons: []string{}}, nil
}

func mintTestPushedKey(t *testing.T, tenant, runID string) (key run.PushedKey, raw []byte) {
	t.Helper()
	tk := make([]byte, offhost.KeySize)
	raw = make([]byte, offhost.KeySize)
	kidBytes := make([]byte, 16)
	_, _ = rand.Read(tk)
	_, _ = rand.Read(raw)
	_, _ = rand.Read(kidBytes)
	kid := hex.EncodeToString(kidBytes)
	wrapped, err := offhost.WrapHoldKey(tk, raw, tenant, runID, kid, 1)
	if err != nil {
		t.Fatal(err)
	}
	return run.PushedKey{
		KID:     kid,
		Wrapped: wrapped,
		Raw:     base64.StdEncoding.EncodeToString(raw),
	}, raw
}

// Adversarial test #18: raw hold keys pushed in create, resume, fork, and
// POST /v1/runs/{id}/keys MUST NEVER appear in logs, error responses,
// GET /v1/runs, or runs.json on disk.
func TestRawKeysScrubbedFromLogsResponsesErrorsAndRegistry(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rt := newFakeRuntime()
	manager := run.NewManager(rt, logger)
	custody := &fakePushedCustody{}
	manager.OffHost = custody

	stateDir := t.TempDir()
	if _, err := manager.LoadState(context.Background(), stateDir); err != nil {
		t.Fatal(err)
	}
	srv := &Server{Manager: manager, Token: "test-token", Version: "test", Log: logger, ServerName: "test-box"}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	runID := run.NewULID(time.Now())
	forkID := run.NewULID(time.Now().Add(time.Millisecond))
	kCreate, rawCreate := mintTestPushedKey(t, "org-alpha", runID)
	kOpen, rawOpen := mintTestPushedKey(t, "org-alpha", runID)
	kResume, rawResume := mintTestPushedKey(t, "org-alpha", runID)
	kFork, rawFork := mintTestPushedKey(t, "org-alpha", forkID)
	kPush, rawPush := mintTestPushedKey(t, "org-alpha", runID)

	secrets := [][]byte{rawCreate, rawOpen, rawResume, rawFork, rawPush}
	assertNoLeak := func(where string, data []byte) {
		t.Helper()
		text := string(data)
		for i, raw := range secrets {
			for _, needle := range []string{
				base64.StdEncoding.EncodeToString(raw),
				base64.RawStdEncoding.EncodeToString(raw),
				hex.EncodeToString(raw),
			} {
				if strings.Contains(text, needle) {
					t.Fatalf("RAW KEY #%d LEAKED into %s", i, where)
				}
			}
		}
	}

	// 1. Create with keys.hold + keys.open
	createBody, _ := json.Marshal(map[string]any{
		"id":     runID,
		"image":  "alpine:latest",
		"tenant": "org-alpha",
		"keys":   map[string]any{"hold": kCreate, "open": []any{kOpen}},
	})
	resp := request(t, ts, "POST", "/v1/runs", "test-token", string(createBody))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	assertNoLeak("POST /v1/runs response", body)

	// 2. Stop (persists stopped run into runs.json)
	resp = request(t, ts, "POST", "/v1/runs/"+runID+"/stop", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stop: %d %s", resp.StatusCode, body)
	}
	assertNoLeak("POST /v1/runs/{id}/stop response", body)

	// 3. GET /v1/runs
	resp = request(t, ts, "GET", "/v1/runs", "test-token", "")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	assertNoLeak("GET /v1/runs response", body)

	// 4. POST /v1/runs/{id}/keys: pushing run's current key succeeds; pushing a
	// different key is refused (409); mismatched kid is 400 — none leak raw bytes.
	pushBody, _ := json.Marshal(map[string]any{"hold": kCreate})
	resp = request(t, ts, "POST", "/v1/runs/"+runID+"/keys", "test-token", string(pushBody))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push keys: %d %s", resp.StatusCode, body)
	}
	assertNoLeak("POST /v1/runs/{id}/keys response", body)

	diffPushBody, _ := json.Marshal(map[string]any{"hold": kPush})
	resp = request(t, ts, "POST", "/v1/runs/"+runID+"/keys", "test-token", string(diffPushBody))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("different-kid push keys: got %d %s, want 409", resp.StatusCode, body)
	}
	assertNoLeak("POST /v1/runs/{id}/keys 409 error", body)

	// Bad kid push -> 400 error body must not leak raw key or echo caller kid
	badPush := kCreate
	badPush.KID = "00000000000000000000000000000000"
	badBody, _ := json.Marshal(map[string]any{"hold": badPush})
	resp = request(t, ts, "POST", "/v1/runs/"+runID+"/keys", "test-token", string(badBody))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad push keys: %d %s", resp.StatusCode, body)
	}
	assertNoLeak("POST /v1/runs/{id}/keys 400 error", body)
	if strings.Contains(string(body), badPush.KID) {
		t.Fatalf("400 error echoed caller kid verbatim: %s", body)
	}

	// 5. Fork with keys.hold
	forkBody, _ := json.Marshal(map[string]any{
		"id":   forkID,
		"keys": map[string]any{"hold": kFork, "open": []any{kOpen}},
	})
	resp = request(t, ts, "POST", "/v1/runs/"+runID+"/fork", "test-token", string(forkBody))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("fork: %d %s", resp.StatusCode, body)
	}
	assertNoLeak("POST /v1/runs/{id}/fork response", body)

	// 6. Resume with keys.hold + keys.open triggering 428
	custody.needErr = &run.NeedKeyError{Missing: []run.KeyNeed{{Tenant: "org-alpha", Run: runID, KID: kCreate.KID, Wrapped: kCreate.Wrapped}}}
	resumeBody, _ := json.Marshal(map[string]any{
		"keys":   map[string]any{"hold": kResume, "open": []any{kOpen}},
		"expect": map[string]any{"generation": 1, "snapshot": "snap-1", "kid": kCreate.KID},
	})
	resp = request(t, ts, "POST", "/v1/runs/"+runID+"/resume", "test-token", string(resumeBody))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("resume 428: %d %s", resp.StatusCode, body)
	}
	var prob Problem
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatal(err)
	}
	if len(prob.NeedKeys) != 1 || prob.NeedKeys[0].KID != kCreate.KID || prob.NeedKeys[0].Wrapped != kCreate.Wrapped || prob.NeedKeys[0].Tenant != "org-alpha" {
		t.Fatalf("428 needKeys: %+v", prob.NeedKeys)
	}
	assertNoLeak("428 response", body)

	// 7. Check captured logs (including explicit slog JSON logging of every request struct) and runs.json
	logger.Info("explicit request struct logging check",
		"create", run.CreateRequest{ID: runID, Image: "alpine", Tenant: "org-alpha", Keys: &run.KeyBundle{Hold: &kCreate, Open: []run.PushedKey{kOpen}}},
		"resume", run.ResumeRequest{Keys: &run.KeyBundle{Hold: &kResume, Open: []run.PushedKey{kOpen}}},
		"fork", run.ForkRequest{ID: forkID, Keys: &run.KeyBundle{Hold: &kFork}},
		"push", run.PushKeysRequest{Hold: &kPush, Raw: kPush.Raw},
		"key", kCreate,
	)
	assertNoLeak("daemon logs", logBuf.Bytes())
	stateData, err := os.ReadFile(filepath.Join(stateDir, "runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak("runs.json", stateData)

	// 8. Also check fmt %v / %#v redaction on wire structs
	for name, formatted := range map[string]string{
		"PushedKey":       fmt.Sprintf("%v %#v", kCreate, kCreate),
		"KeyBundle":       fmt.Sprintf("%v %#v", run.KeyBundle{Hold: &kCreate}, run.KeyBundle{Hold: &kCreate}),
		"CreateRequest":   fmt.Sprintf("%v %#v", run.CreateRequest{Keys: &run.KeyBundle{Hold: &kCreate}}, run.CreateRequest{Keys: &run.KeyBundle{Hold: &kCreate}}),
		"ResumeRequest":   fmt.Sprintf("%v %#v", run.ResumeRequest{Keys: &run.KeyBundle{Hold: &kResume}}, run.ResumeRequest{Keys: &run.KeyBundle{Hold: &kResume}}),
		"ForkRequest":     fmt.Sprintf("%v %#v", run.ForkRequest{Keys: &run.KeyBundle{Hold: &kFork}}, run.ForkRequest{Keys: &run.KeyBundle{Hold: &kFork}}),
		"PushKeysRequest": fmt.Sprintf("%v %#v", run.PushKeysRequest{Hold: &kPush}, run.PushKeysRequest{Hold: &kPush}),
	} {
		assertNoLeak(name+" formatting", []byte(formatted))
	}
}

// Section 7: a daemon in pushed mode refuses raw keys on a listener that is
// neither loopback nor within an operator-configured --overlay-cidr unless TLS is on.
func TestPushedKeysListenerGuard(t *testing.T) {
	loopback := []string{
		"127.0.0.1:7439",
		"[::1]:7439",
		"localhost:7439",
	}
	for _, addr := range loopback {
		if err := SafeForPushedKeys(addr, false); err != nil {
			t.Errorf("SafeForPushedKeys(%q, false) = %v; want allowed", addr, err)
		}
	}
	// Without --overlay-cidr, CGNAT, ULA, RFC1918, unspecified, and public are ALL refused without TLS.
	refusedByDefault := []string{
		"0.0.0.0:7439",
		"[::]:7439",
		"[::ffff:0.0.0.0]:7439",
		"10.0.0.5:7439",
		"172.16.0.5:7439",
		"192.168.1.5:7439",
		"192.0.2.10:7439",
		"100.64.0.1:7439",
		"[fd00::1]:7439",
		"example.com:7439",
	}
	for _, addr := range refusedByDefault {
		if err := SafeForPushedKeys(addr, false); err == nil {
			t.Errorf("SafeForPushedKeys(%q, false) = nil; want refused without --overlay-cidr", addr)
		}
		if err := SafeForPushedKeys(addr, true); err != nil {
			t.Errorf("SafeForPushedKeys(%q, true) = %v; want allowed with TLS", addr, err)
		}
	}

	// With explicit --overlay-cidr configured, addresses inside those CIDRs are allowed,
	// while addresses outside them are still refused without TLS.
	cidrs, err := ParseOverlayCIDRs("100.64.0.0/10, fd7a:115c:a1e0::/48")
	if err != nil {
		t.Fatalf("ParseOverlayCIDRs: %v", err)
	}
	for _, addr := range []string{"100.64.0.1:7439", "100.127.255.254:7439", "[fd7a:115c:a1e0::1]:7439"} {
		if err := SafeForPushedKeys(addr, false, cidrs...); err != nil {
			t.Errorf("SafeForPushedKeys(%q, false, overlay) = %v; want allowed", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.5:7439", "[fd00::1]:7439", "0.0.0.0:7439"} {
		if err := SafeForPushedKeys(addr, false, cidrs...); err == nil {
			t.Errorf("SafeForPushedKeys(%q, false, overlay) = nil; want refused outside overlay CIDR", addr)
		}
	}
	if _, err := ParseOverlayCIDRs("not-a-cidr"); err == nil {
		t.Fatal("ParseOverlayCIDRs accepted invalid CIDR")
	}

	// HTTP-level enforcement: non-loopback/non-overlay ListenAddr without TLS
	// refuses requests carrying raw keys, while TLS and matching OverlayCIDRs accept them.
	discardLog := slog.New(slog.NewTextHandler(io.Discard, nil))
	rt := newFakeRuntime()
	manager := run.NewManager(rt, discardLog)
	manager.OffHost = &fakePushedCustody{}
	runID := run.NewULID(time.Now())
	k, _ := mintTestPushedKey(t, "org-alpha", runID)
	body, _ := json.Marshal(map[string]any{
		"id":     runID,
		"image":  "alpine:latest",
		"tenant": "org-alpha",
		"keys":   map[string]any{"hold": k},
	})

	unsafeSrv := &Server{Manager: manager, Token: "test-token", Version: "test", Log: discardLog, ServerName: "box", ListenAddr: "100.64.0.1:7439", TLS: false}
	unsafeTS := httptest.NewServer(unsafeSrv.Handler())
	defer unsafeTS.Close()
	resp := request(t, unsafeTS, "POST", "/v1/runs", "test-token", string(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("CGNAT listener without --overlay-cidr or TLS: got %d, want 400", resp.StatusCode)
	}

	// Same ListenAddr with matching OverlayCIDRs is accepted.
	overlaySrv := &Server{Manager: manager, Token: "test-token", Version: "test", Log: discardLog, ServerName: "box", ListenAddr: "100.64.0.1:7439", TLS: false, OverlayCIDRs: cidrs}
	overlayTS := httptest.NewServer(overlaySrv.Handler())
	defer overlayTS.Close()
	resp = request(t, overlayTS, "POST", "/v1/runs", "test-token", string(body))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("CGNAT listener WITH --overlay-cidr: got %d, want 201", resp.StatusCode)
	}

	// Same ListenAddr over TLS is accepted (with a fresh run ID).
	runID2 := run.NewULID(time.Now().Add(time.Millisecond))
	k2, _ := mintTestPushedKey(t, "org-alpha", runID2)
	body2, _ := json.Marshal(map[string]any{
		"id":     runID2,
		"image":  "alpine:latest",
		"tenant": "org-alpha",
		"keys":   map[string]any{"hold": k2},
	})
	tlsTS := httptest.NewTLSServer(unsafeSrv.Handler())
	defer tlsTS.Close()
	req, _ := http.NewRequest("POST", tlsTS.URL+"/v1/runs", strings.NewReader(string(body2)))
	req.Header.Set("Authorization", "Bearer test-token")
	tlsResp, err := tlsTS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	tlsResp.Body.Close()
	if tlsResp.StatusCode != http.StatusCreated {
		t.Fatalf("unsafe listener WITH TLS: got %d, want 201", tlsResp.StatusCode)
	}
}

// Flags-off identity: without key custody enabled, id/ids/tenant/keys/bases/expect
// are refused with 400 and GET /v1/runs has no custody fields.
func TestCustodyOffRefusesCustodyFieldsAndKeepsWireShape(t *testing.T) {
	ts, _, _ := newTestServer(t)
	for name, body := range map[string]string{
		"id":     `{"id":"` + run.NewULID(time.Now()) + `","image":"alpine:latest"}`,
		"tenant": `{"image":"alpine:latest","tenant":"org-a"}`,
		"bases":  `{"image":"alpine:latest","bases":{"base-1":"` + strings.Repeat("a", 64) + `"}}`,
		"expect": `{"image":"alpine:latest","expect":{"kid":"` + strings.Repeat("a", 32) + `"}}`,
	} {
		resp := request(t, ts, "POST", "/v1/runs", "test-token", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("flags-off create with %s: got %d, want 400", name, resp.StatusCode)
		}
	}
	// Ordinary create works and has no custody fields.
	resp := request(t, ts, "POST", "/v1/runs", "test-token", `{"image":"alpine:latest"}`)
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("plain create: %d %s", resp.StatusCode, raw)
	}
	for _, field := range []string{`"tenant"`, `"kid"`, `"legacy"`, `"needKeys"`} {
		if strings.Contains(string(raw), field) {
			t.Errorf("flags-off response leaked custody field %s: %s", field, raw)
		}
	}
}

// K4 HTTP routes: POST /v1/remote/snapshots/{id}/rekey, POST /v1/remote/rekey,
// POST /v1/remote/rotate {"mode":"rewrap"}, flags-off rotate byte-identity,
// listener-guard enforcement, and raw key scrubbing on K4 routes.
func TestK4RekeyAndRewrapHTTPRoutes(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	rt := newFakeRuntime()
	manager := run.NewManager(rt, logger)
	manager.OffHost = &fakePushedCustody{}

	srv := &Server{Manager: manager, Token: "test-token", Version: "test", Log: logger, ServerName: "box"}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	runID := run.NewULID(time.Now())
	kHold, rawHold := mintTestPushedKey(t, "org-alpha", runID)
	kHold.Run = runID
	kOpen, rawOpen := mintTestPushedKey(t, "org-alpha", runID)
	kOpen.Run = runID

	// 1. Single-snapshot rekey succeeds and scrubs raw keys.
	rekeySnapBody, _ := json.Marshal(map[string]any{
		"tenant": "org-alpha",
		"keys":   map[string]any{"hold": kHold, "open": []any{kOpen}},
	})
	resp := request(t, ts, "POST", "/v1/remote/snapshots/snap-abc/rekey", "test-token", string(rekeySnapBody))
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/remote/snapshots/{id}/rekey: %d %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"status":"rekeyed"`) {
		t.Fatalf("unexpected rekey snapshot body: %s", raw)
	}

	// 2. Bulk rekey succeeds and scrubs raw keys.
	rekeyBulkBody, _ := json.Marshal(map[string]any{
		"legacy":  true,
		"tenants": map[string]string{runID: "org-alpha"},
		"runKeys": map[string]any{runID: kHold},
	})
	resp = request(t, ts, "POST", "/v1/remote/rekey", "test-token", string(rekeyBulkBody))
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/remote/rekey: %d %s", resp.StatusCode, raw)
	}

	// 3. Rotate in rewrap mode succeeds; unknown mode is 400.
	rewrapBody, _ := json.Marshal(map[string]any{
		"mode":             "rewrap",
		"rewrapped":        map[string]string{kHold.KID: kHold.Wrapped},
		"retireTkVersions": []int{1},
	})
	resp = request(t, ts, "POST", "/v1/remote/rotate", "test-token", string(rewrapBody))
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/remote/rotate rewrap: %d %s", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), `"manifestsRewrapped":0`) || !strings.Contains(string(raw), `"oldKeysRemaining":0`) {
		t.Fatalf("unexpected rewrap body: %s", raw)
	}
	resp = request(t, ts, "POST", "/v1/remote/rotate", "test-token", `{"mode":"bogus"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /v1/remote/rotate bogus mode: %d, want 400", resp.StatusCode)
	}

	// 4. Verify raw keys from K4 requests never appeared in logs.
	for i, secret := range [][]byte{rawHold, rawOpen} {
		for _, needle := range []string{base64.StdEncoding.EncodeToString(secret), hex.EncodeToString(secret)} {
			if strings.Contains(logBuf.String(), needle) {
				t.Fatalf("RAW KEY #%d LEAKED into logs during K4 routes", i)
			}
		}
	}

	// 5. Listener guard refuses K4 rekey requests with raw keys over non-TLS/non-overlay.
	unsafeSrv := &Server{Manager: manager, Token: "test-token", Version: "test", Log: logger, ServerName: "box", ListenAddr: "10.0.0.5:7439", TLS: false}
	unsafeTS := httptest.NewServer(unsafeSrv.Handler())
	defer unsafeTS.Close()
	for _, path := range []string{"/v1/remote/snapshots/snap-abc/rekey", "/v1/remote/rekey"} {
		body := string(rekeySnapBody)
		if path == "/v1/remote/rekey" {
			body = string(rekeyBulkBody)
		}
		resp = request(t, unsafeTS, "POST", path, "test-token", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("unsafe listener on %s: got %d, want 400", path, resp.StatusCode)
		}
	}

	// 6. Flags-off: rekey routes return 400, and POST /v1/remote/rotate keeps
	// exact pre-K4 behavior (ignores body without parsing JSON, omits oldKeysRemaining).
	offTS, _, offManager := newTestServer(t)
	offManager.OffHost = scrubOnly{}
	for _, tc := range []struct{ path, body string }{
		{"/v1/remote/snapshots/snap-abc/rekey", `{}`},
		{"/v1/remote/rekey", `{}`},
	} {
		resp = request(t, offTS, "POST", tc.path, "test-token", tc.body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("flags-off %s: got %d, want 400", tc.path, resp.StatusCode)
		}
	}
	// Non-JSON body on POST /v1/remote/rotate with custody off is NOT rejected
	// as "Body must be JSON" (S15: pre-K4 ignored the body) and omits oldKeysRemaining.
	resp = request(t, offTS, "POST", "/v1/remote/rotate", "test-token", "not-json")
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(raw), "oldKeysRemaining") {
		t.Fatalf("flags-off rotate parsed body or leaked oldKeysRemaining: %d %s", resp.StatusCode, raw)
	}
}
