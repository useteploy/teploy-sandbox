package vm

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/accessgrant"
	"github.com/useteploy/teploy-sandbox/internal/access"
	"github.com/useteploy/teploy-sandbox/internal/run"
)

// The access listener's handler on the real manager and the VM driver
// (the hypervisor and the agent faked): a grant minted from the run's
// epoch works until a revoke in the same second, which closes the open
// stream and refuses the grant from then on; a stop closes streams before
// the VM goes.
func TestAccessEndToEndOnTheVMDriver(t *testing.T) {
	rig := newRig(t, nil)
	registry := access.NewRegistry(access.Limits{Total: 64}, rig.manager.AddAccessBytes, quietLog())
	rig.manager.EnableAccess(registry)
	seed := make([]byte, ed25519.SeedSize)
	issuer := ed25519.NewKeyFromSeed(seed)
	store, err := access.OpenStore("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(access.Config{Audience: "usercontent.example.com", IssuerKeys: []access.IssuerKey{{Kid: "k1", Ed25519: base64.StdEncoding.EncodeToString(issuer.Public().(ed25519.PublicKey))}}}); err != nil {
		t.Fatal(err)
	}
	service := &access.Service{Manager: rig.manager, Store: store, Registry: registry, Log: quietLog()}
	ts := httptest.NewServer(service.Handler())
	t.Cleanup(ts.Close)

	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage})
	if err != nil {
		t.Fatal(err)
	}
	machine := rig.hypervisor.machine(containerName(created.ID))
	machine.mu.Lock()
	machine.connectFunc = func(int) (net.Conn, error) {
		ours, guest := net.Pipe()
		go func() { defer guest.Close(); _, _ = io.Copy(guest, guest) }()
		return ours, nil
	}
	machine.mu.Unlock()

	// The issuer copies the epoch from the run, never from its clock.
	now := time.Now().Unix()
	token, err := accessgrant.Sign(accessgrant.Claims{V: 1, Iss: "op:test", Aud: "usercontent.example.com", Run: created.ID,
		Scp: []string{"tcp:5432"}, Ep: created.Access.Epoch, Iat: now - 1, Exp: now + 600, Jti: "j1"}, "k1", issuer)
	if err != nil {
		t.Fatal(err)
	}
	connect := func() (*http.Response, *io.PipeWriter) {
		reader, writer := io.Pipe()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/access/runs/"+created.ID+"/connect?port=5432", reader)
		req.Header.Set(access.HeaderGrant, token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp, writer
	}
	resp, in := connect()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("connect: %d %s", resp.StatusCode, body)
	}
	go func() { _, _ = in.Write([]byte("ping")) }()
	echo := make([]byte, 4)
	if _, err := io.ReadFull(resp.Body, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo %q %v", echo, err)
	}
	if got, _ := rig.manager.Get(created.ID); got.Access.Streams != 1 {
		t.Fatalf("streams on the run: %d", got.Access.Streams)
	}

	// [B1] Revoke in the same second as the grant was minted.
	revoked, err := rig.manager.RevokeAccess(bg, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Access.Epoch <= created.Access.Epoch {
		t.Fatalf("revoke left the epoch at %d", revoked.Access.Epoch)
	}
	ended := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, resp.Body); close(ended) }()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("the revoke did not close the open stream within a second")
	}
	// Over HTTP/1.1 a refused stream's body must end for the answer to
	// come (the server drains it first): an empty one here.
	refusedReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/access/runs/"+created.ID+"/connect?port=5432", strings.NewReader(""))
	refusedReq.Header.Set(access.HeaderGrant, token)
	again, err := http.DefaultClient.Do(refusedReq)
	if err != nil {
		t.Fatal(err)
	}
	var problem struct{ Type string }
	_ = json.NewDecoder(again.Body).Decode(&problem)
	again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized || !strings.HasSuffix(problem.Type, "/revoked") {
		t.Fatalf("the pre-revoke grant after the revoke: %d %s", again.StatusCode, problem.Type)
	}

	// A fresh grant works; a stop closes it.
	token, _ = accessgrant.Sign(accessgrant.Claims{V: 1, Iss: "op:test", Aud: "usercontent.example.com", Run: created.ID,
		Scp: []string{"tcp:5432"}, Ep: revoked.Access.Epoch, Iat: now - 1, Exp: now + 600, Jti: "j2"}, "k1", issuer)
	resp, in = connect()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect with a fresh grant: %d", resp.StatusCode)
	}
	defer in.Close()
	if _, err := rig.manager.Stop(bg, created.ID); err != nil {
		t.Fatal(err)
	}
	ended = make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, resp.Body); close(ended) }()
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("a stop left the stream open")
	}
	waitUntil := time.Now().Add(5 * time.Second)
	for registry.Count() != 0 && time.Now().Before(waitUntil) {
		time.Sleep(10 * time.Millisecond)
	}
	got, _ := rig.manager.Get(created.ID)
	if registry.Count() != 0 || *got.Usage.AccessRxBytes != 4 || *got.Usage.AccessTxBytes != 4 {
		t.Fatalf("after the stop: %d streams, usage %+v", registry.Count(), got.Usage)
	}
}
