package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestCapacityReportsTheDriverAndNestedVirt(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name       string
		srv        Server
		driver     string
		runtime    string
		nestedVirt bool
	}{
		{name: "unset is docker, as before", srv: Server{}, driver: "docker", runtime: "default"},
		{name: "docker", srv: Server{Driver: "docker", Runtime: "runsc"}, driver: "docker", runtime: "runsc"},
		{name: "vm", srv: Server{Driver: "vm", Runtime: "cloud-hypervisor"}, driver: "vm", runtime: "cloud-hypervisor"},
		{name: "nested", srv: Server{Driver: "vm", Runtime: "cloud-hypervisor", NestedVirt: true}, driver: "vm", runtime: "cloud-hypervisor", nestedVirt: true},
	} {
		srv := tc.srv
		srv.Manager = run.NewManager(newFakeRuntime(), quiet)
		srv.Token, srv.Log, srv.ServerName = "test-token", quiet, "box"
		ts := httptest.NewServer(srv.Handler())
		body := call(t, ts, "GET", "/v1/capacity", "", http.StatusOK)
		ts.Close()
		if body["driver"] != tc.driver || body["runtime"] != tc.runtime {
			t.Errorf("%s: driver=%v runtime=%v", tc.name, body["driver"], body["runtime"])
		}
		// Always present, so a scheduler never has to guess what absence means.
		if nested, ok := body["nestedVirt"].(bool); !ok || nested != tc.nestedVirt {
			t.Errorf("%s: nestedVirt=%v", tc.name, body["nestedVirt"])
		}
	}
}
