package access

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The unix socket admits only the configured peer uid/gid (SO_PEERCRED),
// is 0660, and speaks h2c.
func TestUnixSocketChecksPeerCredentials(t *testing.T) {
	for _, tc := range []struct {
		name  string
		peers UnixPeers
		ok    bool
	}{
		{"own uid", UnixPeers{UID: os.Getuid(), GID: -1}, true},
		{"own gid", UnixPeers{UID: -1, GID: os.Getgid()}, true},
		{"nobody", UnixPeers{UID: -1, GID: -1}, false},
		{"another uid", UnixPeers{UID: os.Getuid() + 12345, GID: -1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "acc")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "access.sock")
			store, _ := OpenStore("", "")
			registry := NewRegistry(Limits{Total: 10}, nil, quiet())
			manager := newFakeManager()
			listener, tlsOn, err := Listen(ListenSpec{Addr: "unix:" + path, Unix: tc.peers, UnixGroup: -1}, store, 4, quiet())
			if err != nil {
				t.Fatal(err)
			}
			if tlsOn {
				t.Fatal("a unix socket with TLS")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o660 {
				t.Fatalf("socket mode: %v %v", info, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = (&Service{Manager: manager, Store: store, Registry: registry, Log: quiet()}).Serve(ctx, listener, true)
			}()
			defer func() { cancel(); <-done }()
			var protocols http.Protocols
			protocols.SetUnencryptedHTTP2(true)
			client := &http.Client{Transport: &http.Transport{
				Protocols: &protocols,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			}}
			resp, err := client.Get("http://access/v1/access/runs/" + runA)
			if !tc.ok {
				if err == nil {
					resp.Body.Close()
					t.Fatalf("a peer that may not use the socket got %d", resp.StatusCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.ProtoMajor != 2 || !strings.Contains(string(body), `"epoch":100`) {
				t.Fatalf("HTTP/%d %s", resp.ProtoMajor, body)
			}
		})
	}
}
