package vm

import (
	"net"
	"os"
	"testing"
)

func TestSocketOwnerIsWhoListens(t *testing.T) {
	dir, err := os.MkdirTemp("", "sbx")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	listener, err := net.Listen("unix", dir+"/s")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("unix", dir+"/s")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := socketOwner(conn)
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("owner %d, this process is %d", uid, os.Getuid())
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := socketOwner(client); err == nil {
		t.Fatal("something that is not a unix socket has an owner")
	}
}
