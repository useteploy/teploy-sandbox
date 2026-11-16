package vm

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestConfinedProcAttrNeverStartsRootOrOutsideACgroup(t *testing.T) {
	cgroup, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	for name, try := range map[string]func() error{
		"uid 0":     func() error { _, err := confinedProcAttr(0, 70000, nil, cgroup); return err },
		"gid 0":     func() error { _, err := confinedProcAttr(70000, 0, nil, cgroup); return err },
		"no cgroup": func() error { _, err := confinedProcAttr(70000, 70000, nil, nil); return err },
	} {
		if try() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	attr, err := confinedProcAttr(70000, 70001, []uint32{993}, cgroup)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Credential.Uid != 70000 || attr.Credential.Gid != 70001 || len(attr.Credential.Groups) != 1 || attr.Credential.NoSetGroups {
		t.Fatalf("credential: %+v", attr.Credential)
	}
	if !attr.UseCgroupFD || attr.CgroupFD != int(cgroup.Fd()) || !attr.Setsid {
		t.Fatalf("attr: %+v", attr)
	}
	if attr.Cloneflags&syscall.CLONE_NEWNET == 0 || attr.Cloneflags&syscall.CLONE_NEWIPC == 0 {
		t.Fatalf("clone flags %#x: the hypervisor shares the host's network or IPC", attr.Cloneflags)
	}
	if attr.Cloneflags&syscall.CLONE_NEWUSER != 0 {
		// A user namespace would make it root somewhere.
		t.Fatalf("clone flags %#x", attr.Cloneflags)
	}
	if len(attr.AmbientCaps) != 0 {
		t.Fatalf("capabilities kept: %v", attr.AmbientCaps)
	}
}

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
