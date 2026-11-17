package vm

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestJailSpecRefusesRootAndPathsThatAreNotItsOwn(t *testing.T) {
	good := jailFor("/run/sbx/abc/vm.jail", 70000, []uint32{993}, "/opt/ch", "/boot/Image", "/dev/sbx/abc/vm", "/run/sbx/abc/vm", nil)
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*jailSpec){
		"uid 0":             func(s *jailSpec) { s.UID = 0 },
		"gid 0":             func(s *jailSpec) { s.GID = 0 },
		"group root":        func(s *jailSpec) { s.Groups = []uint32{993, 0} },
		"no root directory": func(s *jailSpec) { s.Root = "" },
		"the host's root":   func(s *jailSpec) { s.Root = "/" },
		"a relative path":   func(s *jailSpec) { s.Paths[0].Path = "opt/ch" },
		"a path with ..":    func(s *jailSpec) { s.Paths[0].Path = "/opt/../etc/shadow" },
		"the whole tree":    func(s *jailSpec) { s.Paths[0].Path = "/" },
		"an unknown kind":   func(s *jailSpec) { s.Paths[0].Kind = "everything" },
		"a link to nowhere": func(s *jailSpec) { s.Paths[0] = jailPath{Path: "/lib", Kind: jailSymlink} },
	} {
		spec := good
		spec.Paths = append([]jailPath(nil), good.Paths...)
		change(&spec)
		if spec.validate() == nil {
			t.Errorf("%s was accepted", name)
		}
		if _, err := jailArgs(spec, "/opt/ch", nil); err == nil {
			t.Errorf("%s: a command line was made for it", name)
		}
	}
}

// The helper's command line carries the hypervisor's own, unchanged: the
// sweep recognises a VM by it whether or not the helper has become the
// hypervisor yet.
func TestJailArgsKeepTheHypervisorsCommandLine(t *testing.T) {
	spec := jailFor("/run/sbx/abc/vm.jail", 70000, []uint32{993}, "/opt/ch", "/boot/Image", "/dev/sbx/abc/vm", "/run/sbx/abc/vm", nil)
	args, err := jailArgs(spec, "/opt/ch", []string{"--api-socket", "/run/sbx/abc/vm/api.sock", "--landlock"})
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != jailArg0 || !reflect.DeepEqual(args[2:], []string{"/opt/ch", "--api-socket", "/run/sbx/abc/vm/api.sock", "--landlock"}) {
		t.Fatalf("args: %q", args)
	}
	var decoded jailSpec
	if err := json.Unmarshal([]byte(args[1]), &decoded); err != nil || !reflect.DeepEqual(decoded, spec) {
		t.Fatalf("the helper would read %+v (%v), want %+v", decoded, err, spec)
	}
	h := &CloudHypervisor{RunDir: "/run/sbx/abc"}
	if !h.owns(Process{PID: 1, Args: args}) {
		t.Fatal("a jail helper that has not become its hypervisor yet is not recognised as a VM of this daemon")
	}
}

// What the jail holds is exactly what a VM needs, each as tightly as it
// can be mounted.
func TestJailForHoldsOnlyWhatAVMNeeds(t *testing.T) {
	spec := jailFor("/run/sbx/abc/vm.jail", 70000, nil, "/opt/ch", "/boot/Image", "/dev/sbx/abc/vm", "/run/sbx/abc/vm", nil)
	var writable, executable, devices []string
	for _, each := range spec.Paths {
		if each.Write {
			writable = append(writable, each.Path)
		}
		if each.Exec {
			executable = append(executable, each.Path)
		}
		if each.Kind == jailDevice {
			devices = append(devices, each.Path)
		}
		for _, never := range []string{"/proc", "/sys", "/run/dbus", "/dev/net", "/etc", "/tmp"} {
			if each.Path == never || strings.HasPrefix(each.Path, never+"/") {
				t.Errorf("the jail holds %s", each.Path)
			}
		}
	}
	if !reflect.DeepEqual(writable, []string{"/run/sbx/abc/vm"}) || !reflect.DeepEqual(executable, []string{"/opt/ch"}) ||
		!reflect.DeepEqual(devices, []string{"/dev/sbx/abc/vm", "/dev/kvm", "/dev/urandom"}) {
		t.Fatalf("writable %v, executable %v, devices %v", writable, executable, devices)
	}
}

func TestHypervisorLibrariesAreNoneForAStaticBinary(t *testing.T) {
	if _, err := hypervisorLibraries(os.DevNull); err == nil {
		t.Fatal("something that is not a program was accepted as a hypervisor")
	}
	self, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	paths, err := hypervisorLibraries(self)
	if err != nil {
		// Not an ELF file: this is not Linux.
		t.Skip(err)
	}
	for _, each := range paths {
		if each.Write || (each.Kind != jailDir && each.Kind != jailSymlink && each.Kind != jailFile) {
			t.Errorf("a library path that is writable or of an odd kind: %+v", each)
		}
	}
}
