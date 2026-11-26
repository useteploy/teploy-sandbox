package vm

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The saved configuration of a memory image, as Cloud Hypervisor v54.1
// writes it for a VM started with this daemon's command line and given
// its network device with vm.add-net, on x86_64. The field set and the
// defaults are the hypervisor's own (vmm/src/vm_config.rs): the debug
// console, off and on its default port; the disk's lock granularity, the
// command line's default; a console's optional fields as nulls; and
// nothing at all for what is not configured.
const (
	savedVM = "teploy-sbx-01arz3ndektsv4rrffq69g5fav"
	newVM   = "teploy-sbx-01arz3ndektsv4rrffq69g5faw"
	otherVM = "teploy-sbx-01arz3ndektsv4rrffq69g5fax"

	savedMAC = "52:9a:0e:12:34:56"

	savedDevDir = "/dev/teploy-sandbox/0123456789abcdef0123456789abcdef"
	savedRunDir = "/run/sbx/abc"
	savedDisk   = savedDevDir + "/" + savedVM
	savedDir    = savedRunDir + "/" + savedVM

	savedCmdline = "root=/dev/vda1 rw console=ttyS0 quiet"
)

// savedConfigJSON is what the hypervisor wrote into the image.
const savedConfigJSON = `{
  "cpus": {"boot_vcpus": 1, "max_vcpus": 1, "kvm_hyperv": false, "max_phys_bits": 46, "features": {"amx": false}, "nested": false, "core_scheduling": "Vm", "profile": "Host"},
  "memory": {"size": 536870912, "mergeable": false, "hotplug_method": "Acpi", "shared": false, "hugepages": false, "prefault": false, "thp": true},
  "payload": {"kernel": "/kernel", "cmdline": "` + savedCmdline + `"},
  "disks": [{"pci_segment": 0, "path": "` + savedDisk + `", "readonly": false, "direct": true, "num_queues": 1, "queue_size": 128, "vhost_user": false, "disable_io_uring": false, "disable_aio": false, "backing_files": false, "sparse": true, "image_type": "Raw", "lock_granularity": "ByteRange"}],
  "net": [{"id": "net0", "pci_segment": 0, "mac": "` + savedMAC + `", "num_queues": 2, "queue_size": 256, "vhost_user": false, "vhost_mode": "Client", "fds": [17], "offload_tso": false, "offload_ufo": false, "offload_csum": false}],
  "rng": {"pci_segment": 0, "src": "/dev/urandom"},
  "balloon": {"pci_segment": 0, "size": 0, "deflate_on_oom": true, "free_page_reporting": true},
  "serial": {"file": null, "mode": "Tty", "socket": null},
  "console": {"file": null, "mode": "Off", "socket": null, "pci_segment": 0},
  "debug_console": {"mode": "Off", "iobase": 233},
  "vsock": {"pci_segment": 0, "cid": 4, "socket": "` + savedDir + `/vsock.sock"},
  "pvpanic": false,
  "watchdog": false,
  "landlock_enable": true,
  "landlock_rules": [{"path": "` + savedDir + `/outbox", "access": "rw"}]
}`

func savedWant() memoryConfigWant {
	return memoryConfigWant{
		cpus: 1, memoryMB: 512, cmdline: savedCmdline,
		savedDisk: savedDisk, runtimeRoot: savedRunDir,
		networked: true, savedMAC: savedMAC,
		disk:        savedDevDir + "/" + newVM,
		vsockSocket: savedRunDir + "/" + newVM + "/vsock.sock",
		outbox:      savedRunDir + "/" + newVM + "/" + outboxName,
	}
}

// savedDocument is the saved configuration to change: a fresh copy each
// time, decoded, with the lists of devices made anew.
func savedDocument() map[string]any {
	var document map[string]any
	if err := json.Unmarshal([]byte(savedConfigJSON), &document); err != nil {
		panic(err)
	}
	return document
}

// at follows a path ("net.0.mac": a key in an object, an index in a
// list) to the container that holds its last part.
func at(document map[string]any, path string) map[string]any {
	parts := strings.Split(path, ".")
	var container any = document
	for _, part := range parts[:len(parts)-1] {
		if list, ok := container.([]any); ok {
			i, _ := strconv.Atoi(part)
			container = list[i]
		} else {
			container = container.(map[string]any)[part]
		}
	}
	return container.(map[string]any)
}

func lastOf(path string) string {
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
}

// set returns a change that sets the value at path, replacing a list of
// devices whole where the path names one.
func set(path string, value any) func(map[string]any) {
	return func(d map[string]any) { at(d, path)[lastOf(path)] = value }
}

func del(path string) func(map[string]any) {
	return func(d map[string]any) { delete(at(d, path), lastOf(path)) }
}

func encoded(t *testing.T, document map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestASavedConfigurationIsRewrittenForTheVMThatRestoresIt(t *testing.T) {
	want := savedWant()
	rewritten, err := rewriteMemoryConfig([]byte(savedConfigJSON), want)
	if err != nil {
		t.Fatalf("a configuration this daemon's own command line writes was refused: %v", err)
	}
	got, saved := decodeConfig(t, rewritten), decodeConfig(t, []byte(savedConfigJSON))
	// Everything is the saved VM's but the paths that belong to the new
	// one, Landlock, and the network device's descriptors.
	if len(got.Disks) != 1 || got.Disks[0].Path == nil || *got.Disks[0].Path != want.disk {
		t.Errorf("the disks: %+v", got.Disks)
	}
	if got.Vsock == nil || got.Vsock.Socket != want.vsockSocket || got.Vsock.CID != 4 {
		t.Errorf("the vsock: %+v", got.Vsock)
	}
	if !got.LandlockEnable || !reflect.DeepEqual(got.LandlockRules, []chLandlockRule{{Path: want.outbox, Access: "rw"}}) {
		t.Errorf("Landlock: on %t, rules %+v; want the new VM's outbox alone", got.LandlockEnable, got.LandlockRules)
	}
	// The saved descriptor numbers are the saved hypervisor's: the
	// restoring one is given its own with the request, as many as the
	// configuration says (one).
	if len(got.Net) != 1 || !reflect.DeepEqual(got.Net[0].FDs, []int{-1}) || *got.Net[0].MAC != savedMAC || *got.Net[0].ID != netDeviceID {
		t.Errorf("the network device: %+v", got.Net)
	}
	if bytes.Contains(rewritten, []byte(savedVM)) {
		t.Errorf("the rewritten configuration still names the saved VM:\n%s", rewritten)
	}
	// Everything else is as it was saved.
	saved.Disks[0].Path, saved.Vsock.Socket = ptr(want.disk), want.vsockSocket
	saved.Payload.Kernel, saved.Net[0].FDs = ptr(JailKernel), []int{-1}
	saved.LandlockEnable, saved.LandlockRules = true, []chLandlockRule{{Path: want.outbox, Access: "rw"}}
	if !reflect.DeepEqual(got, saved) {
		t.Errorf("the rewritten configuration differs from the saved one beyond the new VM's paths:\n got %+v\nwant %+v", got, saved)
	}

	// The same file as an arm64 hypervisor writes it: no debug console.
	arm := savedDocument()
	del("debug_console")(arm)
	if _, err := rewriteMemoryConfig(encoded(t, arm), want); err != nil {
		t.Errorf("an arm64 configuration was refused: %v", err)
	}
	// A VM without a network device, for a run without one.
	none := savedDocument()
	del("net")(none)
	noNet := savedWant()
	noNet.networked = false
	if rewritten, err = rewriteMemoryConfig(encoded(t, none), noNet); err != nil {
		t.Fatalf("a configuration with no network device was refused: %v", err)
	}
	if got := decodeConfig(t, rewritten); got.Net != nil {
		t.Errorf("a network device appeared: %+v", got.Net)
	}
}

// decodeConfig reads a configuration the way the daemon does.
func decodeConfig(t *testing.T, raw []byte) chConfig {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config chConfig
	must(t, decoder.Decode(&config))
	return config
}

// The configuration is written by a hypervisor the guest may have taken
// over and read by one that will run the same guest. Every value must be
// one this daemon configures, or the image is refused and the run boots
// from its disk. Each case would have the restoring hypervisor open,
// map, create or lock something the daemon did not choose, or run the
// guest with something other than what it was saved with.
func TestASavedConfigurationThatIsNotThisDaemonsRefusesTheImage(t *testing.T) {
	const secret = "/etc/shadow"
	outbox := savedDir + "/" + outboxName
	rule := func(path, access string) []any {
		return []any{map[string]any{"path": path, "access": access}}
	}
	for name, change := range map[string]func(map[string]any){
		// What this daemon's command line can never produce: a device, a
		// console or a feature it gives no VM, and whatever else a file
		// of another shape holds.
		"a passthrough device":            set("devices", []any{map[string]any{"path": "/dev/sg0"}}),
		"a user device":                   set("user_devices", []any{}),
		"a vDPA device":                   set("vdpa", []any{}),
		"a virtio-fs device":              set("fs", []any{}),
		"a persistent memory device":      set("pmem", []any{}),
		"a vhost-user device":             set("generic_vhost_user", []any{}),
		"a rate limit group":              set("rate_limit_groups", []any{}),
		"a NUMA layout":                   set("numa", []any{}),
		"PCI segments":                    set("pci_segments", []any{}),
		"a platform configuration":        set("platform", map[string]any{"num_pci_segments": float64(1)}),
		"a TPM":                           set("tpm", map[string]any{"socket": "/run/x"}),
		"a pvmemcontrol device":           set("pvmemcontrol", map[string]any{"socket": "/run/x"}),
		"an ivshmem device":               set("ivshmem", map[string]any{"path": "/dev/shm/x"}),
		"a debug serial port":             set("gdb", true),
		"an RTC":                          set("rtc", map[string]any{"pci_segment": float64(0)}),
		"a field nothing knows":           set("anything", float64(1)),
		"the hypervisor's own IOMMU flag": set("iommu", true),
		"the kernel command line":         set("payload.cmdline", "init=/bin/sh"),
		"another kernel":                  set("payload.kernel", secret),
		"the host's path of the kernel":   set("payload.kernel", "/var/lib/teploy-sandbox/vm/Image"),
		"firmware":                        set("payload.firmware", "/OVMF.fd"),
		"an initramfs":                    set("payload.initramfs", "/initrd.img"),
		"firmware configuration":          set("payload.fw_cfg_config", map[string]any{"kernel": true}),
		"an IGVM file":                    set("payload.igvm", "/x.igvm"),
		"payload host data":               set("payload.host_data", "x"),
		"no payload":                      del("payload"),
		"no kernel":                       del("payload.kernel"),
		"no command line":                 del("payload.cmdline"),
		// The disk: the saved VM's own, by the node the daemon made for it.
		"the saved disk is another VM's":        set("disks.0.path", savedDevDir+"/"+otherVM),
		"the saved disk is a host file":         set("disks.0.path", secret),
		"the saved disk is the zvol's own node": set("disks.0.path", "/dev/zvol/tank/sbx/"+savedVM),
		"a read-only disk":                      set("disks.0.readonly", true),
		"a disk through the page cache":         set("disks.0.direct", false),
		"another disk queue count":              set("disks.0.num_queues", float64(2)),
		"another disk queue size":               set("disks.0.queue_size", float64(256)),
		"a vhost-user disk":                     set("disks.0.vhost_user", true),
		"a vhost-user socket":                   set("disks.0.vhost_socket", "/run/x.sock"),
		"a disk rate limit group":               set("disks.0.rate_limit_group", "g"),
		"a disk rate limiter":                   set("disks.0.rate_limiter_config", map[string]any{"bw_size": float64(1000)}),
		"io_uring disabled":                     set("disks.0.disable_io_uring", true),
		"aio disabled":                          set("disks.0.disable_aio", true),
		"a disk serial number":                  set("disks.0.serial", "x"),
		"disk queue affinity":                   set("disks.0.queue_affinity", []any{}),
		"backing files":                         set("disks.0.backing_files", true),
		"a disk without holes":                  set("disks.0.sparse", false),
		"a qcow2 disk":                          set("disks.0.image_type", "Qcow2"),
		"a disk of unknown format":              set("disks.0.image_type", "Unknown"),
		"an unknown lock granularity":           set("disks.0.lock_granularity", "none"),
		"a guest block size":                    set("disks.0.guest_block_size", float64(4096)),
		"a disk id":                             set("disks.0.id", "disk0"),
		"a disk on another PCI segment":         set("disks.0.pci_segment", float64(1)),
		"a disk at a PCI slot":                  set("disks.0.pci_device_id", float64(5)),
		"an IOMMU for the disk":                 set("disks.0.iommu", "Virtio"),
		"the disk lock left default":            del("disks.0.lock_granularity"),
		"no disk":                               del("disks"),
		"no disk path":                          del("disks.0.path"),
		"two disks":                             func(d map[string]any) { d["disks"] = []any{d["disks"].([]any)[0], d["disks"].([]any)[0]} },
		// The network device: the one the run's tier gave, found again by
		// its recorded MAC, and backed by a descriptor the daemon hands
		// over, never by a name.
		"another network device":                   set("net.0.mac", "00:11:22:33:44:55"),
		"a tap by name":                            set("net.0.tap", "tap0"),
		"an address":                               set("net.0.ip", "10.0.0.1"),
		"a netmask":                                set("net.0.mask", "255.255.255.0"),
		"a host MAC":                               set("net.0.host_mac", "00:11:22:33:44:55"),
		"an MTU":                                   set("net.0.mtu", float64(1400)),
		"another net queue count":                  set("net.0.num_queues", float64(1)),
		"another net queue size":                   set("net.0.queue_size", float64(128)),
		"a vhost-user net device":                  set("net.0.vhost_user", true),
		"a vhost-user net socket":                  set("net.0.vhost_socket", "/run/x.sock"),
		"a vhost server":                           set("net.0.vhost_mode", "Server"),
		"a net device with no descriptor":          set("net.0.fds", nil),
		"an empty descriptor list":                 set("net.0.fds", []any{}),
		"a net rate limiter":                       set("net.0.rate_limiter_config", map[string]any{"bw_size": float64(1000)}),
		"TSO offload":                              set("net.0.offload_tso", true),
		"UFO offload":                              set("net.0.offload_ufo", true),
		"checksum offload":                         set("net.0.offload_csum", true),
		"another net id":                           set("net.0.id", "net1"),
		"a net device on another PCI segment":      set("net.0.pci_segment", float64(1)),
		"a net device at a PCI slot":               set("net.0.pci_device_id", float64(5)),
		"an IOMMU for the net device":              set("net.0.iommu", "Virtio"),
		"no MAC on the network device":             del("net.0.mac"),
		"no id on the network device":              del("net.0.id"),
		"no descriptors for the network device":    del("net.0.fds"),
		"no network queues":                        del("net.0.num_queues"),
		"two network devices":                      func(d map[string]any) { d["net"] = []any{d["net"].([]any)[0], d["net"].([]any)[0]} },
		"no network device for a run that has one": del("net"),
		// Devices and consoles the daemon gives no VM, or not this way.
		"another random device": set("rng.src", "/dev/hwrng"),
		"an rng id":             set("rng.id", "rng0"),
		"a balloon with size":   set("balloon.size", float64(1048576)),
		"a balloon that keeps memory when out of it": set("balloon.deflate_on_oom", false),
		"a balloon that hoards free pages":           set("balloon.free_page_reporting", false),
		"no balloon":                                 del("balloon"),
		"a serial console to a file":                 set("serial.file", secret),
		"a serial console to a socket":               set("serial.socket", "/run/x.sock"),
		"a serial console that is off":               set("serial.mode", "Off"),
		"a serial console on a pty":                  set("serial.mode", "Pty"),
		"a virtio console":                           set("console.mode", "Tty"),
		"a virtio console to a file":                 set("console.file", secret),
		"a virtio console to a socket":               set("console.socket", "/run/x.sock"),
		"a debug console on a pty":                   set("debug_console.mode", "Pty"),
		"a debug console to a file":                  set("debug_console.file", secret),
		"a debug console to the kernel":              set("debug_console", map[string]any{"mode": "File", "file": "/proc/sysrq-trigger"}),
		"a debug console on another port":            set("debug_console.iobase", float64(0x402)),
		"a panic device":                             set("pvpanic", true),
		"a watchdog":                                 set("watchdog", true),
		// The sandbox: on, and a rule for the saved VM's own outbox.
		"Landlock off":                                  set("landlock_enable", false),
		"no Landlock rules":                             set("landlock_rules", []any{}),
		"no Landlock rules at all":                      del("landlock_rules"),
		"two Landlock rules":                            set("landlock_rules", append(rule(outbox, "rw"), map[string]any{"path": "/", "access": "rw"})),
		"a Landlock rule with execute":                  set("landlock_rules", rule(outbox, "rwx")),
		"a Landlock rule that only reads":               set("landlock_rules", rule(outbox, "r")),
		"a Landlock rule for the whole filesystem":      set("landlock_rules", rule("/", "rw")),
		"a Landlock rule for a host file":               set("landlock_rules", rule(secret, "rw")),
		"a Landlock rule for another VM's outbox":       set("landlock_rules", rule(savedRunDir+"/"+otherVM+"/"+outboxName, "rw")),
		"a Landlock rule for the run directory":         set("landlock_rules", rule(savedRunDir, "rw")),
		"a Landlock rule for the saved VM's directory":  set("landlock_rules", rule(savedDir, "rw")),
		"a Landlock rule for the image mount directory": set("landlock_rules", rule("/var/lib/teploy-sandbox/vm-images", "rw")),
		// The vsock: a socket of one VM of this daemon's, the same VM as
		// the rule's.
		"a vsock socket outside the runtime directory":   set("vsock.socket", "/tmp/"+savedVM+"/vsock.sock"),
		"a vsock socket that is relative":                set("vsock.socket", "vsock.sock"),
		"a vsock socket with a path that loops":          set("vsock.socket", savedRunDir+"/x/../"+savedVM+"/vsock.sock"),
		"a vsock socket with a path that doubles":        set("vsock.socket", savedRunDir+"//"+savedVM+"/vsock.sock"),
		"a vsock socket of another shape":                set("vsock.socket", savedDir+"/api.sock"),
		"a vsock socket of a directory that is not a VM": set("vsock.socket", savedRunDir+"/vm/vsock.sock"),
		"a vsock socket deeper than a VM's":              set("vsock.socket", savedDir+"/x/vsock.sock"),
		"a vsock socket in another runtime directory":    set("vsock.socket", savedRunDir+"/x/"+savedVM+"/vsock.sock"),
		"a vsock socket of another VM than the rule's":   set("vsock.socket", savedRunDir+"/"+otherVM+"/vsock.sock"),
		"no vsock":   del("vsock"),
		"a vsock id": set("vsock.id", "vsock0"),
	} {
		t.Run(name, func(t *testing.T) {
			document := savedDocument()
			change(document)
			if rewritten, err := rewriteMemoryConfig(encoded(t, document), savedWant()); err == nil {
				t.Fatalf("the image was accepted:\n%s", rewritten)
			}
		})
	}
	// The values of the size and the vCPUs are in their own objects; the
	// shorthand above does not reach them.
	for name, change := range map[string]func(d map[string]any){
		"another boot vCPU count": func(d map[string]any) { d["cpus"].(map[string]any)["boot_vcpus"] = float64(2) },
		"another max vCPU count":  func(d map[string]any) { d["cpus"].(map[string]any)["max_vcpus"] = float64(2) },
		"a CPU topology": func(d map[string]any) {
			d["cpus"].(map[string]any)["topology"] = map[string]any{"threads_per_core": float64(1), "cores_per_die": float64(1), "dies_per_package": float64(1), "packages": float64(1)}
		},
		"CPU affinity":                   func(d map[string]any) { d["cpus"].(map[string]any)["affinity"] = []any{} },
		"Hyper-V emulation":              func(d map[string]any) { d["cpus"].(map[string]any)["kvm_hyperv"] = true },
		"another physical address width": func(d map[string]any) { d["cpus"].(map[string]any)["max_phys_bits"] = float64(48) },
		"AMX":                            func(d map[string]any) { d["cpus"].(map[string]any)["features"] = map[string]any{"amx": true} },
		"nested virtualization":          func(d map[string]any) { d["cpus"].(map[string]any)["nested"] = true },
		"per-vCPU core scheduling":       func(d map[string]any) { d["cpus"].(map[string]any)["core_scheduling"] = "Vcpu" },
		"core scheduling off":            func(d map[string]any) { d["cpus"].(map[string]any)["core_scheduling"] = "Off" },
		"another memory size":            func(d map[string]any) { d["memory"].(map[string]any)["size"] = float64(268435456) },
		"mergeable memory":               func(d map[string]any) { d["memory"].(map[string]any)["mergeable"] = true },
		"shared memory":                  func(d map[string]any) { d["memory"].(map[string]any)["shared"] = true },
		"hugepages":                      func(d map[string]any) { d["memory"].(map[string]any)["hugepages"] = true },
		"prefaulting":                    func(d map[string]any) { d["memory"].(map[string]any)["prefault"] = true },
		"memory reservation off":         func(d map[string]any) { d["memory"].(map[string]any)["reserve"] = false },
		"memory zones":                   func(d map[string]any) { d["memory"].(map[string]any)["zones"] = []any{} },
		"memory hotplug":                 func(d map[string]any) { d["memory"].(map[string]any)["hotplug_size"] = float64(1073741824) },
		"hotplugged memory":              func(d map[string]any) { d["memory"].(map[string]any)["hotplugged_size"] = float64(1073741824) },
		"a hugepage size":                func(d map[string]any) { d["memory"].(map[string]any)["hugepage_size"] = float64(2097152) },
		"virtio-mem hotplug":             func(d map[string]any) { d["memory"].(map[string]any)["hotplug_method"] = "VirtioMem" },
		"transparent huge pages off":     func(d map[string]any) { d["memory"].(map[string]any)["thp"] = false },
		"mergeable memory zone": func(d map[string]any) {
			d["memory"].(map[string]any)["zones"] = []any{map[string]any{"id": "z", "size": float64(1), "mergeable": true}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			document := savedDocument()
			change(document)
			if rewritten, err := rewriteMemoryConfig(encoded(t, document), savedWant()); err == nil {
				t.Fatalf("the image was accepted:\n%s", rewritten)
			}
		})
	}
}

// What the run asks for is checked against what was saved: an image
// restores only into the VM it was saved from.
func TestASavedConfigurationForAnotherVMThanTheRunsRefusesTheImage(t *testing.T) {
	raw := []byte(savedConfigJSON)
	if _, err := rewriteMemoryConfig(raw, savedWant()); err != nil {
		t.Fatalf("as saved: %v", err)
	}
	for name, change := range map[string]func(w *memoryConfigWant){
		"another vCPU count":           func(w *memoryConfigWant) { w.cpus = 2 },
		"another memory size":          func(w *memoryConfigWant) { w.memoryMB = 1024 },
		"another kernel command line":  func(w *memoryConfigWant) { w.cmdline = savedCmdline + " mitigations=off" },
		"another disk node than saved": func(w *memoryConfigWant) { w.savedDisk = savedDevDir + "/" + newVM },
		"a run with no network device": func(w *memoryConfigWant) { w.networked = false },
		"another recorded MAC":         func(w *memoryConfigWant) { w.savedMAC = "00:11:22:33:44:55" },
		"another runtime root":         func(w *memoryConfigWant) { w.runtimeRoot = "/run/sbx/def" },
	} {
		want := savedWant()
		change(&want)
		if _, err := rewriteMemoryConfig(raw, want); err == nil {
			t.Errorf("%s: the image was accepted", name)
		}
	}
	// And the image of a VM without a network device is not restored for
	// a run that has one.
	none := savedDocument()
	del("net")(none)
	if _, err := rewriteMemoryConfig(encoded(t, none), savedWant()); err == nil {
		t.Error("a VM saved without a network device was restored for a run that has one")
	}
}

// The file is bounded and whole before any of it is read.
func TestASavedConfigurationThatIsNoFileAtAllRefusesTheImage(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":         nil,
		"not JSON":      {0, 1, 'c', 'o', 'n', 'f', 'i', 'g'},
		"not an object": []byte(`[{"cpus":{}}]`),
		"truncated":     []byte(savedConfigJSON[:len(savedConfigJSON)/2]),
		"two documents": append([]byte(savedConfigJSON), savedConfigJSON...),
		"then garbage":  append([]byte(savedConfigJSON), '}'),
		"oversize":      append([]byte(savedConfigJSON), bytes.Repeat([]byte(" "), imageConfigMaxBytes)...),
	} {
		if _, err := rewriteMemoryConfig(raw, savedWant()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (chConfig{}).check(savedWant()); err == nil {
		t.Error("the zero configuration was accepted")
	}
	// What the hypervisor may write besides the shape above, and means
	// nothing to the guest: the other disk lock it offers, and the debug
	// console's port named or not with the console off.
	for name, change := range map[string]func(map[string]any){
		"the whole-file disk lock":   set("disks.0.lock_granularity", "Full"),
		"the debug console unnamed":  del("debug_console"),
		"the debug console unported": del("debug_console.iobase"),
		"the console's nulls left out": func(d map[string]any) {
			for _, field := range []string{"file", "socket"} {
				delete(d["serial"].(map[string]any), field)
				delete(d["console"].(map[string]any), field)
			}
		},
	} {
		document := savedDocument()
		change(document)
		if _, err := rewriteMemoryConfig(encoded(t, document), savedWant()); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var document map[string]any
	must(t, json.Unmarshal(raw, &document))
	return document
}
