package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
)

// The saved configuration of a memory image (its config.json) is
// written by a hypervisor process the guest may have taken over, and is
// read back by a hypervisor that will run the same guest. So it is
// never trusted and never passed on as it came: the daemon decodes it
// under a strict schema of the fields its own command line produces,
// requires every value to be one the daemon configures, and rewrites
// the paths that belong to the new VM. Anything else refuses the image,
// and the run boots from its disk.
//
// The schema mirrors Cloud Hypervisor v54.1's VmConfig as the daemon's
// command line fills it. The image's host class pins the hypervisor
// version an image restores under, so a newer hypervisor's fields never
// reach here: its images have another class.

// memoryConfigWant is what the image's configuration must say, and the
// paths of the VM being restored that replace the saved ones.
type memoryConfigWant struct {
	cpus     int
	memoryMB int
	cmdline  string
	// savedDisk is the private device node the saved VM had its disk
	// at, which its configuration must name: a configuration that names
	// another path would have the restoring hypervisor open that.
	savedDisk string
	// runtimeRoot is this daemon's directory of VM runtime dirs. The
	// saved vsock socket and the saved Landlock rule must be a VM's,
	// the same one's, under it.
	runtimeRoot string
	// networked: the run has a network device, and the saved
	// configuration must have exactly one, with savedMAC.
	networked bool
	savedMAC  string

	// What the new VM's are:
	disk, vsockSocket, outbox string
}

// chPCI is the flattened PciDeviceCommonConfig of every device.
type chPCI struct {
	ID       *string `json:"id,omitempty"`
	Iommu    string  `json:"iommu,omitempty"`
	Segment  *uint16 `json:"pci_segment,omitempty"`
	DeviceID *uint8  `json:"pci_device_id,omitempty"`
}

// plain requires a device with no IOMMU, no PCI segment but the first
// and no device ID, and the given id ("" for none).
func (p chPCI) plain(wantID string) error {
	haveID := ""
	if p.ID != nil {
		haveID = *p.ID
	}
	if haveID != wantID || p.Iommu != "" || (p.Segment != nil && *p.Segment != 0) || p.DeviceID != nil {
		return fmt.Errorf("a device's place on the PCI bus or its id (%q) is not what this daemon configures", haveID)
	}
	return nil
}

type chCPUFeatures struct {
	AMX bool `json:"amx"`
}

type chCpus struct {
	BootVCPUs      uint32          `json:"boot_vcpus"`
	MaxVCPUs       uint32          `json:"max_vcpus"`
	Topology       json.RawMessage `json:"topology,omitempty"`
	KVMHyperV      bool            `json:"kvm_hyperv"`
	MaxPhysBits    uint8           `json:"max_phys_bits"`
	Affinity       json.RawMessage `json:"affinity,omitempty"`
	Features       chCPUFeatures   `json:"features"`
	Nested         bool            `json:"nested"`
	CoreScheduling string          `json:"core_scheduling"`
	Profile        string          `json:"profile"`
}

type chMemory struct {
	Size           uint64          `json:"size"`
	Mergeable      bool            `json:"mergeable"`
	HotplugMethod  string          `json:"hotplug_method"`
	HotplugSize    *uint64         `json:"hotplug_size,omitempty"`
	HotpluggedSize *uint64         `json:"hotplugged_size,omitempty"`
	Shared         bool            `json:"shared"`
	Hugepages      bool            `json:"hugepages"`
	HugepageSize   *uint64         `json:"hugepage_size,omitempty"`
	Prefault       bool            `json:"prefault"`
	Reserve        *bool           `json:"reserve,omitempty"`
	Zones          json.RawMessage `json:"zones,omitempty"`
	THP            bool            `json:"thp"`
}

type chPayload struct {
	Firmware  *string `json:"firmware,omitempty"`
	Kernel    *string `json:"kernel,omitempty"`
	Cmdline   *string `json:"cmdline,omitempty"`
	Initramfs *string `json:"initramfs,omitempty"`
}

type chDisk struct {
	chPCI
	Path            *string         `json:"path"`
	Readonly        bool            `json:"readonly"`
	Direct          bool            `json:"direct"`
	NumQueues       int             `json:"num_queues"`
	QueueSize       uint16          `json:"queue_size"`
	VhostUser       bool            `json:"vhost_user"`
	VhostSocket     *string         `json:"vhost_socket,omitempty"`
	RateLimitGroup  *string         `json:"rate_limit_group,omitempty"`
	RateLimiter     json.RawMessage `json:"rate_limiter_config,omitempty"`
	DisableIoUring  bool            `json:"disable_io_uring"`
	DisableAIO      bool            `json:"disable_aio"`
	Serial          *string         `json:"serial,omitempty"`
	QueueAffinity   json.RawMessage `json:"queue_affinity,omitempty"`
	BackingFiles    bool            `json:"backing_files"`
	Sparse          bool            `json:"sparse"`
	ImageType       string          `json:"image_type"`
	LockGranularity string          `json:"lock_granularity"`
	GuestBlockSize  *uint32         `json:"guest_block_size,omitempty"`
}

type chNet struct {
	chPCI
	Tap         *string         `json:"tap,omitempty"`
	IP          *string         `json:"ip,omitempty"`
	Mask        *string         `json:"mask,omitempty"`
	MAC         *string         `json:"mac,omitempty"`
	HostMAC     *string         `json:"host_mac,omitempty"`
	MTU         *uint16         `json:"mtu,omitempty"`
	NumQueues   int             `json:"num_queues"`
	QueueSize   uint16          `json:"queue_size"`
	VhostUser   bool            `json:"vhost_user"`
	VhostSocket *string         `json:"vhost_socket,omitempty"`
	VhostMode   string          `json:"vhost_mode"`
	FDs         []int           `json:"fds,omitempty"`
	RateLimiter json.RawMessage `json:"rate_limiter_config,omitempty"`
	OffloadTSO  bool            `json:"offload_tso"`
	OffloadUFO  bool            `json:"offload_ufo"`
	OffloadCSUM bool            `json:"offload_csum"`
}

type chRng struct {
	chPCI
	Src string `json:"src"`
}

type chBalloon struct {
	chPCI
	Size              uint64 `json:"size"`
	DeflateOnOOM      bool   `json:"deflate_on_oom"`
	FreePageReporting bool   `json:"free_page_reporting"`
}

type chSerial struct {
	File   *string `json:"file,omitempty"`
	Mode   string  `json:"mode"`
	Socket *string `json:"socket,omitempty"`
}

type chConsole struct {
	chPCI
	File   *string `json:"file,omitempty"`
	Mode   string  `json:"mode"`
	Socket *string `json:"socket,omitempty"`
}

type chDebugConsole struct {
	File *string `json:"file,omitempty"`
	Mode string  `json:"mode"`
	// IOBase is the port the device would answer on: x86_64 only, where
	// the hypervisor's default configuration names its own default port
	// even with the device off.
	IOBase *uint16 `json:"iobase,omitempty"`
}

type chVsock struct {
	chPCI
	CID    uint32 `json:"cid"`
	Socket string `json:"socket"`
}

type chLandlockRule struct {
	Path   string `json:"path"`
	Access string `json:"access"`
}

// chConfig is VmConfig with everything the daemon's command line can
// produce, and nothing else: decoding refuses a field that is not here.
type chConfig struct {
	Cpus           chCpus           `json:"cpus"`
	Memory         chMemory         `json:"memory"`
	Payload        *chPayload       `json:"payload,omitempty"`
	Disks          []chDisk         `json:"disks,omitempty"`
	Net            []chNet          `json:"net,omitempty"`
	Rng            chRng            `json:"rng"`
	Balloon        *chBalloon       `json:"balloon,omitempty"`
	Serial         chSerial         `json:"serial"`
	Console        chConsole        `json:"console"`
	DebugConsole   *chDebugConsole  `json:"debug_console,omitempty"`
	Vsock          *chVsock         `json:"vsock,omitempty"`
	Pvpanic        bool             `json:"pvpanic,omitempty"`
	Watchdog       bool             `json:"watchdog,omitempty"`
	LandlockEnable bool             `json:"landlock_enable"`
	LandlockRules  []chLandlockRule `json:"landlock_rules,omitempty"`
}

// What the daemon configures, as Cloud Hypervisor v54.1 fills it in from
// the daemon's command line and its vm.add-net.
const (
	chMaxPhysBits    = 46
	chDiskQueues     = 1
	chDiskQueueSize  = 128
	chNetQueues      = 2
	chNetQueueSize   = 256
	chImageRaw       = "Raw"
	chVhostClient    = "Client"
	chCoreScheduling = "Vm"
	chCPUProfileHost = "Host"
	chHotplugAcpi    = "Acpi"
	chConsoleOff     = "Off"
	chConsoleTty     = "Tty"
	// chDebugConsolePort is the hypervisor's default port for its debug
	// console (0xe9), which its configuration names with the console off.
	chDebugConsolePort = 0xe9
	// How the hypervisor can lock a disk image: the choice its command
	// line leaves by default (ByteRange), and the other it offers. The
	// daemon sets neither: they are how the hypervisor keeps other
	// hypervisors off the same image, and mean nothing to the guest.
	chLockByteRange = "ByteRange"
	chLockFull      = "Full"
	// The ids the hypervisor gives the devices this daemon leaves unnamed:
	// a prefix of its own and a counter over the devices it names, in the
	// order it makes them (vmm/src/device_manager.rs, next_device_name).
	// This daemon's command line has it make the disk first and the
	// vsock second.
	chDiskID  = "_disk0"
	chVsockID = "_vsock1"
)

// rewriteMemoryConfig reads an image's config.json and returns the
// configuration the restoring VM is given: the same, with the paths
// that belong to the new VM, Landlock on and its rule the new outbox.
// The saved file is limited to imageConfigMaxBytes before it is parsed.
func rewriteMemoryConfig(raw []byte, want memoryConfigWant) ([]byte, error) {
	if len(raw) > imageConfigMaxBytes {
		return nil, fmt.Errorf("the saved configuration is %d bytes, more than the %d an image's may be", len(raw), imageConfigMaxBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config chConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("the saved configuration is not one this daemon could have written: %w", err)
	}
	// Nothing may follow: not a second document, and not what More would
	// not call one (a closing bracket, which CH's own reader stops at).
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("the saved configuration holds more than one document, or more than a document")
	}
	if err := config.check(want); err != nil {
		return nil, err
	}
	config.Payload.Kernel = ptr(JailKernel)
	config.Disks[0].Path = ptr(want.disk)
	if len(config.Net) == 1 {
		// The saved numbers are the saved hypervisor's, and mean nothing
		// here: the hypervisor replaces them with the descriptors handed
		// over with the restore, for a device whose configuration has
		// them, as many as it says (one).
		config.Net[0].FDs = []int{-1}
	}
	config.Vsock.Socket = want.vsockSocket
	config.LandlockEnable = true
	config.LandlockRules = []chLandlockRule{{Path: want.outbox, Access: "rw"}}
	rewritten, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	return rewritten, nil
}

func (c chConfig) check(want memoryConfigWant) error {
	// The size must be the same, and the memory plain, private and
	// unresizable: what a copy-on-write restore needs, and what KSM is
	// kept out by (mergeable must not be on, or the hypervisor would
	// make the guest's RAM mergeable host-wide).
	cpus, memory := c.Cpus, c.Memory
	switch {
	case cpus.BootVCPUs != uint32(want.cpus) || cpus.MaxVCPUs != uint32(want.cpus):
		return fmt.Errorf("the saved VM had %d vCPUs (max %d) and the run has %d", cpus.BootVCPUs, cpus.MaxVCPUs, want.cpus)
	case cpus.Topology != nil || cpus.Affinity != nil || cpus.KVMHyperV || cpus.MaxPhysBits != chMaxPhysBits || cpus.Features != (chCPUFeatures{}) ||
		cpus.Nested || cpus.CoreScheduling != chCoreScheduling || cpus.Profile != chCPUProfileHost:
		return errors.New("the saved VM's CPUs were configured in a way this daemon does not configure them")
	case memory.Size != uint64(want.memoryMB)<<20:
		return fmt.Errorf("the saved VM had %d MiB of memory and the run has %d", memory.Size>>20, want.memoryMB)
	case memory.Mergeable:
		return errors.New("the saved VM's memory was mergeable (KSM)")
	case memory.Shared || memory.Hugepages || memory.Prefault || memory.Reserve != nil || memory.Zones != nil ||
		memory.HotplugSize != nil || memory.HotpluggedSize != nil || memory.HugepageSize != nil || memory.HotplugMethod != chHotplugAcpi || !memory.THP:
		return errors.New("the saved VM's memory was configured in a way this daemon does not configure it")
	}
	// One disk: the saved VM's own, writable, direct, raw.
	if c.Payload == nil || len(c.Disks) != 1 || c.Balloon == nil || c.Vsock == nil {
		return errors.New("the saved VM does not have exactly the payload, disk, balloon and vsock this daemon gives every VM")
	}
	payload, disk := c.Payload, c.Disks[0]
	if payload.Firmware != nil || payload.Initramfs != nil || payload.Kernel == nil || *payload.Kernel != JailKernel || payload.Cmdline == nil || *payload.Cmdline != want.cmdline {
		return errors.New("the saved VM's payload is not the kernel image and command line this daemon gives every VM")
	}
	if disk.Path == nil || *disk.Path != want.savedDisk || disk.Readonly || !disk.Direct || disk.NumQueues != chDiskQueues || disk.QueueSize != chDiskQueueSize ||
		disk.VhostUser || disk.VhostSocket != nil || disk.RateLimitGroup != nil || disk.RateLimiter != nil || disk.DisableIoUring || disk.DisableAIO ||
		disk.Serial != nil || disk.QueueAffinity != nil || disk.BackingFiles || !disk.Sparse || disk.ImageType != chImageRaw ||
		(disk.LockGranularity != chLockByteRange && disk.LockGranularity != chLockFull) || disk.GuestBlockSize != nil {
		return errors.New("the saved VM's disk is not the raw, direct, writable disk this daemon gives every VM")
	}
	if err := disk.plain(chDiskID); err != nil {
		return err
	}
	// The network device the run's tier gives, no more and no less, and
	// backed by a descriptor: its tap is a file the daemon hands over,
	// never a name the configuration could point anywhere.
	if !want.networked && len(c.Net) != 0 {
		return errors.New("the saved VM has a network device and the run has none")
	}
	if want.networked {
		if len(c.Net) != 1 {
			return fmt.Errorf("the saved VM has %d network devices and the run has one", len(c.Net))
		}
		net := c.Net[0]
		if err := net.plain(netDeviceID); err != nil {
			return err
		}
		if net.MAC == nil || *net.MAC != want.savedMAC || net.Tap != nil || net.IP != nil || net.Mask != nil || net.HostMAC != nil || net.MTU != nil ||
			net.NumQueues != chNetQueues || net.QueueSize != chNetQueueSize || net.VhostUser || net.VhostSocket != nil || net.VhostMode != chVhostClient ||
			len(net.FDs) == 0 || net.RateLimiter != nil || net.OffloadTSO || net.OffloadUFO || net.OffloadCSUM {
			return errors.New("the saved VM's network device is not the one this daemon gives a run (a MAC and a handed-over descriptor)")
		}
	}
	// The hypervisor reaches only paths that are the new VM's or the
	// jail's: the saved vsock socket and Landlock rule must be those of
	// a VM of this daemon's, one VM, and are replaced below.
	if c.Rng.Src != rngDevice || c.Balloon.Size != 0 || !c.Balloon.DeflateOnOOM || !c.Balloon.FreePageReporting {
		return errors.New("the saved VM's random device or balloon is not what this daemon configures")
	}
	if err := c.Rng.plain(""); err != nil {
		return err
	}
	if err := c.Balloon.plain(""); err != nil {
		return err
	}
	if c.Serial.Mode != chConsoleTty || c.Serial.File != nil || c.Serial.Socket != nil || c.Console.Mode != chConsoleOff || c.Console.File != nil || c.Console.Socket != nil {
		return errors.New("the saved VM's consoles are not what this daemon configures (output to the hypervisor's own, and no virtio console)")
	}
	if err := c.Console.plain(""); err != nil {
		return err
	}
	// The debug console is x86_64's: there the hypervisor's configuration
	// has it, off and on its default port. Any other debug console is a
	// device the daemon gives no VM, and one that would be made before
	// the hypervisor's sandbox is applied to it.
	if c.DebugConsole != nil && (c.DebugConsole.Mode != chConsoleOff || c.DebugConsole.File != nil ||
		(c.DebugConsole.IOBase != nil && *c.DebugConsole.IOBase != chDebugConsolePort)) {
		return errors.New("the saved VM has a debug console, and this daemon gives every VM none")
	}
	if c.Pvpanic || c.Watchdog || !c.LandlockEnable || len(c.LandlockRules) != 1 || c.LandlockRules[0].Access != "rw" {
		return errors.New("the saved VM's hypervisor was not run with the sandbox this daemon gives every hypervisor")
	}
	if err := savedVMDir(c.Vsock.Socket, c.LandlockRules[0].Path, want.runtimeRoot); err != nil {
		return err
	}
	return c.Vsock.plain(chVsockID)
}

// savedVMDir checks that the saved vsock socket and the saved Landlock
// rule are those of one VM of this daemon's runtime directory: the
// restoring hypervisor would otherwise be pointed at a socket, or given
// a rule, that is anything's.
func savedVMDir(vsockSocket, landlockPath, runtimeRoot string) error {
	if !filepath.IsAbs(vsockSocket) || filepath.Clean(vsockSocket) != vsockSocket || filepath.Base(vsockSocket) != vsockSocketName {
		return fmt.Errorf("the saved VM's vsock socket %q is not a VM's", vsockSocket)
	}
	dir := filepath.Dir(vsockSocket)
	if filepath.Dir(dir) != filepath.Clean(runtimeRoot) || !runNameShape.MatchString(filepath.Base(dir)) {
		return fmt.Errorf("the saved VM's vsock socket %q is not under this daemon's runtime directory", vsockSocket)
	}
	if landlockPath != filepath.Join(dir, outboxName) {
		return fmt.Errorf("the saved VM's Landlock rule names %q, not its own outbox", landlockPath)
	}
	return nil
}

func ptr[T any](value T) *T { return &value }
