package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

func TestDriverDiskReportsThePool(t *testing.T) {
	rig := newRig(t, nil)
	rig.zfs.available, rig.zfs.used = 7<<30, 3<<30
	usage, err := rig.driver.Disk(bg)
	if err != nil {
		t.Fatal(err)
	}
	// The pool, not the dataset the volumes are under.
	if rig.zfs.spaceAsked != "tank" || usage.Kind != "zfs-pool" || usage.Name != "tank" || usage.FreeBytes != 7<<30 || usage.UsedBytes != 3<<30 {
		t.Fatalf("asked %q, usage %+v", rig.zfs.spaceAsked, usage)
	}
	if got := rig.manager.Disk(bg); got == nil || *got != *usage {
		t.Fatalf("manager: %+v", got)
	}
}

// cgroupHypervisor gives every fake VM a cgroup directory.
type cgroupHypervisor struct {
	*fakeHypervisor
	dir string
}

func (h cgroupHypervisor) CgroupDir(name string) string { return filepath.Join(h.dir, name) }

// countingNetwork counts traffic for every attached VM.
type countingNetwork struct {
	*fakeNetwork
	rx, tx int64
}

func (n *countingNetwork) Counters(_ context.Context, name string) (int64, int64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.attached[name] == nil {
		return 0, 0, errNoDevice
	}
	return n.rx, n.tx, nil
}

func TestDriverSampleUsage(t *testing.T) {
	rig := newRig(t, nil)
	cgroups := t.TempDir()
	rig.driver.hypervisor = cgroupHypervisor{fakeHypervisor: rig.hypervisor, dir: cgroups}
	network := &countingNetwork{fakeNetwork: newFakeNetwork(t), rx: 1500, tx: 300}
	rig.driver.network = network
	rig.manager.UsageInterval = time.Minute
	rig.manager.Egress = &fakeEgress{}

	created, err := rig.manager.Create(bg, run.CreateRequest{Image: GoldenImage, Network: run.NetworkOpen, Limits: &run.Limits{MemoryMB: 512}})
	if err != nil {
		t.Fatal(err)
	}
	name := containerName(created.ID)
	if err := os.MkdirAll(filepath.Join(cgroups, name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroups, name, "cpu.stat"), []byte("usage_usec 2500000\nuser_usec 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rig.zfs.mu.Lock()
	rig.zfs.datasets[rig.volume(created.ID)].props["used"] = "65536"
	rig.zfs.mu.Unlock()

	sample, err := rig.driver.SampleUsage(bg, name, true)
	if err != nil {
		t.Fatal(err)
	}
	if sample.CPUUsec == nil || *sample.CPUUsec != 2500000 || sample.RxBytes == nil || *sample.RxBytes != 1500 ||
		sample.TxBytes == nil || *sample.TxBytes != 300 || sample.DiskBytes == nil || *sample.DiskBytes != 65536 {
		t.Fatalf("sample: %+v", sample)
	}
	rig.manager.SampleUsage(bg)
	got, _ := rig.manager.Get(created.ID)
	if got.Usage.CPUSeconds == nil || *got.Usage.CPUSeconds != 2.5 || *got.Usage.RxBytes != 1500 || *got.Usage.DiskBytes != 65536 {
		t.Fatalf("usage: %+v", got.Usage)
	}
	if _, err := rig.driver.SampleUsage(bg, "teploy-sbx-nothing", true); err == nil {
		t.Fatal("a VM that does not exist was sampled")
	}
}

// What a VM has used of its network is read from its tap, in its
// namespace, from the guest's side.
func TestHostNetworkCountersAreTheGuests(t *testing.T) {
	var asked []string
	sys := netSys{run: func(_ context.Context, ns, name string, args ...string) ([]byte, error) {
		asked = append(asked, ns+" "+name+" "+strings.Join(args, " "))
		return []byte(`[{"ifindex":3,"ifname":"tsbx1","stats64":{"rx":{"bytes":700,"packets":5},"tx":{"bytes":9000,"packets":8}}}]`), nil
	}}
	n := newHostNetwork(netPlan{}, sys, quietLog())
	n.attached["vm-a"] = &attachment{name: "vm-a", ns: "nsbx1", tap: "tsbx1", attached: true}
	n.attached["vm-b"] = &attachment{name: "vm-b", ns: "nsbx2", tap: "tsbx2"}
	rx, tx, err := n.Counters(bg, "vm-a")
	if err != nil || rx != 9000 || tx != 700 {
		t.Fatalf("rx %d tx %d err %v", rx, tx, err)
	}
	if len(asked) != 1 || asked[0] != "nsbx1 ip -j -s link show dev tsbx1" {
		t.Fatalf("asked %q", asked)
	}
	for _, name := range []string{"vm-b", "vm-none"} {
		if _, _, err := n.Counters(bg, name); !errors.Is(err, errNoDevice) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, _, err := parseLinkStats([]byte(`[{"ifname":"x"}]`)); err == nil {
		t.Fatal("no counters parsed")
	}
}
