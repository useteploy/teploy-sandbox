package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/useteploy/teploy-sandbox/internal/run"
)

var _ run.UsageSampler = (*Driver)(nil)

// cgroupLocator is a hypervisor whose VMs each have a cgroup of their own.
type cgroupLocator interface {
	CgroupDir(name string) string
}

// CgroupDir is the cgroup the named VM's hypervisor runs in: its vCPU
// threads and the hypervisor's own.
func (h *CloudHypervisor) CgroupDir(name string) string {
	if h.confine == nil || h.confine.cgroups == nil {
		return ""
	}
	return h.confine.cgroups.path(name)
}

// netCounter is a network that can count a VM's traffic.
type netCounter interface {
	Counters(ctx context.Context, name string) (rx, tx int64, err error)
}

// errNoDevice: the VM has no network device to count (network "none").
var errNoDevice = errors.New("no network device")

// Counters is what the VM of the named place has received and sent, from
// its tap's counters in the place's namespace. The tap's receive side is
// what the guest sent, so the two swap: rx here is the tap's transmit.
// The tap is the VM's only device; an open run's uplink carries the same
// traffic again and is not added.
func (n *hostNetwork) Counters(ctx context.Context, name string) (rx, tx int64, err error) {
	n.mu.Lock()
	a := n.attached[name]
	if a == nil || !a.attached || a.gone {
		n.mu.Unlock()
		return 0, 0, errNoDevice
	}
	ns, tap := a.ns, a.tap
	n.mu.Unlock()
	out, err := n.sys.run(ctx, ns, "ip", "-j", "-s", "link", "show", "dev", tap)
	if err != nil {
		return 0, 0, err
	}
	return parseLinkStats(out)
}

// parseLinkStats reads `ip -j -s link show` for one device and returns it
// from the guest's side: (received, sent) = (tap tx, tap rx).
func parseLinkStats(out []byte) (rx, tx int64, err error) {
	var links []struct {
		Stats64 *struct {
			RX struct {
				Bytes int64 `json:"bytes"`
			} `json:"rx"`
			TX struct {
				Bytes int64 `json:"bytes"`
			} `json:"tx"`
		} `json:"stats64"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return 0, 0, fmt.Errorf("ip link: %w", err)
	}
	if len(links) != 1 || links[0].Stats64 == nil {
		return 0, 0, fmt.Errorf("ip link: no counters in %q", out)
	}
	return links[0].Stats64.TX.Bytes, links[0].Stats64.RX.Bytes, nil
}

// SampleUsage reads a run's VM: CPU time from its cgroup's cpu.stat,
// network bytes from its tap, and its volume's ZFS `used` (the bytes the
// clone holds of its own, beyond what it shares with the image it was
// cloned from). A part that cannot be read is left out.
func (d *Driver) SampleUsage(ctx context.Context, containerID string) (run.UsageSample, error) {
	current, err := d.instance(containerID)
	if err != nil {
		return run.UsageSample{}, err
	}
	var sample run.UsageSample
	if locator, ok := d.hypervisor.(cgroupLocator); ok {
		if dir := locator.CgroupDir(containerID); dir != "" {
			if stat, err := os.ReadFile(filepath.Join(dir, "cpu.stat")); err == nil {
				if usec, err := run.ParseCPUStat(stat); err == nil {
					sample.CPUUsec = &usec
				}
			}
		}
	}
	if counter, ok := d.network.(netCounter); ok {
		if rx, tx, err := counter.Counters(ctx, current.network); err == nil {
			sample.RxBytes, sample.TxBytes = &rx, &tx
		}
	}
	if used, err := d.volumes.zfs.Property(ctx, d.volumes.runVolume(containerID), "used"); err == nil {
		if bytes, err := strconv.ParseInt(used, 10, 64); err == nil && bytes >= 0 {
			sample.DiskBytes = &bytes
		}
	}
	return sample, nil
}
