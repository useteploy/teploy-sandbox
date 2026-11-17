package vm

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Host sizing. Three numbers on the host are shared by every VM and are
// not the driver's to set; a host whose numbers are too small for the runs
// it is to carry fails at the worst moment, one run at a time, in ways
// that look like a guest's own fault. So the daemon says so at start (a
// warning: the numbers belong to the operator, and a host may be meant
// for fewer runs than the flags allow). scripts/install-host.sh reports
// the same arithmetic.
//
//   - the host's connection tracking table (net.netfilter.nf_conntrack_max)
//     holds every connection an open run makes through its link, up to
//     --vm-net-connections per run: runs × connections.
//   - the daemon's open files (RLIMIT_NOFILE): two per connection an
//     allowlist run has open through its proxy (the guest's side and the
//     proxy's own), up to --vm-net-connections per run, and a few per VM
//     (the hypervisor's output pipes, a run's proxy listener):
//     runs × connections × 2 + (runs + pool) × filesPerVM + filesBase.
//   - the kernel's asynchronous I/O contexts (fs.aio-max-nr), one number
//     for the whole host: every VM's disk takes aioPerVM of it, pool VMs
//     included, since the hypervisor uses Linux AIO for the disk (io_uring
//     is refused by the daemon's filter): (runs + pool) × aioPerVM.
//
// runs is --vm-max-runs; with no limit set, only the pool is checked.
const (
	// aioPerVM is what one VM's disk takes of fs.aio-max-nr: the
	// hypervisor's queue for it (measured on Cloud Hypervisor v54.1 with
	// one disk queue: aio-nr rose by 128 per VM).
	aioPerVM = 128
	// filesPerVM and filesBase are the daemon's open files beyond the
	// proxied connections: per VM, and for itself (its listener, its
	// registry, its logs, the connections of its API, the commands it
	// runs).
	filesPerVM = 8
	filesBase  = 1024
)

// sizingHost reads what the sizing is checked against.
type sizingHost struct {
	sysctl func(path string) (int64, error)
	nofile func() (uint64, error)
}

func realSizingHost() sizingHost {
	return sizingHost{
		sysctl: func(path string) (int64, error) {
			raw, err := os.ReadFile(path)
			if err != nil {
				return 0, err
			}
			return strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		},
		nofile: func() (uint64, error) {
			var limit syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
				return 0, err
			}
			return limit.Cur, nil
		},
	}
}

type sizingWarning struct {
	text  string
	attrs []any
}

// HostNeeds is what the host's shared numbers have to hold for a daemon
// with this config: zero where nothing is needed.
type HostNeeds struct {
	Conntrack, Files, AIO int64
}

// Needs is the sizing arithmetic for runs VMs that runs may have and the
// configured pool.
func (c Config) Needs() HostNeeds {
	c = c.withDefaults()
	runs := int64(max(c.MaxRuns, 0))
	pool, _ := c.Warm.VMs()
	connections := int64(max(c.NetConnections, 0))
	needs := HostNeeds{AIO: (runs + int64(pool)) * aioPerVM}
	if runs > 0 {
		needs.Conntrack = runs * connections
		needs.Files = runs*connections*2 + (runs+int64(pool))*filesPerVM + filesBase
	}
	return needs
}

// sizingWarnings compares the host's numbers with what the config needs.
func sizingWarnings(config Config, host sizingHost) []sizingWarning {
	config = config.withDefaults()
	needs := config.Needs()
	pool, _ := config.Warm.VMs()
	var warnings []sizingWarning
	about := []any{"maxRuns", config.MaxRuns, "warmPoolVMs", pool, "netConnections", config.NetConnections}
	check := func(what, fix string, have, need int64) {
		if need > 0 && have < need {
			warnings = append(warnings, sizingWarning{
				text:  fmt.Sprintf("%s is %d, and this configuration needs %d; %s", what, have, need, fix),
				attrs: about,
			})
		}
	}
	if needs.Conntrack > 0 {
		if have, err := host.sysctl("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
			check("net.netfilter.nf_conntrack_max", "raise it (sysctl), or lower --vm-net-connections or --vm-max-runs: open runs that fill the host's connection table make every new connection on the host fail, not only theirs", have, needs.Conntrack)
		}
	}
	if needs.Files > 0 {
		if have, err := host.nofile(); err == nil {
			check("the daemon's open file limit (RLIMIT_NOFILE)", "raise it (LimitNOFILE= in the service's unit), or lower --vm-net-connections or --vm-max-runs: allowlist runs' connections through their proxies are the daemon's open files", int64(min(have, 1<<62)), needs.Files)
		}
	}
	if have, err := host.sysctl("/proc/sys/fs/aio-max-nr"); err == nil {
		check("fs.aio-max-nr", "raise it (sysctl): a VM that cannot have its disk's asynchronous I/O falls back to synchronous I/O, much slower", have, needs.AIO)
	}
	if config.MaxRuns == 0 && config.NetConnections > 0 {
		warnings = append(warnings, sizingWarning{
			text:  fmt.Sprintf("no --vm-max-runs, so the connection table and the open file limit cannot be checked: each run may hold %d tracked connections and %d of the daemon's open files", config.NetConnections, 2*config.NetConnections),
			attrs: about,
		})
	}
	return warnings
}
