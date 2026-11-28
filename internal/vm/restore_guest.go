package vm

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/useteploy/teploy-sandbox/internal/guest"
)

// Bringing a restored guest up to date. A VM restored from a memory
// image comes back exactly as it was saved (restore.go): with the wall
// clock it was stopped at, since on x86 the hypervisor does not advance
// the guest's clock across a restore (measured, M0), and with its
// network device on the address it had, under the run's new tap. Before
// the run gets it back the daemon steps the clock, checks that the
// guest's random state is new, and moves the device to the run's new
// address, with no PCI rescan: the device is the saved one.

const (
	// restoreClockMark is the first line of the script a restored
	// guest runs for its clock when its agent is older than guest
	// protocol version 3.
	restoreClockMark = "# teploy-sandbox restore handshake"

	// restoreHandshakeTimeout bounds each step of a restored guest's
	// handshake.
	restoreHandshakeTimeout = 30 * time.Second

	// clockTolerance is how far the guest's clock may be from the
	// host's after the step. A guest whose step did not take is behind
	// by the whole time it was stopped.
	clockTolerance = 250 * time.Millisecond
)

// restoreClock brings a restored guest's clock and random state up to
// date, and checks both. The guest comes back with the wall clock and
// the random state it was saved with: a guest left hours behind
// verifies no certificate, and one left on the saved random state
// continues a stream that is in the image on disk. So the step must be
// seen to have taken, and the kernel to have the driver that reseeds
// the generator at the restore, or the image is not used.
//
// What makes the random state new is the kernel's, not the daemon's.
// Before a restored VM is let run again, the hypervisor changes its VM
// Generation ID and notifies the guest's device of it (Cloud
// Hypervisor's vm.restore: "Any restore may be a fork, so reseed before
// the guest runs"), and the kernel's driver for the device reseeds the
// generator as soon as the guest runs again, on that interrupt. The
// agent's own reseed comes later: once the guest has been running again
// for as long as its first answer took, which is seconds. Whatever read
// the generator before that read the saved stream over again, and read
// it just as a second restore of the same image would.
func (d *Driver) restoreClock(ctx context.Context, machine Machine) error {
	ctx, cancel := context.WithTimeout(ctx, restoreHandshakeTimeout)
	defer cancel()
	entropy := make([]byte, guest.RestoredEntropyBytes)
	if _, err := rand.Read(entropy); err != nil {
		return err
	}
	sent := time.Now()
	result, err := machine.Agent().Restored(ctx, sent.UnixNano(), entropy)
	if err == nil {
		if err := clockStepped(result.ClockNs, sent, time.Now()); err != nil {
			return err
		}
		// So it is the kernel's driver that is looked for, and only
		// that: an agent that reseeded the guest is no evidence that
		// nothing read the saved stream first. A guest whose kernel has
		// no driver bound to the device gets no answer to the
		// hypervisor's notification, and is not served from the image,
		// whatever the agent could do.
		if !result.VMGenIDSeen {
			return errors.New("the guest's kernel has no driver bound to the VM Generation ID device, so nothing reseeded its random state at the restore")
		}
		if !result.Reseeded {
			d.log.Info("restored guest: the agent's reseed request was not honoured; the kernel's own reseed at the restore is what counts", "why", "RNDRESEEDCRNG refused or unknown to the kernel")
		}
		return nil
	}
	var agentErr *guest.Error
	switch {
	case !errors.As(err, &agentErr):
		// No answer is the VM's process failing to answer.
		return &vmUnreachable{fmt.Errorf("restored handshake: %w", err)}
	case agentErr.Code == guest.CodeUnsupportedVersion:
		// An agent built before version 3: the step is a script, and the
		// guest's own kernel must be the one to reseed.
		return d.restoreClockScript(ctx, machine)
	}
	return fmt.Errorf("restored handshake: %w", err)
}

// restoreForkGuest is restoreClock for a child of a fork of a running
// run (guest protocol version 4): the clock and the random state as for
// any restore, checked the same way, and in the same request the agent
// ends every exec session it had (the parent's, inherited with its
// memory: their callers are the parent's), writes the restore's
// generation and runs the guest's on-restore hooks (design 5.5: what
// seeded a generator of its own before the fork is restarted there).
//
// An agent older than version 4 cannot be asked for that, and the
// script older agents get for a resume does none of it: such a guest
// is not served from the image, and the child boots from the fork's
// disk snapshot instead, as a fork did before memory forks existed.
// (Its inherited sessions would in fact die anyway: the hypervisor
// resets every vsock connection at a restore and the agent ends the
// process group of a connection that is gone (M0, U6). But the hooks
// would not run, and "anyway" is not what a fork is promised on.) The
// driver asks the parent's agent its version before it pauses the
// parent (SaveForkMemory), so this is a backstop, not the usual way an
// old agent is found out.
func (d *Driver) restoreForkGuest(ctx context.Context, machine Machine) error {
	ctx, cancel := context.WithTimeout(ctx, restoreHandshakeTimeout)
	defer cancel()
	entropy := make([]byte, guest.RestoredEntropyBytes)
	if _, err := rand.Read(entropy); err != nil {
		return err
	}
	sent := time.Now()
	result, err := machine.Agent().RestoredFork(ctx, sent.UnixNano(), entropy, true)
	var agentErr *guest.Error
	switch {
	case err == nil:
	case !errors.As(err, &agentErr):
		return &vmUnreachable{fmt.Errorf("restored handshake: %w", err)}
	case agentErr.Code == guest.CodeUnsupportedVersion:
		return fmt.Errorf("the guest's agent is older than protocol version %d: it cannot end the sessions a fork inherits or run the guest's on-restore hooks", forkProtocol)
	default:
		return fmt.Errorf("restored handshake: %w", err)
	}
	if err := clockStepped(result.ClockNs, sent, time.Now()); err != nil {
		return err
	}
	if !result.VMGenIDSeen {
		return errors.New("the guest's kernel has no driver bound to the VM Generation ID device, so nothing reseeded its random state at the restore")
	}
	attrs := []any{"sessionsKilled", result.SessionsKilled, "generation", result.Generation, "hooks", len(result.Hooks)}
	if len(result.HooksFailed) > 0 {
		attrs = append(attrs, "hooksFailed", strings.Join(result.HooksFailed, ","))
	}
	if !result.Reseeded {
		attrs = append(attrs, "agentReseed", "refused or unknown to the kernel; the kernel's own reseed at the restore is what counts")
	}
	d.log.Info("fork's child brought up to date", attrs...)
	return nil
}

func (d *Driver) restoreClockScript(ctx context.Context, machine Machine) error {
	now := time.Now()
	// The clock to the nanosecond, and read back; then whether the
	// guest's kernel reseeds its generator by itself.
	script := fmt.Sprintf("%s\nset -eu\ndate -u -s @%d.%09d >/dev/null\ndate +%%s.%%N\n%s", restoreClockMark, now.Unix(), now.Nanosecond(), vmGenIDProbe("/sys/bus"))
	var stdout, stderr strings.Builder
	code, timedOut, err := machine.Agent().Exec(ctx, script, "/", nil, restoreHandshakeTimeout, &stdout, &stderr)
	switch {
	case err != nil:
		return &vmUnreachable{fmt.Errorf("restored handshake: %w", err)}
	case timedOut:
		return errors.New("restored handshake: the guest did not finish in time")
	case code != 0:
		return fmt.Errorf("restored handshake: the guest could not step its clock (exit %d): %s", code, detailOf(stderr.String()))
	}
	clockNs, vmgenid, err := parseClockAnswer(stdout.String())
	if err != nil {
		return err
	}
	if err := clockStepped(clockNs, now, time.Now()); err != nil {
		return err
	}
	if !vmgenid {
		return errors.New("the guest's kernel has no VM Generation ID driver bound to reseed its random state with, and its agent is too old to")
	}
	return nil
}

// vmGenIDProbe is shell for a guest whose agent is older than the
// handshake op: it prints vmgenid when the kernel's VM Generation ID
// driver is bound to the device the hypervisor presents, and
// vmgenid-absent when it is not. The device is in the hypervisor's
// tables whether or not the kernel has the driver, so what says the
// driver is there is that it is bound, wherever the kernel bound it: to
// the ACPI device, or to the platform device that is its physical node.
// The kernel's own message that it reseeded because the VM was forked
// says so too. bus is the system's /sys/bus.
func vmGenIDProbe(bus string) string {
	return fmt.Sprintf(`seen=-absent
for d in %[1]s/*/devices/VMGENCTR*; do
  if [ -e "$d/driver" ]; then seen=; fi
  if node="$(readlink -f "$d/physical_node" 2>/dev/null)" && [ -n "$node" ] && [ -e "$node/driver" ]; then seen=; fi
done
if dmesg 2>/dev/null | grep -q 'crng reseeded due to virtual machine fork'; then seen=; fi
echo "vmgenid$seen"`, bus)
}

func detailOf(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 512 {
		text = text[len(text)-512:]
	}
	return text
}

// parseClockAnswer reads what the handshake script printed: the
// guest's clock as seconds.nanoseconds, and whether its kernel has the
// VM Generation ID device.
func parseClockAnswer(out string) (clockNs int64, vmgenid bool, err error) {
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		switch line {
		case "vmgenid":
			vmgenid = true
		case "vmgenid-absent":
		default:
			sec, frac, ok := strings.Cut(line, ".")
			whole, errA := strconv.ParseInt(sec, 10, 64)
			nanos, errB := strconv.ParseInt(frac, 10, 64)
			if !ok || errA != nil || errB != nil || len(frac) > 9 || nanos < 0 || nanos >= 1e9 {
				return 0, false, fmt.Errorf("restored handshake: the guest's clock reads %q", line)
			}
			for range 9 - len(frac) {
				nanos *= 10
			}
			clockNs = whole*1e9 + nanos
		}
	}
	if clockNs == 0 {
		return 0, false, errors.New("restored handshake: the guest did not say what its clock reads")
	}
	return clockNs, vmgenid, nil
}

// clockStepped says whether clockNs, the guest's clock as it read it
// after the step, is the host's time as sent: no further behind than
// the moment it was sent, and no further ahead than now.
func clockStepped(clockNs int64, sent, now time.Time) error {
	low, high := sent.Add(-clockTolerance).UnixNano(), now.Add(clockTolerance).UnixNano()
	if clockNs >= low && clockNs <= high {
		return nil
	}
	read := time.Unix(0, clockNs).UTC().Format(time.RFC3339Nano)
	if clockNs > high {
		return fmt.Errorf("the guest's clock was not stepped: it reads %s, which is %s ahead of the host", read, time.Duration(clockNs-high).Round(time.Millisecond))
	}
	return fmt.Errorf("the guest's clock was not stepped: it reads %s, and the host's time is %s ahead of it", read, time.Duration(low-clockNs).Round(time.Millisecond))
}

// restoreNetwork moves the guest's restored network device from the
// address it was saved with to the run's new one. The device is in the
// guest as it was; what changes is who the host lets through.
func (d *Driver) restoreNetwork(ctx context.Context, machine Machine, network *GuestNetwork, oldMAC string) error {
	ctx, cancel := context.WithTimeout(ctx, guestSetupTimeout+execGrace)
	defer cancel()
	started := time.Now()
	var stdout, stderr strings.Builder
	code, timedOut, err := machine.Agent().Exec(ctx, restoreNetScript(network, oldMAC), "/", nil, guestSetupTimeout, &stdout, &stderr)
	switch {
	case err != nil:
		return &vmUnreachable{fmt.Errorf("restore the guest's network device: %w", err)}
	case timedOut:
		return errors.New("restore the guest's network device: the guest did not finish in time")
	case code != 0:
		return fmt.Errorf("move the guest's network device to its new address (the image needs iproute2): exit %d: %s", code, detailOf(stderr.String()))
	}
	d.log.Info("vm restored network device ready", "guestSetup", time.Since(started).String())
	return nil
}
